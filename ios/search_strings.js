// search_strings_fixed.js
// Frida-script: Tìm strings nhạy cảm trong memory (với fallback nếu enumerateModulesSync không có)
// Regex tìm nhiều từ khóa
const plainPatterns = [
    "API_KEY",
    "api_key",
    "ApiKey",
    "password",
    "passwd",
    "secret",
    "token",
    "auth",
    "bearer"
];

// UTF-8 encoder (works in Frida where TextEncoder may be missing)
function utf8ToBytes(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
        let codePoint = str.charCodeAt(i);

        // handle surrogate pairs for characters outside BMP
        if (codePoint >= 0xd800 && codePoint <= 0xdbff && i + 1 < str.length) {
            const hi = codePoint;
            const lo = str.charCodeAt(i + 1);
            if (lo >= 0xdc00 && lo <= 0xdfff) {
                codePoint = ((hi - 0xd800) << 10) + (lo - 0xdc00) + 0x10000;
                i++; // consumed pair
            }
        }

        if (codePoint <= 0x7f) {
            out.push(codePoint);
        } else if (codePoint <= 0x7ff) {
            out.push(0xc0 | (codePoint >> 6));
            out.push(0x80 | (codePoint & 0x3f));
        } else if (codePoint <= 0xffff) {
            out.push(0xe0 | (codePoint >> 12));
            out.push(0x80 | ((codePoint >> 6) & 0x3f));
            out.push(0x80 | (codePoint & 0x3f));
        } else {
            out.push(0xf0 | (codePoint >> 18));
            out.push(0x80 | ((codePoint >> 12) & 0x3f));
            out.push(0x80 | ((codePoint >> 6) & 0x3f));
            out.push(0x80 | (codePoint & 0x3f));
        }
    }
    return out;
}

function toHexPattern(s) {
    try {
        const bytes = utf8ToBytes(s);
        return bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
    } catch (e) {
        return null;
    }
}
// safe conversions / reads
function bytesToUtf8String(buf, maxLen) {
    if (!buf) return "";
    try {
        var u8 = new Uint8Array(buf);
        var len = Math.min(u8.length, maxLen || u8.length);
        try {
            if (typeof TextDecoder !== 'undefined') {
                return (new TextDecoder('utf-8')).decode(u8.subarray(0, len));
            }
        } catch (e) { }
        // fallback percent decode
        try {
            var pct = "";
            for (var i = 0; i < len; i++) pct += '%' + ('0' + u8[i].toString(16)).slice(-2);
            return decodeURIComponent(pct);
        } catch (e) {
            var out = "";
            for (var j = 0; j < len; j++) out += String.fromCharCode(u8[j]);
            return out;
        }
    } catch (e) {
        return "";
    }
}
function safeReadString(addr, maxLen) {
    try {
        if (typeof Memory.readUtf8String === 'function') {
            try {
                return Memory.readUtf8String(addr, maxLen);
            } catch (e) {
                // fallthrough
            }
        }
    } catch (e) { }
    try {
        var ab = Memory.readByteArray(addr, maxLen || 256);
        return bytesToUtf8String(ab, maxLen || 256);
    } catch (e) {
        return `${e})`;
    }
}

// hex dump helper: return string like "00 11 22 ...  | ascii..."
function hexDump(addr, length) {
    length = length || 64;
    try {
        var ab = Memory.readByteArray(addr, length);
        if (!ab) return "(no-bytes)";
        var u8 = new Uint8Array(ab);
        var hexs = [], ascii = [];
        for (var i = 0; i < u8.length; i++) {
            hexs.push(('0' + u8[i].toString(16)).slice(-2));
            var ch = u8[i];
            ascii.push((ch >= 0x20 && ch <= 0x7e) ? String.fromCharCode(ch) : '.');
        }
        // group hex into 16-byte chunks for readability
        var lines = [];
        for (var offset = 0; offset < hexs.length; offset += 16) {
            var hs = hexs.slice(offset, offset + 16).join(' ');
            var as = ascii.slice(offset, offset + 16).join('');
            lines.push(hs.padEnd(16 * 3 - 1) + "  |" + as + "|");
        }
        return lines.join('\n');
    } catch (e) {
        return `${e}`;
    }
}

// helper: decide whether to scan module (skip large/system libs)
function isAppModule(m) {
    if (!m || !m.path) return false;
    if (!m.size || m.size > 20 * 1024 * 1024) return false; // skip very large
    const p = m.path.toLowerCase();
    // skip common system paths (tweak if you need)
    if (p.indexOf("/system/") !== -1) return false;
    if (p.indexOf("/usr/lib/") !== -1) return false;
    if (p.indexOf("/system/library/") !== -1) return false;
    if (p.indexOf("/private/var/") !== -1) return false;
    // optionally only scan app bundle modules (uncomment to restrict)
    // if (p.indexOf("/var/containers/") === -1 && p.indexOf("/private/var/containers/") === -1) return false;
    return true;
}
function formatBytes(num, decimals = 2) {
    if (!num || num === 0) return '0 B';

    const k = 1024;
    const sizes = ['B', 'Kb', 'Mb', 'Gb', 'Tb'];
    const i = Math.floor(Math.log(num) / Math.log(k));

    const value = num / Math.pow(k, i);
    return `${value.toFixed(decimals)}${sizes[i]}`;
}
// read raw bytes
function safeReadBytes(addr, length) {
    try {
        return Memory.readByteArray(addr, length);
    } catch (e) {
        return `${e}`;;
    }
}
// ascii preview: show printable bytes as char, others as '.', and highlight match bytes with [ ]
// inputs:
//   matchAddr: NativePointer
//   matchLen: number of bytes in match
//   ctxLen: total bytes to show (default 64)
function asciiPreview(matchAddr, matchLen, ctxLen) {
    ctxLen = ctxLen || 64;
    var half = Math.floor(ctxLen / 2);
    var start = ptr(matchAddr).sub(half);
    var bytes = safeReadBytes(start, ctxLen);
    if (typeof bytes == 'string') return bytes;
    var u8 = new Uint8Array(bytes);
    var asciiParts = [];
    var hexParts = [];
    // compute index of match inside this buffer
    var matchOffset = half;
    // but if matchAddr - start < 0, adjust (rare)
    try {
        var diff = ptr(matchAddr).sub(start).toInt32();
        if (!isNaN(diff)) matchOffset = diff;
    } catch (e) { }
    // clamp match region
    var matchStart = Math.max(0, matchOffset);
    var matchEnd = Math.min(u8.length, matchOffset + matchLen);

    for (var i = 0; i < u8.length; i++) {
        var ch = u8[i];
        // ascii printable?
        var disp = (ch >= 0x20 && ch <= 0x7e) ? String.fromCharCode(ch) : '.';
        // highlight match region
        if (i === matchStart) {
            asciiParts.push('[' + disp);
        } else if (i === matchEnd) {
            asciiParts.push(']' + disp);
        } else {
            asciiParts.push(disp);
        }
        hexParts.push(('0' + ch.toString(16)).slice(-2));
    }
    // if match reaches end, close bracket
    if (matchEnd >= u8.length) {
        asciiParts.push(']');
    }
    // join to string, trim surrounding uninteresting bytes for compactness
    var asciiStr = asciiParts.join('');
    var hexStr = hexParts.join(' ');

    // also show a simple center-mark line with offsets relative to match
    return {
        ascii: asciiStr,
        hex: hexStr,
        matchOffset: matchOffset,
        matchStart: matchStart,
        matchEnd: matchEnd
    };
}

const hexPatterns = plainPatterns
    .map(p => ({ plain: p, hex: toHexPattern(p) }))
    .filter(x => x.hex);

// lấy danh sách modules — dùng fallback nếu enumerateModulesSync không tồn tại
let modules = [];
if (typeof Process.enumerateModulesSync === 'function') {
    modules = Process.enumerateModulesSync();
} else if (typeof Process.enumerateModules === 'function') {
    // some runtimes provide enumerateModules (non-Sync) that still returns array
    try {
        modules = Process.enumerateModules();
    } catch (e) {
        // nếu enumerateModules là async/iterator thì không dùng được ở đây
        console.log("[!] enumerateModules() threw:", e);
        modules = [];
    }
} else {
    console.log("[!] No module enumeration function available on this Process object");
}

console.log("\n[*] Found", modules.length, "modules");
for (let m of modules) {
    console.log(`⚈ ${m.name} (${formatBytes(m.size)}, ${m.path})`);

    if (!m.size || m.size === 0) continue; // skip size 0 hoặc quá lớn và skip system libs để giảm noise
    if (m.size > 10 * 1024 * 1024) continue; // optional: skip huge modules
    if (!isAppModule(m)) continue; // remove/comment nếu muốn quét nhiều hơn

    for (let p of hexPatterns) {
        try {
            // compute match length in bytes from hex pattern
            const matchLen = p.hex.split(' ').length;
            const results = Memory.scanSync(m.base, m.size, p.hex);
            for (let r of results) {
                // hex preview centered on match: try to show surrounding bytes, but ensure bounds
                const ctxLen = 64; // total bytes to show
                const half = Math.floor(ctxLen / 2);
                const ascii = asciiPreview(r.address, matchLen, ctxLen);
                let preview = "";
                try {
                    preview = safeReadString(r.address, Math.min(200, r.size || 200));
                } catch (e) {
                    preview = `${e}`;
                }

                let hexd = '';
                try {

                    // r.address is NativePointer — we can compute baseAddr = r.address.sub(half)
                    var startAddr = r.address;
                    try {
                        startAddr = ptr(r.address).sub(half);
                    } catch (e) {
                        // fallback keep r.address
                        startAddr = r.address;
                    }
                    // read safe: if startAddr below module base, use r.address
                    try {
                        // produce hex dump (may fail if unreadable)
                        let rs = hexDump(startAddr, ctxLen);
                        hexd = rs.split('\n').join('\n          ');
                    } catch (e) {
                        hexd = `${e}`;
                    }

                } catch (e) {
                    hexd = `${e}`;
                }

                // console.log(`  ${r.address} (+${r.size} bytes): "${preview}" | ${typeof ascii == 'string' ? ascii : ascii.ascii} | ${hexd}`);
                console.log(`  ${r.address} (+${r.size} bytes) found '${p.plain}'`);
                console.log(`    UTF8:  ${preview}`);
                if (typeof ascii === 'string') {
                    console.log(`    ASCII: ${ascii}`);
                } else {
                    console.log(`    ASCII: ${ascii.ascii}`);
                    console.log(`      (match bytes in [brackets])  matchOffset=${ascii.matchOffset} matchLen=${matchLen}`);
                }
                console.log("    Hex:   " + hexd);

            }
        } catch (e) {
            console.log(`[!] hex scan error in ${m.name} for '${p.plain}': ${e}`);
        }
    }
}

