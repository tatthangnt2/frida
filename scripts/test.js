// dumpModule_fixed.js
// Improved module dumper — safer file copy and proper read/write handling.

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

var NSString = ObjC.classes.NSString;

function allocStr(str) { return Memory.allocUtf8String(str); }
function getNSString(str) { return NSString.stringWithUTF8String_(allocStr(str)); }

function getU32(addr) { if (typeof addr == "number") addr = ptr(addr); return Memory.readU32(addr); }
function getU64(addr) { if (typeof addr == "number") addr = ptr(addr); return Memory.readU64(addr); }
function putU64(addr, n) { if (typeof addr == "number") addr = ptr(addr); Memory.writeU64(addr, n); }

function malloc(size) { return Memory.alloc(size); }

function getExportFunction(type, name, ret, args) {
    var nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    }
    if (type === "f") {
        return new NativeFunction(nptr, ret, args);
    } else if (type === "d") {
        return Memory.readPointer(nptr);
    }
    return null;
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);

function getCacheDir(index) {
    var NSUserDomainMask = 1;
    var npdirs = NSSearchPathForDirectoriesInDomains(index, NSUserDomainMask, 1);
    var len = ObjC.Object(npdirs).count();
    if (len == 0) return '';
    return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") pathname = allocStr(pathname);
    return wrapper_open(pathname, flags, mode);
}

var modules = null;
function getAllAppModules() {
    if (modules == null) {
        modules = [];
        var tmpmods = Process.enumerateModulesSync();
        for (var i = 0; i < tmpmods.length; i++) {
            if (tmpmods[i].path.indexOf(".app") != -1 || tmpmods[i].path.indexOf(".dylib") != -1) {
                modules.push(tmpmods[i]);
            }
        }
    }
    return modules;
}

var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function dumpModule(name) {
    if (modules == null) modules = getAllAppModules();
    var target = null;
    var idx = -1;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) !== -1 || modules[i].name.indexOf(name) !== -1) {
            target = modules[i];
            idx = i;
            break;
        }
    }
    if (!target) { console.log("Cannot find module: " + name); return; }

    var modbase = target.base;
    var modsize = target.size;
    var newmodname = target.name + ".decrypted";
    var newmodpath = null;
    var fmodule = -1;
    var BUFSIZE = 4096;

    // find writable cache dir
    for (var index = 1; index < 10; index++) {
        try {
            var base = getCacheDir(index);
            if (base && base.length > 0) {
                var candidate = base + "/" + newmodname;
                var fd = open(candidate, O_CREAT | O_RDWR, '0644');
                if (fd !== -1) {
                    newmodpath = candidate;
                    fmodule = fd;
                    break;
                } else {
                    // couldn't open this candidate, continue
                }
            }
        } catch (e) {}
    }

    if (fmodule === -1) {
        console.log("Cannot open output file in cache dirs");
        return;
    }

    var oldmodpath = target.path;
    var foldmodule = open(oldmodpath, O_RDONLY, 0);
    if (foldmodule === -1) {
        console.log("Cannot open source file: " + oldmodpath);
        close(fmodule);
        return;
    }

    // copy with correct read/write lengths
    var buffer = malloc(BUFSIZE);
    while (true) {
        var bytesRead = read(foldmodule, buffer, BUFSIZE);
        if (bytesRead <= 0) break; // 0 EOF, <0 error
        var nw = write(fmodule, buffer, bytesRead);
        if (nw !== bytesRead) {
            console.log("Warning: wrote " + nw + " of " + bytesRead + " bytes");
        }
    }

    // parse mach header in memory to find encryption info
    var is64bit = false;
    var magic = getU32(modbase);
    var size_of_mach_header = 0;
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    } else {
        console.log("Unknown mach-o magic: 0x" + magic.toString(16));
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptoff = -1;
    var crypt_off = 0;
    var crypt_size = 0;

    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
            offset_cryptoff = off + 8;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
            break;
        }
        off += cmdsize;
    }

    if (offset_cryptoff !== -1) {
        console.log("Found LC_ENCRYPTION_INFO at offset 0x" + offset_cryptoff.toString(16));
        // zero out cryptid in new file (8 bytes)
        var zeroBuf = malloc(8);
        Memory.writeByteArray(zeroBuf, [0,0,0,0,0,0,0,0]);
        lseek(fmodule, offset_cryptoff, SEEK_SET);
        write(fmodule, zeroBuf, 8);

        // overwrite encrypted segment data with memory contents (assuming decrypted in memory)
        console.log("Writing decrypted segment from mem offset 0x" + crypt_off.toString(16) + " len 0x" + crypt_size.toString(16));
        lseek(fmodule, crypt_off, SEEK_SET);
        // read memory content and write in chunks
        var remaining = crypt_size >>> 0;
        var src = modbase.add(crypt_off);
        while (remaining > 0) {
            var chunk = Math.min(remaining, BUFSIZE);
            var b = Memory.readByteArray(src, chunk);
            if (!b) { console.log("Memory.readByteArray failed at " + src); break; }
            // allocate temp buffer and copy bytes to it for write()
            var tmp = malloc(chunk);
            Memory.writeByteArray(tmp, b);
            var ww = write(fmodule, tmp, chunk);
            if (ww !== chunk) {
                console.log("Warning: wrote " + ww + " of " + chunk);
            }
            remaining -= chunk;
            src = src.add(chunk);
        }
        console.log("Fixed decrypted at offsets. Output: " + newmodpath);
    } else {
        console.log("No LC_ENCRYPTION_INFO found. Output copy at: " + newmodpath);
    }

    close(foldmodule);
    close(fmodule);
}
