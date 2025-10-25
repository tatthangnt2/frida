# Dump strings in memory for iOS/Android
# python3 dump.py -U <AppName>
#
# Android-Special:
# adb push frida-server-17.4.0-android-arm64 /data/local/tmp/
# adb shell "chmod 755 /data/local/tmp/frida-server-17.4.0-android-arm64"
# adb shell "/data/local/tmp/frida-server-17.4.0-android-arm64 &"
#
import textwrap
import frida
import os
import sys
import frida.core
import argparse
import logging
import string
import re
from io import open
import shutil
import codecs
import concurrent.futures
import time

print("""
  _____                                  
 |  __ \                                 
 | |  | |_   _ _ __ ___  _ __   ___ _ __ 
 | |  | | | | | '_ ` _ \| '_ \ / _ \ '__|
 | |__| | |_| | | | | | | |_) |  __/ |   
 |_____/ \__,_|_| |_| |_| .__/ \___|_|   
                        | |              
                        |_|              
""")

# --- Configs ---
PAGE_SIZE = 4096
MIN_STRINGS_LEN = 4
MAX_SIZE = 10*1024*1024 # 10M
READ_TIMEOUT = 2.0      # seconds per page read
DUMP_TIMEOUT = 30.0     # seconds per region dump
MAX_WORKERS= 4
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)

parser = argparse.ArgumentParser(
        prog="fridump",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("")
)
parser.add_argument("process", help="the process that you will be injecting to")
parser.add_argument("-o", "--out", type=str, metavar="dir", help="provide full output directory path. (default: ./dump/<process>)")
parser.add_argument("-U", "--usb", action="store_true", help="device connected over usb")
parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
parser.add_argument("-r", "--read", action="store_true", help="dump readable parts of memory. More data, more errors")
parser.add_argument("-w", "--write", action="store_true",  help="dump writeable parts of memory. More data, more errors")
parser.add_argument("-x", "--execute", action="store_true",  help="dump executable parts of memory. More data, more errors")
parser.add_argument("--min-len", type=int, metavar="bytes", default=MIN_STRINGS_LEN, 
                    help="minximum strings length (default: {MIN_STRINGS_LEN}).")         
parser.add_argument("--max-size", type=int, metavar="bytes", default=MAX_SIZE, help="maximum size of dump file in bytes (default: {MAX_SIZE} = 10Mb)")
parser.add_argument("--read-timeout", type=float, default=READ_TIMEOUT, help=f"timeout per page read in seconds (default: {READ_TIMEOUT})")
parser.add_argument("--dump-timeout", type=float, default=DUMP_TIMEOUT, help=f"timeout per region dump in seconds (default: {DUMP_TIMEOUT})")
parser.add_argument("--retry", type=str, help="File containing failed from previous dump to retry")


args = parser.parse_args()

# Define Configurations
APP_NAME = args.process
OUT_DIR = ""
USB = args.usb
DEBUG_LEVEL = logging.INFO

PERMISSION = ''
PERMISSION += 'r' if args.read else '-'
PERMISSION += 'w' if args.write else '-'
PERMISSION += 'x' if args.execute else '-'

if args.max_size is not None:
    MAX_SIZE = args.max_size

if args.min_len is not None:
    MIN_STRINGS_LEN = args.min_len

if args.read_timeout is not None:
    READ_TIMEOUT = args.read_timeout

if args.dump_timeout is not None:
    DUMP_TIMEOUT = args.dump_timeout

if args.verbose:
    DEBUG_LEVEL = logging.DEBUG

logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)

# Output dir
if args.out is not None:
    OUT_DIR = args.out
else:
    OUT_DIR = os.path.join(os.getcwd(), APP_NAME+"-dump")

# --- Del output dir
if os.path.exists(OUT_DIR):
    try:
        shutil.rmtree(OUT_DIR)
    except Exception as e:
        print("Warning: failed to remove existing dump directory:", e)
        sys.exit(1)

# Make output dir
try:
    os.makedirs(OUT_DIR, exist_ok=True)
except Exception as e:
    print("Cannot create output directory:", e)
    sys.exit(1)

OUT_ASCII_PATH = os.path.join(OUT_DIR, "strings-ascii.txt")
OUT_UTF8_PATH = os.path.join(OUT_DIR, "strings-utf8.txt")
OUT_UTF16_PATH = os.path.join(OUT_DIR, "strings-utf16.txt")
OUT_ERROR_PATH = os.path.join(OUT_DIR, "errors.log")
OUT_LOG_PATH = os.path.join(OUT_DIR, "dump.log")
OUT_DUMP_DIR= os.path.join(OUT_DIR, "dump")
try:
    os.makedirs(OUT_DUMP_DIR, exist_ok=True)
except Exception as e:
    print("Cannot create output dump directory:", e)
    sys.exit(1)

log_file = open(OUT_LOG_PATH, "a", encoding="utf-8")
def log(*msgs, sep=' ', end='\n'):
    """Ghi vào file log"""
    line = sep.join(str(m) for m in msgs) + end
    log_file.write(line)
    log_file.flush()
    logging.debug(line.strip())  # optional: ghi vào logging

def echo(*msgs, sep=' ', end='\n'):
    """In ra console và ghi vào file"""
    line = sep.join(str(m) for m in msgs)
    print(line, end=end)
    log_file.write(line + end)
    log_file.flush()

echo("Current Directory " + str(os.getcwd()))
echo("Output directory  " + OUT_DIR)
echo("USB               " + str(USB))
echo("RETRY             " + str(args.retry))
echo("PERMISSIONS       " + (PERMISSION if PERMISSION == '---' else "r--,rw-,r-x"))
echo("MIN_STRINGS_LEN   " + str(MIN_STRINGS_LEN))
echo("PAGE_SIZE         " + str(PAGE_SIZE))
echo("READ_TIMEOUT      " + str(READ_TIMEOUT)+"s")
echo("DUMP_TIMEOUT      " + str(DUMP_TIMEOUT)+"s")
echo("DEBUG_LEVEL       " + str(DEBUG_LEVEL))

def read_with_timeout(agent, address, size):
    try:
        fut = _executor.submit(agent.read_memory, address, size)
        result = fut.result(timeout=READ_TIMEOUT)
        return result
    except concurrent.futures.TimeoutError:
        log(f"[!] read timeout at {hex(address)} size={size} (timeout={READ_TIMEOUT}s)")
        return None
    except Exception as e:
        log(f"[!] read exception at {hex(address)} size={size}: {e}")
        return None

def dump_to_file(agent, base, size, error, prot):
    try:
        try:
            if isinstance(base, str):
                addr = int(base, 0)
            else:
                addr = int(base)
        except Exception:
            addr = int(str(base), 0)

        prefix = ""
        if isinstance(prot, str):
            prot_lower = prot.lower()
            if "x" in prot_lower:
                prefix = "code_"
            elif ("r" in prot_lower and "w" in prot_lower):
                prefix = "mem_"
            elif (prot_lower.startswith("r") and "w" not in prot_lower and "x" not in prot_lower):
                prefix = "const_"
            else:
                prefix = prot  # other -> no prefix

        filename = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', f"{prefix}{hex(addr)}.dump")
        fpath = os.path.join(OUT_DUMP_DIR, filename)

        result = bytearray()
        skipped = []
        success_pages = 0
        total_pages = 0

        offset = 0
        size = int(size)

        region_start_time = time.time()

        while offset < size:
            # Nếu tổng thời gian cho region vượt DUMP_TIMEOUT -> abort
            elapsed_region = time.time() - region_start_time
            if DUMP_TIMEOUT is not None and elapsed_region > DUMP_TIMEOUT:
                log(f"[!] region timeout for {hex(addr)} after {elapsed_region:.2f}s (limit={DUMP_TIMEOUT}s)")
                with open(OUT_ERROR_PATH, "a") as ef:
                    ef.write(f"Region {hex(addr)} ({prot}) aborted due to dump-timeout {elapsed_region:.2f}s\n")
                error += f" dump-timeout:{elapsed_region:.2f}s"
                return error

            to_read = min(PAGE_SIZE, size - offset)
            curr_addr = addr + offset
            total_pages += 1
            try:
                chunk = read_with_timeout(agent, curr_addr, to_read)
                if chunk is None:
                    skipped.append((curr_addr, to_read))
                else:
                    data = bytes(chunk) if isinstance(chunk, (bytes, bytearray)) else bytearray(chunk)
                    result.extend(data)
                    success_pages += 1
            except Exception as e:
                log(f"[!] read error at {hex(curr_addr)}: {str(e)}")
                skipped.append((curr_addr, to_read))
            offset += to_read

        with open(fpath, "wb") as f:
            meta = (
                f"base: {hex(addr)}\n"
                f"size: {size}\n"
                f"prot: {prot}\n"
                f"page_size: {PAGE_SIZE}\n"
                f"total_pages: {total_pages}\n"
                f"success_pages: {success_pages}\n"
                f"skipped_pages: {len(skipped)}\n\n"
            )
            f.write(meta.encode("utf-8"))
            if len(result) > 0:
                f.write(b"\n--RAW-DATA--\n")
                f.write(result)

        # --- Write strings ---
        try:
            strings(filename, bytes(result))
        except Exception as e:
            log(f"[!] strings() failed for {filename}: {e}")

        # --- Write error ---
        if skipped:
            with open(OUT_ERROR_PATH, "a") as ef:
                ef.write(f"Region {hex(addr)} ({prot}) size:{size} skipped:{len(skipped)} pages\n")
                for (a, l) in skipped:
                    ef.write(f"  {hex(a)} size:{l}\n")
            error += f" skipped:{len(skipped)}"
        return error
    except Exception as e:
        log(f"[!dump_to_file exception] {str(e)}")
        return error

def splitter(agent, base, size, max_size, error, prot):
    cur_base = int(base, 0)
    num_full_chunks = size // max_size
    remainder = size % max_size
    num_chunks = num_full_chunks + (1 if remainder else 0)
    log(f"Number of chunks: {num_chunks}")

    # Dump full chunks
    for _ in range(num_full_chunks):
        log(f"Save bytes: {hex(cur_base)} till {hex(cur_base + max_size)}")
        error = dump_to_file(agent, cur_base, max_size, error, prot)
        cur_base += max_size

    # Dump remainder
    if remainder:
        log(f"Save bytes: {hex(cur_base)} till {hex(cur_base + remainder)}")
        error = dump_to_file(agent, cur_base, remainder, error, prot)

    return error

# Progress bar function
def print_progress(times, total, prefix ='', suffix ='', decimals = 2, bar = 80):
    filled = int(round(bar * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    bar_str = '#' * filled + '-' * (bar - filled)
    sys.stdout.write('%s [%s] %s%s %s\r' % (prefix, bar_str, percents, '%', suffix))
    sys.stdout.flush()
    if times == total:
        print("\n")

# Extract strings from a dump file
def strings(filename, data):
    try:
        # daa bytes
        # --- ASCII strings ---
        ascii_strings = re.findall(rb"[\x20-\x7E]{%d,}" % MIN_STRINGS_LEN, data)
        ascii_strings = [s.decode("ascii", errors="ignore") for s in ascii_strings]

        # --- UTF-8 strings ---
        utf8_strings = []
        try:
            text_utf8 = data.decode("utf-8", errors="ignore")
            utf8_strings = re.findall(r"[\x20-\x7E]{%d,}" % MIN_STRINGS_LEN, text_utf8)
        except Exception:
            pass

        # --- UTF-16 strings (little endian + big endian) ---
        utf16_strings = []
        try:
            text_utf16le = data.decode("utf-16le", errors="ignore")
            utf16_strings += re.findall(r"[\x20-\x7E]{%d,}" % MIN_STRINGS_LEN, text_utf16le)
        except Exception:
            pass
        try:
            text_utf16be = data.decode("utf-16be", errors="ignore")
            utf16_strings += re.findall(r"[\x20-\x7E]{%d,}" % MIN_STRINGS_LEN, text_utf16be)
        except Exception:
            pass

        if(len(ascii_strings)>0):
            with open(OUT_ASCII_PATH, "a", encoding="utf-8") as fa:
                fa.write(f"\n# Strings (ASCII) from {filename} ({len(ascii_strings)} items)\n")
                for s in ascii_strings:
                    fa.write(s + "\n")

        if(len(utf8_strings)>0):
            with open(OUT_UTF8_PATH, "a", encoding="utf-8") as fu8:
                fu8.write(f"\n# Strings (UTF-8) from {filename} ({len(utf8_strings)} items)\n")
                for s in utf8_strings:
                    fu8.write(s + "\n")

        if(len(utf16_strings)>0):
            with open(OUT_UTF16_PATH, "a", encoding="utf-8") as fu16:
                fu16.write(f"\n# Strings (UTF-16) from {filename} ({len(utf16_strings)} items)\n")
                for s in utf16_strings:
                    fu16.write(s + "\n")

        echo(f"{filename:24} ascii:{len(ascii_strings):6},    utf8:{len(utf8_strings):6},    utf16:{len(utf16_strings):6}")

    except Exception as e:
        log(f"[!] strings() failed for {filename}: {e}")

# Method to receive messages from Javascript API calls
def on_message(message, data):
   echo("[on_message] message:", message, "data:", data)

# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(APP_NAME)
    else:
        session = frida.attach(APP_NAME)
except Exception as e:
    echo("Can't connect to "+APP_NAME+". Have you connected the device?")
    log(str(e))
    sys.exit()

mem_access_viol = ""

echo("\nStarting memory dump...")

script = session.create_script(
    """'use strict';

    rpc.exports = {
      enumerateRanges: function (prot) {
        try {
          if (typeof prot === 'string') {
            if (Process.enumerateRangesSync) return Process.enumerateRangesSync({ protection: prot });
            if (Memory.enumerateRangesSync) return Memory.enumerateRangesSync({ protection: prot });
          } else {
            if (Process.enumerateRangesSync) return Process.enumerateRangesSync(prot);
            if (Memory.enumerateRangesSync) return Memory.enumerateRangesSync(prot);
          }
          if (Process.enumerateRanges) return Process.enumerateRanges(prot);
        } catch (e) {
          throw e;
        }
        throw new Error('Process.enumerateRanges() not available in this frida runtime');
      },

      readMemory: function (address, size) {
        try {
            var p = ptr(address);
            var len = parseInt(size);
            if (p.isNull()) return null;

            // Cách ổn định nhất: sử dụng Memory.readByteArray
            if (Memory && Memory.readByteArray) {
                var result = Memory.readByteArray(p, len);
                if (result !== null) return result;
            }

            // Hoặc thử p.readByteArray nếu được
            if (p.readByteArray) {
                return p.readByteArray(len);
            }

            // Cuối cùng, fallback thủ công
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
                bytes[i] = Memory.readU8(p.add(i));
            }
            return bytes.buffer;
        } catch (e) {
            send({ type: 'readMemoryError', error: String(e), addr: address, size: size });
            return null;
        }
    }
};
    """)
script.on("message", on_message)
script.load()

agent = script.exports_sync
ranges = agent.enumerate_ranges(PERMISSION)
retry_ranges= []
if args.retry:
    try:
        with open(OUT_ERROR_PATH, "r") as ef:
            for line in ef:
                if line.startswith("Region"):
                    parts = line.split()
                    base = parts[1] # '0xabcdef'
                    retry_ranges.append(base)
    except FileNotFoundError:
        log("File not found: "+OUT_ERROR_PATH)
        sys.exit()

# --- Replace main dumping loop with filter by protection (optional) and summary ---
successful_regions = 0
skipped_regions = 0
i = 0
l = len(ranges)

for mem_range in ranges:
    # mem_range thường có keys: 'base', 'size', 'protection' (tùy runtime)
    base = mem_range.get("base", mem_range.get("start", None))
    size = mem_range.get("size", mem_range.get("length", None))
    prot = mem_range.get("protection", mem_range.get("PERMISSION", ""))

    # Nếu thiếu base/size, skip
    if base is None or size is None:
        log("Skipping malformed region: {}".format(mem_range))
        skipped_regions += 1
        continue
    
    if args.retry and (str(base) not in retry_ranges):
        continue

    # Filter by PERMISSION
    if PERMISSION != '---':
        prot_str = prot if isinstance(prot, str) else str(prot)
        protLower = prot_str.lower()
        # Bỏ region nếu nó không chứa ít nhất 1 ký tự được yêu cầu
        if ('r' in PERMISSION and 'r' not in protLower) or \
        ('w' in PERMISSION and 'w' not in protLower) or \
        ('x' in PERMISSION and 'x' not in protLower):
            log(
                "Skipping region without required perms: {} prot={}".format(
                    hex(int(base, 0) if isinstance(base, str) else base), prot_str
                )
            )
            skipped_regions += 1
            continue

    log(f"Region {str(base)}       ({str(prot)})            size:{str(size)}")

    if size > MAX_SIZE:
        log("Too big, splitting the dump into chunks")
        mem_access_viol = splitter(agent, base, size, MAX_SIZE, mem_access_viol, prot)
        successful_regions += 1
        continue

    mem_access_viol = dump_to_file(agent, base, size, mem_access_viol, prot)
    successful_regions += 1
    i += 1
    print_progress(i, l, prefix='Progress:', suffix='Complete')

echo("")
echo("Summary: attempted regions: {}, successful regions: {}, skipped regions: {}".format(len(ranges), successful_regions, skipped_regions))
