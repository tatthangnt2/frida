// C function hook
try {
    var addr = Module.findExportByName(null, "SecItemCopyMatching");
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                // args[0] = query (CFDictionaryRef)
                try {
                    var qptr = args[0];
                    // best-effort: try to bridge to ObjC and inspect keys
                    // often easier: log pointer + backtrace
                    console.log("[SecItemCopyMatching] query ptr = " + qptr);
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
                } catch (e) {}
            },
            onLeave: function (retval) {
                console.log("[SecItemCopyMatching] returned: " + retval);
            }
        });
    }
} catch (e) {}
