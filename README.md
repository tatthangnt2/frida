# Frida 

 Frida script (JavaScript) & shell helper:

* Hook: network, crypto, file, biometric
* Dump at runtime: HTTP requests, SharedPreferences, Keychain, sqlite
* Bypass: SSL pinning, root/jailbreak detection, emulator checks
* Reverse-engineering: stack trace, arguments, return values

**Notice**: These scripts are intended for technical support purposes only. Do not use them for unauthorized attacks.

---

### Attach  & load script via USB

```bash
# list process
frida-ps -Uai
# Spawn app & load script
frida -U -f com.example.app -l scripts/sslpinning-android.js
# Attach & load script
frida -U -n "AppName" -l scripts/sslpinning-android.js 
# or
frida -U -p <PID> -l scripts/sslpinning-android.js 
```

### &#x20;

### &#x20;

### frida-trace 

```bash
# trace JNI / Java/Objective-C function
frida-trace -U -i "*open*" com.example.app
```

---
