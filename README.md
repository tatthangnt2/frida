# Frida 

 Frida script (JavaScript) & shell helper:

* Hook: network, crypto, file, biometric
* Dump at runtime: HTTP requests, headers, SharedPreferences, Keychain, sqlite
* Bypass: SSL pinning, root/jailbreak detection, emulator checks
* Reverse-engineering: stack trace, arguments, return values

**Notice**: These scripts are intended for technical support purposes only. Do not use them for unauthorized attacks.

---

### Attach  & load script via USB

```bash
# list process
frida-ps -Uai
# Attach & load script
frida -U -f com.example.app -l scripts/sslpinning-android.js --no-pause
# or
frida -U -n "AppName" -l scripts/sslpinning-android.js --no-pause
# or
frida -U -p <PID> -l scripts/sslpinning-android.js --no-pause
```

### &#x20;

### &#x20;

### frida-trace 

```bash
# trace special function JNI / Java/Objective-C cụ thể
frida-trace -U -i "*open*" com.example.app
```

---
