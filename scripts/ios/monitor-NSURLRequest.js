

const MINIFY = true;
function headerStringToDict(str) {
    const obj = {};
    if (!str) return obj;
    const lines = str.split("\n");
    for (const line of lines) {
        const idx = line.indexOf(":");
        if (idx > 0) {
            const k = line.substring(0, idx).trim();
            const v = line.substring(idx + 1).trim();
            obj[k] = v;
        }
    }
    return obj;
}
function toNSDictionary(obj) {
    const dict = {};
    const allKeys = obj.allKeys();
    for (let i = 0; i < allKeys.count(); i++) {
        const key = allKeys.objectAtIndex_(i);
        const value = obj.objectForKey_(key);
        dict[key.toString()] = value.toString();
    }
    return dict;
}
function parseJSON(value) {
    try {
        return JSON.parse(value);
    } catch (e) { }
    return value;
}
function isProbablyBinary(str) {
    if (!str) return false;
    // consider binary if includes NUL or many non-printable chars
    for (let i = 0; i < Math.min(str.length, 120); i++) {
        const c = str.charCodeAt(i);
        if (c === 0) return true;
        // allow common printable + whitespace (9..13 = \t\r\n)
        if (c < 32 && (c < 9 || c > 13)) return true;
    }
    return false;
}
function escapeSingleQuotes(s) {
    if (s === null || s === undefined) return "";
    // escape single quotes for shell: replace ' with '\'' sequence
    return s.replace(/'/g, "'\\''");
}
function buildCurl(url, method, headers, bodyRaw) {
    // Start with basic flags: -i to include response headers in output (optional), -s silent
    let parts = ["curl -i -s -X " + (method || "GET") + " '" + url + "'"];

    // Add headers
    for (const k in headers) {
        if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
        const v = headers[k];
        // omit Content-Length (curl will set)
        if (k.toLowerCase() === "content-length") continue;
        parts.push(" -H '" + escapeSingleQuotes(k) + ": " + escapeSingleQuotes(v) + "'");
    }

    // Body handling
    if (bodyRaw && bodyRaw.length > 0) {
        if (bodyRaw.startsWith("<base64> ")) {
            // binary body: print base64 and give instruction
            const b64 = bodyRaw.substring(9);
            const hint = "\n# Body is binary (base64). To send with curl:\n" +
                "# echo '" + b64 + "' | base64 -d > /tmp/body.bin\n" +
                "# curl -i -s -X " + (method || "POST") + " '" + url + "' ";
            // re-add headers for convenience
            for (const k in headers) {
                if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
                if (k.toLowerCase() === "content-length") continue;
                const v = headers[k];
                hint += " -H '" + escapeSingleQuotes(k) + ": " + escapeSingleQuotes(v) + "'";
            }
            hint += " --data-binary @/tmp/body.bin\n";
            return { curl: "# (binary body) see below", hint: hint };
        } else if (isProbablyBinary(bodyRaw)) {
            return {
                curl: "# (binary body detected) cannot include inline",
                hint: "# Body appears binary; extract base64 from the script and use --data-binary."
            };
        } else {
            // printable body -> include with -d (escape quotes)
            const escaped = escapeSingleQuotes(bodyRaw);
            parts.push(" --data '" + escaped + "'");
        }
    }

    return { curl: parts.join(" ") };
}

try {
    if (!ObjC.available) {
        // console.log("❌ Objective-C Runtime is not available!");
        // throw new Error("ObjC runtime not available");

        console.log('okhttp3.OkHttpClient & okhttp3.Request monitor...');
        Java.perform(() => {
            const OkHttpClient = Java.use("okhttp3.OkHttpClient");
            const Request = Java.use("okhttp3.Request");
            const Buffer = Java.use("okio.Buffer");

            OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (req) {
                try {
                    const url = req.url().toString();
                    const method = req.method();
                    const headers = headerStringToDict(req.headers().toString());

                    let body = "";
                    const bodyData = req.body();
                    if (bodyData) {
                        const buffer = Buffer.$new();
                        bodyData.writeTo(buffer);
                        try { body = buffer.readUtf8(); }
                        catch (_) {
                            try {
                                body = "<base64> " + buffer.readByteArray().toBase64();
                            } catch (_) { }
                        }
                    }

                    if (MINIFY) {
                        console.log(`🌐 ${method} ${url}`, JSON.stringify({ headers, body: parseJSON(body) }))
                    }
                    else {
                        console.log(`🌐 ${method} ${url}`)
                        const out = buildCurl(url, method, headers, body);
                        if (out.curl) console.log(out.curl);
                        if (out.hint) console.log(out.hint);
                        console.log(JSON.stringify({ headers, body: parseJSON(body) }, null, 4))
                    }

                } catch (e) { }

                return this.newCall(req);
            };
        });

        // const RealCall = Java.use("okhttp3.internal.connection.RealCall");
        // RealCall.getResponseWithInterceptorChain.implementation = function () {
        //     const resp = this.getResponseWithInterceptorChain();
        //     try {
        //         const req = resp.request();
        //         const url = req.url().toString();
        //         const code = resp.code();
        //         const hdrs = headerStringToDict(resp.headers().toString());

        //         let bodyStr = "";
        //         const body = resp.body();
        //         if (body) {
        //             const source = body.source();
        //             source.request(9999999);
        //             const buffer = source.getBuffer().clone();
        //             bodyStr = buffer.readUtf8();
        //         }

        //         console.log(`📥 RESPONSE ${code} ${url}`, JSON.stringify({ headers: hdrs, body: parseJSON(bodyStr) }));
        //     } catch (e) { }

        //     return resp;
        // };
    }
    else {
        console.log('NSURLRequest & NSURLSession monitor...');
        // --- Hook initWithURL: để log request URL ---
        const NSURLRequest = ObjC.classes.NSURLRequest;
        if (!MINIFY && NSURLRequest && NSURLRequest["- initWithURL:"]) {
            Interceptor.attach(NSURLRequest["- initWithURL:"].implementation, {
                onEnter(args) {
                    const url = ObjC.Object(args[2]).toString();
                    console.log(`🌐 [NSURLRequest initWithURL:] ${url}`);
                }
            });
        }

        // --- Hook NSURLSessionTask setRequest: để lấy body + headers ---
        const NSURLSessionTask = ObjC.classes.NSURLSessionTask;
        if (NSURLSessionTask && NSURLSessionTask["- resume"]) {
            Interceptor.attach(NSURLSessionTask["- resume"].implementation, {
                onEnter(args) {
                    const task = ObjC.Object(args[0]);
                    const request = task.currentRequest();
                    if (!request) return;

                    const url = request.URL().absoluteString().toString();
                    const method = request.HTTPMethod() ? request.HTTPMethod().toString() : "UNKNOWN";
                    const headers = request.allHTTPHeaderFields() ? toNSDictionary(request.allHTTPHeaderFields()) : {};
                    const bodyData = request.HTTPBody();
                    let body = bodyData ? ObjC.classes.NSString.alloc().initWithData_encoding_(bodyData, 4)?.toString() : "";

                    if (request.HTTPBodyStream()) {
                        try {
                            const stream = request.HTTPBodyStream();
                            stream.open();
                            const buf = Memory.alloc(10240);
                            let data = "";
                            let read = 0;

                            while ((read = stream.read_maxLength_(buf, 10240)) > 0) {
                                data += Memory.readUtf8String(buf, read);
                            }

                            body = data;
                            stream.close();
                        } catch (e) { }
                    }

                    if (MINIFY) {
                        console.log(`🌐 ${method} ${url}`, JSON.stringify({ headers, body: parseJSON(body) }))
                    }
                    else {
                        console.log(`🌐 ${method} ${url}`)
                        const out = buildCurl(url, method, headers, body);
                        if (out.curl) console.log(out.curl);
                        if (out.hint) console.log(out.hint);
                        console.log(JSON.stringify({ headers, body: parseJSON(body) }, null, 4))
                    }
                }
            });
        }

    }
} catch (error) {
    console.log("[!] Exception: " + error.message);
}