import {
  encryptData,
  decryptData,
  arrayBufferToBase64,
  base64ToUint8Array,
  encryptBinary,
  decryptBinary,
  utf8ToBase64,
  base64ToUtf8,
  sanitizeFilename,
  generateToken,
  jsonOK,
  jsonError,
  handleCORS,
  isOriginAllowed,
  processRequest,
  getCORSHeaders,
  forwardRequest,
  addCORSHeaders
} from './helpers.js';

export
  async function handleRequest(request, env) {
  const JSONBIN = await env.JSONBIN;
  if (!JSONBIN) return jsonError("Missing env.JSONBIN", 500);

  try {
    const urlObj = new URL(request.url);
    const { pathname, searchParams } = urlObj;
    const headers = request.headers;

    // --- public token download handler ---
    // Path: /_download/<token>/<filename>
    if (pathname.startsWith("/_download/")) {
      const parts = pathname.split("/").filter(Boolean); // ['', '_download', token, filename]
      const token = parts[1];
      if (!token) return jsonError("Token missing", 400);
      const tokenPath = `/__token/${token}`;
      const tokenEntry = await env.JSONBIN.get(tokenPath);
      if (!tokenEntry) return jsonError("Token not found or expired", 404);
      let tokenObj;
      try {
        tokenObj = JSON.parse(tokenEntry);
      } catch (e) {
        return jsonError("Invalid token record", 500);
      }
      if (Date.now() > tokenObj.expires) {
        try { await env.JSONBIN.delete(tokenPath); } catch (e) { }
        return jsonError("Token expired", 404);
      }

      // Fetch the target file (raw) and stream similarly to GET/raw
      const target = tokenObj.target;
      const result = await env.JSONBIN.getWithMetadata(target, "arrayBuffer");
      if (!result || !result.value) return jsonError(`${target} Not Found`, 404);
      let value = result.value;
      const meta = result.metadata || {};
      const filetype = tokenObj.filetype || meta.filetype || "application/octet-stream";
      const filename = tokenObj.filename || meta.filename || target.split("/").pop() || "file";

      if (tokenObj.crypt) {
        // value is stored ciphertext bytes -> decode to string -> decrypt -> base64 -> bytes
        const ciphertext = new TextDecoder().decode(value);
        const decryptedBase64 = await decryptData(ciphertext, tokenObj.crypt);
        const bytes = base64ToUint8Array(decryptedBase64);
        value = bytes.buffer;
      }

      const headersOut = new Headers({
        "Content-Type": filetype,
        "Content-Disposition": `attachment; filename="${sanitizeFilename(filename)}"; filename*=UTF-8''${encodeURIComponent(sanitizeFilename(filename))}`,
        "Cache-Control": "no-store",
      });
      try { headersOut.set("Content-Length", String(value.byteLength || value.length || 0)); } catch (e) { }
      return new Response(value, { headers: headersOut });
    }

    //
    if (request.method === 'OPTIONS') {
      return handleCORS(request, env);
    }

    // --- AUTH ---
    const APIKEY = env.APIKEYSECRET;
    if (!APIKEY) return jsonError("Missing env.APIKEYSECRET", 500);

    const authHeader = headers.get("Authorization");
    const keyFromQuery = searchParams.get("key");
    const expectedHeader = `Bearer ${APIKEY}`;

    if (authHeader) {
      if (authHeader !== expectedHeader) return jsonError("Invalid Authorization header", 401);
    } else if (keyFromQuery) {
      if (keyFromQuery !== APIKEY) return jsonError("Invalid key query", 401);
    } else return jsonError("Missing Authorization or key", 401);


    const crypt = searchParams.get("c");
    const q = searchParams.get("q");
    const sParam = searchParams.get("s");
    const listFlag = searchParams.has("list");
    const encbase64 = searchParams.has("b64");
    const redirect = searchParams.has("redirect") || searchParams.has("r");
    const forward = searchParams.has("forward") || searchParams.has("f");

    const isJson = pathname.endsWith(".json");

    const downloadFlag = true; // force wget to save file cleanly


    // === 1️⃣ LIST MODE ===
    if (listFlag) {
      const list = await env.JSONBIN.list();
      const result = [];
      for (const key of list.keys) {
        const meta = key.metadata || {};
        result.push({
          name: key.name,
          size: meta.size || "?",
          filetype: meta.filetype || "json/raw",
          filename: meta.filename || "-",
        });
      }
      // Plain text table (wget/curl friendly)
      const table_header = `${"name".padEnd(20)}  ${"filename".padEnd(20)}  ${"filetype".padEnd(20)}\n`
        + `${"-".repeat(60)}\n`;
      ;
      const textTable = result
        .map(
          (r) =>
            `${r.name.padEnd(20)}  ${r.filename.padEnd(20)}  ${r.filetype.padEnd(25)}  ${r.size}`
        )
        .join("\n");
      return new Response(table_header + textTable + "\n", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    // === 2️⃣ GET ===
    if (request.method === "GET") {
      let storeHint = sParam || "raw";
      if (q || isJson || redirect) storeHint = "json";
      const isRaw = storeHint === "raw";
      const wantDownload = searchParams.has("download") || searchParams.has("dl");
      console.log(`get file: pathname:${pathname}, sParam:${sParam}, isRaw:${isRaw}`)


      // try json first (unless s=raw)
      if (!isRaw) {
        // const stored = await env.JSONBIN.get(pathname);
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError(`${pathname} Not Found`, 404);

        let value = result.value;
        if (value) {
          // convert ArrayBuffer/Uint8Array to UTF-8 string
          let text;
          if (value instanceof ArrayBuffer) {
            text = new TextDecoder().decode(new Uint8Array(value));
          } else if (value instanceof Uint8Array) {
            text = new TextDecoder().decode(value);
          } else {
            text = String(value);
          }

          if (crypt) {
            // stored ciphertext bytes -> utf8 string -> decrypt -> maybe base64 or plaintext JSON string
            const ciphertext = text;
            const decrypted = await decryptData(ciphertext, crypt);

            // decrypted may be plain JSON text or a base64-encoded payload (for binary-safe storage).
            // Try parsing as JSON first; if that fails, try base64 -> UTF-8 decode.
            let decoded = decrypted;
            try {
              JSON.parse(decoded);
            } catch (e) {
              try {
                const bytes = base64ToUint8Array(decrypted);
                decoded = new TextDecoder().decode(bytes);
              } catch (e2) {
                // fallback: keep decrypted as-is
              }
            }
            text = decoded;
          }

          // ensure value is a JSON string for downstream JSON.parse
          value = text;

          const disposition = `attachment; filename="${pathname.split("/").pop() || "data.json"}"`;
          const json = JSON.parse(value);

          if (wantDownload) {
            // create a short-lived token and redirect to public download URL
            const filenameForToken = sanitizeFilename(pathname.split("/").pop() || "data.json");
            const token = generateToken();
            const expiresSec = parseInt(searchParams.get("expires") || "60", 10) || 60;
            const tokenObj = { target: pathname, expires: Date.now() + expiresSec * 1000, filename: filenameForToken, filetype: "application/json", crypt: crypt };
            await env.JSONBIN.put(`/__token/${token}`, JSON.stringify(tokenObj));
            return new Response(null, { status: 302, headers: { Location: `/_download/${token}/${encodeURIComponent(filenameForToken)}`, "Cache-Control": "no-store" } });
          }

          if (redirect) {
            let url = "";
            if (q && json.hasOwnProperty(q)) {
              url = json[q];

            } else {
              if (!json.url) {
                return jsonError(`redirect url Not Found`, 404);
              }
              url = json.url;

            }



            // const url = json.url;
            // Return a 302 redirect response
            return new Response(null, {
              status: 302,
              headers: {
                "Location": url,
                // Optional: for clarity
                "Cache-Control": "no-store",
              },
            });

          }
          if (forward) {
            let url = "";
            if (q && json.hasOwnProperty(q)) {
              url = json[q];

            } else {
              if (!json.url) {
                return jsonError(`redirect url Not Found`, 404);
              }
              url = json.url;

            }


            try {
              const config = {
                targetUrl: url,
                allowedOrigins: env.ALLOWED_ORIGINS?.split(',') || ['*'],
                timeout: parseInt(env.TIMEOUT || '30000'),
                logRequests: env.LOG_REQUESTS === 'true',
              };

              // Log request details (optional)
              if (config.logRequests) {
                console.log('Incoming request:', {
                  method: request.method,
                  url: request.url,
                  headers: Object.fromEntries(request.headers),
                });
              }

              // Check origin if not wildcard
              if (!isOriginAllowed(request, config.allowedOrigins)) {
                return new Response('Origin not allowed', { status: 403 });
              }

              const processedRequest = await processRequest(request, config);
              const response = await forwardRequest(processedRequest, config);

              return addCORSHeaders(response, request, config);

            }
            catch (error) {
              console.error('Proxy error:', error);

              return new Response(
                JSON.stringify({
                  error: 'Proxy Error',
                  message: error.message,
                  timestamp: new Date().toISOString()
                }),
                {
                  status: 500,
                  headers: {
                    'Content-Type': 'application/json',
                    ...getCORSHeaders(request, ['*'])
                  }
                }
              );
            }


          }



          if (!q) {
            return new Response(value, {
              headers: {
                "Content-Type": "application/json",
                "Content-Disposition": disposition,
              },
            });
          } else {

            if (json.hasOwnProperty(q)) {
              let text = String(json[q]);
              if (encbase64) {
                text = base64ToUtf8(text);
              }
              return new Response(text, {
                headers: {
                  "Content-Type": "text/html",
                  "Content-Disposition": disposition,
                },
              });
            } else {
              return jsonError(`${q} Not Found`, 404);
            }
          }

        }
      }

      // try raw with metadata
      const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
      if (!result || !result.value) return jsonError(`${pathname} Not Found`, 404);

      let value = result.value;
      const meta = result.metadata || {};
      const filetype = meta.filetype || "application/octet-stream";
      let filename = meta.filename || pathname.split("/").pop() || "file";
      filename = searchParams.get("filename") || filename;
      filename = sanitizeFilename(filename);
      if (!filename.includes(".")) {
        const ext = filetype.split("/")[1] || "bin";
        filename = `${filename}.${ext}`;
      }
      if (crypt) {
        // value is stored ciphertext (UTF-8 bytes containing the iv:enc string)
        const ciphertext = new TextDecoder().decode(value);
        // decrypt -> returns base64 payload (we encrypted base64 of original binary)
        const decryptedBase64 = await decryptData(ciphertext, crypt);
        const bytes = base64ToUint8Array(decryptedBase64);
        value = bytes.buffer;

      }


      if (wantDownload) {
        const filenameForToken = sanitizeFilename(filename);
        const token = generateToken();
        const expiresSec = parseInt(searchParams.get("expires") || "60", 10) || 60;
        const tokenObj = { target: pathname, expires: Date.now() + expiresSec * 1000, filename: filenameForToken, filetype, crypt: crypt };
        await env.JSONBIN.put(`/__token/${token}`, JSON.stringify(tokenObj));
        return new Response(null, { status: 302, headers: { Location: `/_download/${token}/${encodeURIComponent(filenameForToken)}`, "Cache-Control": "no-store" } });
      }

      const headersOut = new Headers({
        "Content-Type": filetype,
        // Basic Content-Disposition and RFC5987 filename* for wider client support
        "Content-Disposition": `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
        "Content-Location": `/${encodeURIComponent(filename)}`,
        "Cache-Control": "no-store",
      });
      try {
        headersOut.set("Content-Length", String(value.byteLength || value.length || 0));
      } catch (e) { }
      return new Response(value, { headers: headersOut });
    }

    // === 3️⃣ POST / PATCH ===
    if (request.method === "POST" || request.method === "PATCH") {
      let contentType = headers.get("content-type") || "";
      let storetype = sParam;
      if (!storetype) {
        if (q || isJson) storetype = "json";
        else if (contentType.includes("json")) storetype = "json";
        else storetype = "raw";
      }
      console.log(`store file: pathname:${pathname}, storetype:${storetype} `)

      if (storetype === "json") {
        let existing = {};
        const old = await env.JSONBIN.get(pathname);
        if (old) {
          let val = old;
          if (crypt) val = await decryptData(val, crypt);
          try {
            existing = JSON.parse(val);
          } catch { }
        }

        let bodyText = await request.text();
        if (encbase64) bodyText = utf8ToBase64(bodyText);

        if (q) { existing[q] = bodyText; }
        else {
          try {
            existing = JSON.parse(bodyText);
          } catch (e) {
            return jsonError("Invalid JSON: " + e.message, 400);
          }
        }

        let dataToStore = JSON.stringify(existing);
        if (crypt) {
          dataToStore = await encryptData(dataToStore, crypt)
        };
        await env.JSONBIN.put(pathname, dataToStore, {
          metadata: { crypt: crypt },
        });
        return jsonOK({ ok: true, type: "json", crypt: crypt });
      }

      if (storetype === "raw") {
        const buffer = await request.arrayBuffer();
        const segments = pathname.split("/");
        let filename = segments.pop() || "file";
        if (!filename.includes(".")) {
          const ext = contentType.split("/")[1] || "bin";
          filename = `${filename}.${ext}`;
        }
        let toStore = buffer;
        if (crypt) {
          // encrypt binary payload and store ciphertext as UTF-8 bytes
          const encrypted = await encryptBinary(buffer, crypt);
          toStore = new TextEncoder().encode(encrypted).buffer;

          // const utf8 =  String.fromCharCode(...new Uint8Array(buffer));
          // const decrypted = await decryptData(utf8, crypt);
          // const bytes = Uint8Array.from(atob(decrypted), (c) => c.charCodeAt(0));
          // value = bytes.buffer;
          // toStore = await encryptData(utf8, crypt);



        }
        await env.JSONBIN.put(pathname, toStore, {
          metadata: { filetype: contentType || "application/octet-stream", filename, size: (toStore && toStore.byteLength) || undefined },
        });
        return jsonOK({ stored: filename, type: "raw" });
      }

      return jsonError("Unsupported store type", 400);
    }

    // === 4️⃣ DELETE ===
    if (request.method === "DELETE") {
      await env.JSONBIN.delete(pathname);
      return jsonOK({ deleted: true });
    }

    return jsonError("Method Not Allowed", 405);
  } catch (err) {
    return jsonError(err.message || String(err), 500);
  }
}

// --- helper responses ---
// (response helpers moved to `helpers.js`)
