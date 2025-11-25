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

export async function handleRequest(request, env) {
  const JSONBIN = env.JSONBIN;
  if (!JSONBIN) return jsonError("Missing env.JSONBIN", 500);
  
  const APIKEY = env.APIKEYSECRET;
  if (!APIKEY) return jsonError("Missing env.APIKEYSECRET", 500);

  if (request.method === 'OPTIONS') {
    return handleCORS(request, env);
  }

  try {
    const urlObj = new URL(request.url);
    const originPathname = urlObj.pathname;
    const { searchParams } = urlObj;
    
    const forwardPath = `/_forward/${APIKEY}`;
    const urlSplit = env.URLSPLIT || "/urlsplit";
    const isForward = originPathname.startsWith(forwardPath);

    let pathname = originPathname;
    let forwardPathname = "/";

    console.log("pathname", pathname);

    if (isForward) {
      pathname = originPathname.slice(forwardPath.length);

      if(pathname.includes(urlSplit)){

        const pathname_list = pathname.split(urlSplit);
        console.log("pathname_list",pathname_list);
        pathname = pathname_list[0];
        if(pathname_list.length > 1)
        forwardPathname = pathname_list[1];


      }
    }
    // remove slash
    if(pathname.endsWith("/") && (pathname.length > 0 )){
      console.log(pathname, " -->", pathname.slice(0,pathname.length-1)) ; 
      pathname = pathname.slice(0,pathname.length-1);
    }
    console.log(`pathname:${pathname}, forwardPathname:${forwardPathname}`);

    const headers = request.headers;
    const crypt = searchParams.get("c");
    const q = searchParams.get("q");

    // === PUBLIC TOKEN DOWNLOAD ===
    if (pathname.startsWith("/_download/")) {
      const parts = pathname.split("/").filter(Boolean);
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

      const target = tokenObj.target;
      const result = await env.JSONBIN.getWithMetadata(target, "arrayBuffer");
      if (!result || !result.value) return jsonError(`${target} Not Found`, 404);
      
      let value = result.value;
      const meta = result.metadata || {};
      const filetype = tokenObj.filetype || meta.filetype || "application/octet-stream";
      const filename = tokenObj.filename || meta.filename || target.split("/").pop() || "file";

      if (tokenObj.crypt) {
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
      try { 
        headersOut.set("Content-Length", String(value.byteLength || value.length || 0)); 
      } catch (e) { }
      
      return new Response(value, { headers: headersOut });
    }

    // === FORWARD HANDLER (handles ALL methods) ===
    if (isForward) {
      console.log(`isForward: ${pathname}`)
      // Fetch the config from JSONBIN
      const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
      if (!result || !result.value) {
        return jsonError(`Forward config not found: ${pathname}`, 404);
      }

      // Convert to text
      let text;
      const value = result.value;
      if (value instanceof ArrayBuffer) {
        text = new TextDecoder().decode(new Uint8Array(value));
      } else if (value instanceof Uint8Array) {
        text = new TextDecoder().decode(value);
      } else {
        text = String(value);
      }

      // Decrypt if needed
      if (crypt) {
        const decrypted = await decryptData(text, crypt);
        let decoded = decrypted;
        try {
          JSON.parse(decoded);
        } catch (e) {
          try {
            const bytes = base64ToUint8Array(decrypted);
            decoded = new TextDecoder().decode(bytes);
          } catch (e2) {
            // fallback
          }
        }
        text = decoded;
      }

      // Parse JSON config
      let json;
      try {
        json = JSON.parse(text);
      } catch (e) {
        return jsonError(`Invalid JSON in forward config: ${e.message}`, 500);
      }

      // Get target URL
      let targetUrl = "";
      if (q && json.hasOwnProperty(q)) {
        targetUrl = json[q];
      } else if (json.url) {
        targetUrl = json.url;
      } else {
        return jsonError(`No target URL found in ${pathname}`, 404);
      }

      // Forward the request
      console.log(`targetUrl: ${targetUrl}`)

      try {
        const config = {
          targetUrl: targetUrl,
          forwardPathname : forwardPathname,
          allowedOrigins: env.ALLOWED_ORIGINS?.split(',') || ['*'],
          timeout: parseInt(env.TIMEOUT || '30000'),
          logRequests: env.LOG_REQUESTS === 'true',
        };

        if (config.logRequests) {
          console.log('Forwarding request:', {
            method: request.method,
            from: request.url,
            to: targetUrl,
          });
        }

        if (!isOriginAllowed(request, config.allowedOrigins)) {
          return new Response('Origin not allowed', { status: 403 });
        }

        const processedRequest = await processRequest(request, config);
        const response = await forwardRequest(processedRequest, config);

        return addCORSHeaders(response, request, config);

      } catch (error) {
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

    // === AUTHENTICATION (for non-forward requests) ===
    const authHeader = headers.get("Authorization");
    const keyFromQuery = searchParams.get("key");
    const expectedHeader = `Bearer ${APIKEY}`;

    if (authHeader) {
      if (authHeader !== expectedHeader) {
        return jsonError("Invalid Authorization header", 401);
      }
    } else if (keyFromQuery) {
      if (keyFromQuery !== APIKEY) {
        return jsonError("Invalid key query", 401);
      }
    } else {
      return jsonError("Missing Authorization or key", 401);
    }

    // Parse additional params
    const sParam = searchParams.get("s");
    const listFlag = searchParams.has("list");
    const encbase64 = searchParams.has("b64");
    const redirect = searchParams.has("redirect") || searchParams.has("r");
    const isJson = pathname.endsWith(".json");

    // === LIST MODE ===
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
      
      const table_header = `${"name".padEnd(20)}  ${"filename".padEnd(20)}  ${"filetype".padEnd(20)}\n${"-".repeat(60)}\n`;
      const textTable = result
        .map((r) => `${r.name.padEnd(20)}  ${r.filename.padEnd(20)}  ${r.filetype.padEnd(25)}  ${r.size}`)
        .join("\n");
      
      return new Response(table_header + textTable + "\n", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    // === GET ===
    if (request.method === "GET") {
      let storeHint = sParam || "raw";
      if (q || isJson || redirect) storeHint = "json";
      const isRaw = storeHint === "raw";
      const wantDownload = searchParams.has("download") || searchParams.has("dl");
      
      console.log(`GET file: pathname:${pathname}, sParam:${sParam}, isRaw:${isRaw}`);

      // Try JSON first (unless s=raw)
      if (!isRaw) {
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) {
          return jsonError(`${pathname} Not Found`, 404);
        }

        let value = result.value;
        
        // Convert to text
        let text;
        if (value instanceof ArrayBuffer) {
          text = new TextDecoder().decode(new Uint8Array(value));
        } else if (value instanceof Uint8Array) {
          text = new TextDecoder().decode(value);
        } else {
          text = String(value);
        }

        // Decrypt if needed
        if (crypt) {
          const decrypted = await decryptData(text, crypt);
          let decoded = decrypted;
          try {
            JSON.parse(decoded);
          } catch (e) {
            try {
              const bytes = base64ToUint8Array(decrypted);
              decoded = new TextDecoder().decode(bytes);
            } catch (e2) {
              // fallback
            }
          }
          text = decoded;
        }

        const disposition = `attachment; filename="${pathname.split("/").pop() || "data.json"}"`;
        const json = JSON.parse(text);

        // Handle download with token
        if (wantDownload) {
          const filenameForToken = sanitizeFilename(pathname.split("/").pop() || "data.json");
          const token = generateToken();
          const expiresSec = parseInt(searchParams.get("expires") || "60", 10) || 60;
          const tokenObj = {
            target: pathname,
            expires: Date.now() + expiresSec * 1000,
            filename: filenameForToken,
            filetype: "application/json",
            crypt: crypt
          };
          await env.JSONBIN.put(`/__token/${token}`, JSON.stringify(tokenObj));
          return new Response(null, {
            status: 302,
            headers: {
              Location: `/_download/${token}/${encodeURIComponent(filenameForToken)}`,
              "Cache-Control": "no-store"
            }
          });
        }

        // Handle redirect
        if (redirect) {
          let url = "";
          if (q && json.hasOwnProperty(q)) {
            url = json[q];
          } else if (json.url) {
            url = json.url;
          } else {
            return jsonError(`Redirect URL not found`, 404);
          }

          return new Response(null, {
            status: 302,
            headers: {
              "Location": url,
              "Cache-Control": "no-store",
            },
          });
        }

        // Return JSON or specific field
        if (!q) {
          return new Response(text, {
            headers: {
              "Content-Type": "application/json",
              "Content-Disposition": disposition,
            },
          });
        } else {
          if (json.hasOwnProperty(q)) {
            let fieldText = String(json[q]);
            if (encbase64) {
              fieldText = base64ToUtf8(fieldText);
            }
            return new Response(fieldText, {
              headers: {
                "Content-Type": "text/plain",
                "Content-Disposition": disposition,
              },
            });
          } else {
            return jsonError(`Field '${q}' not found`, 404);
          }
        }
      }

      // Try raw with metadata
      const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
      if (!result || !result.value) {
        return jsonError(`${pathname} Not Found`, 404);
      }

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
        const ciphertext = new TextDecoder().decode(value);
        const decryptedBase64 = await decryptData(ciphertext, crypt);
        const bytes = base64ToUint8Array(decryptedBase64);
        value = bytes.buffer;
      }

      if (wantDownload) {
        const filenameForToken = sanitizeFilename(filename);
        const token = generateToken();
        const expiresSec = parseInt(searchParams.get("expires") || "60", 10) || 60;
        const tokenObj = {
          target: pathname,
          expires: Date.now() + expiresSec * 1000,
          filename: filenameForToken,
          filetype,
          crypt: crypt
        };
        await env.JSONBIN.put(`/__token/${token}`, JSON.stringify(tokenObj));
        return new Response(null, {
          status: 302,
          headers: {
            Location: `/_download/${token}/${encodeURIComponent(filenameForToken)}`,
            "Cache-Control": "no-store"
          }
        });
      }

      const headersOut = new Headers({
        "Content-Type": filetype,
        "Content-Disposition": `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
        "Content-Location": `/${encodeURIComponent(filename)}`,
        "Cache-Control": "no-store",
      });
      
      try {
        headersOut.set("Content-Length", String(value.byteLength || value.length || 0));
      } catch (e) { }
      
      return new Response(value, { headers: headersOut });
    }

    // === POST / PATCH ===
    if (request.method === "POST" || request.method === "PATCH") {
      let contentType = headers.get("content-type") || "";
      let storetype = sParam;
      
      if (!storetype) {
        if (q || isJson) storetype = "json";
        else if (contentType.includes("json")) storetype = "json";
        else storetype = "raw";
      }
      
      console.log(`Store file: pathname:${pathname}, storetype:${storetype}`);

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

        if (q) {
          existing[q] = bodyText;
        } else {
          try {
            existing = JSON.parse(bodyText);
          } catch (e) {
            return jsonError("Invalid JSON: " + e.message, 400);
          }
        }

        let dataToStore = JSON.stringify(existing);
        if (crypt) {
          dataToStore = await encryptData(dataToStore, crypt);
        }
        
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
          const encrypted = await encryptBinary(buffer, crypt);
          toStore = new TextEncoder().encode(encrypted).buffer;
        }
        
        await env.JSONBIN.put(pathname, toStore, {
          metadata: {
            filetype: contentType || "application/octet-stream",
            filename,
            size: toStore.byteLength
          },
        });
        
        return jsonOK({ stored: filename, type: "raw" });
      }

      return jsonError("Unsupported store type", 400);
    }

    // === DELETE ===
    if (request.method === "DELETE") {
      await env.JSONBIN.delete(pathname);
      return jsonOK({ deleted: true });
    }

    return jsonError("Method Not Allowed", 405);
    
  } catch (err) {
    console.error('Request error:', err);
    return jsonError(err.message || String(err), 500);
  }
}