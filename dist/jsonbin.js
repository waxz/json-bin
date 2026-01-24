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
    addCORSHeaders,
    bufferToText,
    decryptAndDecode
} from './helpers.js';

export async function handleRequest(request, env) {
    // ============================================================
    // INITIALIZATION & VALIDATION
    // ============================================================

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

        // Forward logic
        const forwardPath = `/_forward/${APIKEY}`;
        const urlSplitMarker = env.URLSPLIT || "/urlsplit";
        const isForward = originPathname.startsWith(forwardPath);
        let pathname = originPathname;
        let forwardPathname = "/";

        // ============================================================
        // ADMIN PANEL
        // ============================================================
        if (originPathname === '/' && !searchParams.has("list") ) {
            return new Response(getAdminHTML(env), {
                headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Cache-Control': 'no-cache'
                }
            });
        }

        if (isForward) {
            pathname = originPathname.slice(forwardPath.length);
            if (pathname.includes(urlSplitMarker)) {
                const [jsonbinPath, targetPath] = pathname.split(urlSplitMarker);
                pathname = jsonbinPath;
                forwardPathname = targetPath || "/";
            }
        }

        if (pathname.endsWith("/") && pathname.length > 1) {
            pathname = pathname.slice(0, -1);
        }

        const headers = request.headers;
        const crypt = searchParams.get("c");
        const q = searchParams.get("q");
        const sParam = searchParams.get("s");

        // ============================================================
        // PUBLIC TOKEN DOWNLOAD
        // ============================================================
        if (pathname.startsWith("/_download/")) {
            return await handleTokenDownload(request, env, crypt);
        }

        // ============================================================
        // FORWARD/PROXY HANDLER
        // ============================================================
        if (isForward) {
            return await handleForward(pathname, forwardPathname, request, env, { crypt, q });
        }

        // ============================================================
        // AUTHENTICATION
        // ============================================================
        const authHeader = headers.get("Authorization");
        const keyFromQuery = searchParams.get("key");
        const expectedHeader = `Bearer ${APIKEY}`;

        if (authHeader && authHeader !== expectedHeader) {
            return jsonError("Invalid Authorization header", 401);
        } else if (keyFromQuery && keyFromQuery !== APIKEY) {
            return jsonError("Invalid key query", 401);
        } else if (!authHeader && !keyFromQuery) {
            return jsonError("Missing Authorization or key", 401);
        }

        // ============================================================
        // OPERATION ROUTING
        // ============================================================

        const listFlag = searchParams.has("list");
        const encbase64 = searchParams.has("b64");
        const redirect = searchParams.has("redirect") || searchParams.has("r");
        const isJson = pathname.endsWith(".json");

        if (listFlag) {
            return await handleList(searchParams,env);
        }

        if (request.method === "GET") {
            return await handleGet(pathname, env, { sParam, q, crypt, encbase64, redirect, isJson, searchParams });
        }

        if (request.method === "POST" || request.method === "PATCH") {
            return await handleStore(pathname, request, env, { sParam, q, crypt, encbase64, isJson });
        }

        if (request.method === "DELETE") {
            await env.JSONBIN.delete(pathname);
            return jsonOK({ deleted: true });
        }

        return jsonError("Method Not Allowed", 405);

    } catch (err) {
        console.error('[ERROR]', err.message, err.stack);
        return jsonError(err.message || String(err), 500);
    }
}

// ============================================================
// HANDLER FUNCTIONS
// ============================================================
async function handleTokenDownload(request, env, ) {
    const url = new URL(request.url);
    const { searchParams } = url;
  
    const pathname = url.pathname;
    // const code = searchParams.get("c") || "";
    const shareCode = searchParams.get("share") || "";
  
  
    console.log(`shareCode=${shareCode}`)
  
    const link = `${decodeURIComponent(pathname)}`.slice(11);
    
    const shareLink = decodeURIComponent(await decryptData(link, shareCode));
    
  
    // const shareLink = await decryptData(link, code);
  
    console.log(`handleTokenDownload link ${link}`);
    console.log(`handleTokenDownload shareLink ${shareLink}`);
    const path = shareLink.slice(4);
    console.log(`handleTokenDownload path ${path}`);

    if(shareLink.startsWith("/_s/")){
      console.log("path",path);
  
      const result = await env.JSONBIN.getWithMetadata(path, "arrayBuffer");
      if (!result || !result.value) return jsonError("Source item not found", 404);
      const newMeta = result.metadata || {};
  
      console.log("newMeta",newMeta);
      
      if(newMeta.expiresSec == 0){
        return jsonError("Share is Disabled", 404);
      }
      let shared_ok = false;
      if (shareCode == newMeta.code){
        if(newMeta.expiresSec == 1){
            shared_ok = true;
          }else{
            const now = Date.now();
            const dt = now - newMeta.shareActivateStamp;
            const sec = dt/1000;
            console.log("sec",sec);
            if(sec > newMeta.expiresSec){
              shared_ok = false;
            }else{
              shared_ok = true;
            }
          }
      }else{
        return jsonError("shareCode is Wrong", 404);
      }
  
      if(shared_ok){
     
        const filename = sanitizeFilename(newMeta.filename || path.split("/").pop() || "data");
  
        return new Response(result.value, {
          headers: {
            "Content-Type": newMeta.filetype,
            "Content-Disposition": `attachment; filename="${sanitizeFilename(filename)}"; filename*=UTF-8''${encodeURIComponent(sanitizeFilename(filename))}`,
            "Content-Length": String(result.value.byteLength || 0),
            "Cache-Control": "no-store"
          }
        });
      }
    }else{
      return jsonError("shareCode Expires", 404);
    }
}
async function handleForward(pathname, forwardPathname, request, env, { crypt, q }) {
    // ... (Keep existing forward logic as is, omitted for brevity but should be included in final) ...
    // Using simple version here for space, assume previous code exists
    const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
    if (!result?.value) return jsonError(`Forward config not found`, 404);
    
    let text = bufferToText(result.value);
    if (crypt) text = await decryptAndDecode(text, crypt);
    
    let config;
    try { config = JSON.parse(text); } catch (e) { return jsonError("Invalid Config", 500); }
    
    let targetUrl = (q && config[q]) ? config[q] : config.url;
    if (!targetUrl) return jsonError("No target URL", 404);

    const forwardConfig = {
        targetUrl: targetUrl,
        forwardPathname: forwardPathname,
        allowedOrigins: ['*'],
        timeout: 100000
    };
    
    const processedRequest = await processRequest(request, forwardConfig);
    const response = await forwardRequest(processedRequest, forwardConfig);
    
    // Redirect HTML logic
    const content_type = response.headers.get("content-type");
    if (content_type && content_type.includes("text/html")) {
        return new Response(null, {
            status: 302,
            headers: { "Location": `${targetUrl}${forwardPathname}`, "Cache-Control": "no-store" }
        });
    }
    return addCORSHeaders(response, request, forwardConfig);
}

async function handleList(searchParams, env) {

    const list = await env.JSONBIN.list();
    const items = [];
    for (const key of list.keys) {
        const meta = key.metadata || {};
        items.push({
            name: key.name,
            size: meta.size || "?",
            filetype: meta.filetype || "json/raw",
            filename: meta.filename || "-",
            encrypted: meta.crypt ? "yes" : "no"
        });
    }

    if (searchParams.has("json_response")) {
        var jsonArray = JSON.parse(JSON.stringify(items))
        return jsonOK(jsonArray);

    }else{
        const header = `${"name".padEnd(20)}  ${"filename".padEnd(20)}  ${"filetype".padEnd(20)}  ${"encrypted".padEnd(10)}\n${"-".repeat(80)}\n`;

        const rows = items.map(r => `${r.name.padEnd(20)}  ${r.filename.padEnd(20)}  ${r.filetype.padEnd(25)}  ${r.encrypted.padEnd(10)}  ${r.size}`).join("\n");
        return new Response(header + rows + "\n", { headers: { "Content-Type": "text/plain" } });
    }


}

async function handleGet(pathname, env, { sParam, q, crypt, encbase64, redirect, isJson, searchParams }) {
    let storeHint = sParam || "raw";
    if (q || isJson || redirect) storeHint = "json";
    const isRaw = storeHint === "raw";
    const wantDownload = searchParams.has("download") || searchParams.has("dl");

    // JSON GET
    if (!isRaw) {
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result?.value) return jsonError(`${pathname} Not Found`, 404);

        let text = bufferToText(result.value);
        const meta = result.metadata || {};

        try {
            if (meta.crypt) {
                if (!crypt) return jsonError(`${pathname} is encrypted`, 403);
                text = await decryptAndDecode(text, crypt);
            }
        } catch (error) {
            return jsonError(`Decryption failed`, 401);
        }

        const json = JSON.parse(text);
        
        if (wantDownload) {
            return createDownloadToken(pathname, "application/json", searchParams, env, crypt);
        }

        if (redirect) {
            const url = (q && json[q]) || json.url;
            return new Response(null, { status: 302, headers: { "Location": url, "Cache-Control": "no-store" } });
        }

        if (q) {
            if (!json.hasOwnProperty(q)) return jsonError(`Field '${q}' not found`, 404);
            let fieldText = String(json[q]);
            if (encbase64) fieldText = base64ToUtf8(fieldText);
            return new Response(fieldText, { headers: { "Content-Type": "text/plain" } });
        }

        return new Response(text, { headers: { "Content-Type": "application/json" } });
    }

    // RAW GET
    const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
    if (!result?.value) return jsonError(`${pathname} Not Found`, 404);

    let value = result.value;
    const meta = result.metadata || {};
    const filetype = meta.filetype || "application/octet-stream";
    let filename = searchParams.get("filename") || meta.filename || pathname.split("/").pop() || "file";
    
    try {
        if (meta.crypt) {
            if (!crypt) return jsonError(`${pathname} is encrypted`, 403);
            const ciphertext = new TextDecoder().decode(value);
            const decryptedBase64 = await decryptData(ciphertext, crypt);
            value = base64ToUint8Array(decryptedBase64).buffer;
        }
    } catch (error) {
        return jsonError(`Decryption failed`, 401);
    }

    if (wantDownload) {
        return createDownloadToken(pathname, filetype, searchParams, env, crypt, filename);
    }

    return new Response(value, {
        headers: {
            "Content-Type": filetype,
            "Content-Disposition": `attachment; filename="${filename}"`,
            "Content-Length": String(value.byteLength || 0),
            "Cache-Control": "no-store"
        }
    });
}

/**
 * Handle POST/PATCH operation - store or update data
 */
async function handleStore(pathname, request, env, { sParam, q, crypt, encbase64, isJson }) {
    const { searchParams } = new URL(request.url);
    const contentType = request.headers.get("content-type") || "";
    let filename = searchParams.get("filename")|| pathname.split("/").pop() || "file";
    filename = filename.trim();

    // ==========================================
    // 1. RENAME (MOVE) LOGIC
    // ==========================================
    if (searchParams.has("rename_to")) {
        const newPath = searchParams.get("rename_to").trim();
        
        if (!newPath || !newPath.startsWith("/")) {
            return jsonError("New path must start with /", 400);
        }
        if (newPath === pathname) {
            return jsonError("New path is same as current", 400);
        }

        // Check if destination already exists to prevent accidental overwrite
        const destExists = await env.JSONBIN.get(newPath);
        if (destExists && !searchParams.has("force")) {
            return jsonError("Destination already exists. Use ?force=true to overwrite.", 409);
        }

        // Get existing data (Value + Metadata)
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError("Source item not found", 404);

        // Save to new key
        // We preserve the existing metadata (including encryption status, filetype, etc.)
        // We update the filename in metadata to match the new path name
        const newMeta = result.metadata || {};
        newMeta.filename = filename;

        await env.JSONBIN.put(newPath, result.value, {
            metadata: newMeta
        });

        // Delete old key
        await env.JSONBIN.delete(pathname);

        return jsonOK({ renamed: true, from: pathname, to: newPath });
    }

    // ==========================================
    // 2. SET TYPE (METADATA ONLY) LOGIC
    // ==========================================
    if (searchParams.has("set_type")) {
        const newType = searchParams.get("set_type");
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError("Item not found", 404);

        const meta = result.metadata || {};
        meta.filetype = newType; 
        
        await env.JSONBIN.put(pathname, result.value, { metadata: meta });
        return jsonOK({ ok: true, type: newType, message: "Type updated" });
    }
    if (searchParams.has("set_name")) {
        const newName = searchParams.get("set_name");
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError("Item not found", 404);

        const meta = result.metadata || {};
        meta.filename = newName; 
        
        await env.JSONBIN.put(pathname, result.value, { metadata: meta });
        return jsonOK({ ok: true, type: newType, message: "Name updated" });
    }
    // ==========================================
    // 3. STANDARD STORE LOGIC (JSON/RAW)
    // ==========================================
    
    // Determine storage type
    let storetype = sParam;
    if (!storetype) {
        storetype = (q || isJson || contentType.includes("json")) ? "json" : "raw";
    }

    // Store as JSON
    if (storetype === "json") {
        let existing = {};
        const result = await env.JSONBIN.getWithMetadata(pathname);

        if (result?.value) {
            const meta = result.metadata || {};
            let val = result.value;
            if (meta.crypt && crypt) {
                try { val = await decryptData(val, crypt); } catch(e) {}
            }
            try { existing = JSON.parse(val); } catch (e) {}
        }

        let bodyText = await request.text();
        if (encbase64) bodyText = utf8ToBase64(bodyText);

        if (q) existing[q] = bodyText;
        else {
            try { existing = JSON.parse(bodyText); } catch (e) { return jsonError("Invalid JSON", 400); }
        }

        let dataToStore = JSON.stringify(existing);
        if (crypt) dataToStore = await encryptData(dataToStore, crypt);

        await env.JSONBIN.put(pathname, dataToStore, { metadata: { crypt: !!crypt,filename, filetype: "application/json" } });
        return jsonOK({ ok: true, type: "json", encrypted: !!crypt });
    }

    // Store as raw binary
    if (storetype === "raw") {
        const buffer = await request.arrayBuffer();
        let toStore = buffer;
        
        // let filename = pathname.split("/").pop() || "file";
        // if (!filename.includes(".")) {
        //     const ext = contentType.split("/")[1] || "bin";
        //     filename = `${filename}.${ext}`;
        // }

        if (crypt) {
            const encrypted = await encryptBinary(buffer, crypt);
            toStore = new TextEncoder().encode(encrypted).buffer;
        }

        await env.JSONBIN.put(pathname, toStore, {
            metadata: {
                filetype: contentType || "application/octet-stream",
                filename,
                size: toStore.byteLength,
                crypt: !!crypt
            }
        });
        return jsonOK({ stored: filename, type: "raw", size: toStore.byteLength, encrypted: !!crypt });
    }
    return jsonError("Unsupported store type", 400);
}


// ============================================================
// HELPER: DOWNLOAD TOKEN
// ============================================================

async function createDownloadToken(pathname, filetype, searchParams, env, crypt, filename = null) {
    const filenameForToken = sanitizeFilename(filename || pathname.split("/").pop() || "data");
    // const token = generateToken();
    
    const code = searchParams.get("code") || "";
    const expiresSec = parseInt(searchParams.get("expires") || "0", 10) || 0;
    
    const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
    if (!result || !result.value) return jsonError("Source item not found", 404);
    const newMeta = result.metadata || {};
    
    const link = `/_s/${encodeURIComponent(pathname)}`;
    const shareLink = `/_download/${encodeURIComponent(await encryptData(link, code))}?share=${code}`;
    
    newMeta.code = code ;
    newMeta.shareActivateStamp = Date.now();
    newMeta.expiresSec = expiresSec ;
    newMeta.shareLink = shareLink;
    console.log("createDownloadToken searchParams:", searchParams);

    console.log("createDownloadToken newMeta:", newMeta);
    console.log("createDownloadToken link:", link);
    console.log("createDownloadToken shareLink:", shareLink);
    console.log("createDownloadToken code:", code);
    console.log("createDownloadToken expiresSec:", expiresSec);

    
    await env.JSONBIN.put(pathname, result.value, {
        metadata: newMeta
    });
    if (searchParams.has("json_response")) {
        return jsonOK({
            url: `${shareLink}`,
            filename: filenameForToken
        });
    }
    return new Response(null, {
    status: 302,
    headers: {
      Location: `/${shareLink}`,
      "Cache-Control": "no-store"
    }
    });

}
// ============================================================
// ADMIN PANEL HTML
// ============================================================
function getAdminHTML(env) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="https://img.icons8.com/?size=100&id=lR3lNSwEbHDV&format=png&color=000000">
    <title>JSONBIN Admin Panel</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"><\/script>
    <style>
        :root { 
            --primary: #667eea; 
            --primary-dark: #5568d3; 
            --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-500: #6b7280;
            --gray-600: #4b5563;
            --gray-700: #374151;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            background: var(--bg-gradient); 
            min-height: 100vh; 
            padding: 20px; 
            color: #333; 
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .hidden { display: none !important; }
        
        /* Loading */
        .loading { 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            padding: 40px;
            color: var(--gray-500);
        }
        .spinner {
            width: 24px;
            height: 24px;
            border: 3px solid var(--gray-200);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 10px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        /* Panels */
        .panel { 
            background: white; 
            border-radius: 12px; 
            padding: 24px; 
            margin-bottom: 20px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
        }
        .header { 
            margin-bottom: 20px; 
            color: white; 
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 1.5rem; }
        .auth-section { max-width: 400px; margin: 40px auto; text-align: center; }
        
        /* Grid */
        .content-grid { 
            display: grid; 
            grid-template-columns: 350px 1fr; 
            gap: 20px; 
            height: calc(100vh - 180px); 
        }
        @media (max-width: 968px) { 
            .content-grid { grid-template-columns: 1fr; height: auto; } 
        }
        
        /* List */
        .list-panel { display: flex; flex-direction: column; height: 100%; }
        .items-list { 
            flex: 1; 
            overflow-y: auto; 
            border: 1px solid var(--gray-200); 
            border-radius: 8px; 
            margin-top: 10px; 
        }
        .item { 
            padding: 12px; 
            border-bottom: 1px solid #f0f0f0; 
            cursor: pointer; 
            transition: all 0.2s ease; 
        }
        .item:hover { background: #f8f9fa; }
        .item:focus { outline: 2px solid var(--primary); outline-offset: -2px; }
        .item.active { background: #eff6ff; border-left: 4px solid var(--primary); }
        .item-header { display: flex; justify-content: space-between; align-items: center; }
        .item-name { font-weight: 500; font-size: 14px; word-break: break-all; }
        .item-meta { 
            font-size: 11px; 
            color: var(--gray-600); 
            margin-top: 4px; 
            display: flex; 
            gap: 8px; 
            align-items: center;
        }
        
        /* Badges */
        .badge { 
            padding: 2px 6px; 
            border-radius: 4px; 
            font-size: 10px; 
            font-weight: 600; 
            text-transform: uppercase; 
        }
        .badge-json { background: #dbeafe; color: #1e40af; }
        .badge-md { background: #fce7f3; color: #9d174d; }
        .badge-img { background: #dcfce7; color: #166534; }
        .badge-audio { background: #fef3c7; color: #b45309; }
        .badge-video { background: #e0e7ff; color: #4338ca; }
        .badge-raw { background: var(--gray-100); color: var(--gray-700); }
        .badge-lock { background: #fef3c7; color: #92400e; }
        
        /* Forms */
        .form-group { margin-bottom: 15px; }
        .form-group label { 
            display: block; 
            margin-bottom: 5px; 
            font-size: 0.875rem; 
            font-weight: 500; 
            color: var(--gray-700);
        }
        .form-control { 
            width: 100%; 
            padding: 10px 12px; 
            border: 1px solid var(--gray-200); 
            border-radius: 6px; 
            font-size: 14px; 
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-control:focus { 
            outline: none; 
            border-color: var(--primary); 
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        textarea.form-control { 
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; 
            min-height: 400px; 
            resize: vertical; 
            line-height: 1.5;
        }
        .md-preview { 
            border: 1px solid var(--gray-200); 
            border-radius: 6px; 
            padding: 20px; 
            min-height: 400px; 
            background: #fff; 
            overflow-y: auto;
            line-height: 1.6;
        }
        .md-preview h1, .md-preview h2, .md-preview h3 { margin: 1em 0 0.5em; }
        .md-preview p { margin: 0.5em 0; }
        .md-preview code { background: var(--gray-100); padding: 2px 6px; border-radius: 4px; }
        .md-preview pre { background: var(--gray-100); padding: 12px; border-radius: 6px; overflow-x: auto; }
        
        /* Audio Player */
        .audio-container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            color: white;
        }
        .audio-icon {
            font-size: 5rem;
            margin-bottom: 20px;
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        .audio-player {
            width: 100%;
            max-width: 500px;
            margin: 20px auto;
        }
        .audio-player audio {
            width: 100%;
            border-radius: 30px;
        }
        .audio-info {
            margin-top: 15px;
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        /* Toolbar */
        .editor-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            padding-bottom: 15px; 
            border-bottom: 1px solid #eee; 
            margin-bottom: 15px; 
        }
        .editor-header h2 {
            font-size: 1rem;
            max-width: 60%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .type-select { 
            padding: 6px 10px; 
            border-radius: 6px; 
            border: 1px solid var(--gray-200); 
            font-size: 12px; 
            background: white; 
            cursor: pointer; 
        }
        .type-select:focus { outline: none; border-color: var(--primary); }
        
        /* Buttons */
        .btn { 
            padding: 8px 16px; 
            border: none; 
            border-radius: 6px; 
            cursor: pointer; 
            font-size: 14px; 
            font-weight: 500; 
            display: inline-flex; 
            align-items: center; 
            justify-content: center;
            gap: 6px; 
            text-decoration: none; 
            transition: all 0.2s ease;
        }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn:hover:not(:disabled) { transform: translateY(-1px); }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover:not(:disabled) { background: var(--primary-dark); }
        .btn-success { background: var(--success); color: white; }
        .btn-success:hover:not(:disabled) { background: #059669; }
        .btn-danger { background: var(--danger); color: white; }
        .btn-danger:hover:not(:disabled) { background: #dc2626; }
        .btn-secondary { background: var(--gray-500); color: white; }
        .btn-secondary:hover:not(:disabled) { background: var(--gray-600); }
        .btn-outline { background: white; border: 1px solid var(--gray-200); color: var(--gray-700); }
        .btn-outline:hover:not(:disabled) { background: var(--gray-100); }
        
        .editor-actions { 
            margin-top: 20px; 
            display: flex; 
            gap: 10px; 
            border-top: 1px solid #eee; 
            padding-top: 20px; 
            flex-wrap: wrap; 
        }
        
        /* Tabs */
        .tabs { display: flex; gap: 2px; margin-bottom: -1px; }
        .tab { 
            padding: 10px 20px; 
            cursor: pointer; 
            border: 1px solid transparent; 
            border-radius: 6px 6px 0 0; 
            background: var(--gray-100); 
            color: var(--gray-600);
            font-size: 14px;
            transition: all 0.2s;
        }
        .tab:hover { background: var(--gray-200); }
        .tab.active { 
            background: white; 
            border-color: var(--gray-200); 
            color: var(--primary); 
            border-bottom: 1px solid white; 
            font-weight: 600; 
        }
        
        /* Stats */
        .stats { display: flex; gap: 10px; margin-bottom: 10px; }
        .stat-card { 
            background: #f8f9fa; 
            padding: 12px; 
            border-radius: 8px; 
            flex: 1; 
            text-align: center; 
        }
        .stat-val { font-size: 1.25rem; font-weight: bold; color: var(--primary); }
        .stat-lbl { font-size: 0.7rem; color: var(--gray-600); text-transform: uppercase; letter-spacing: 0.5px; }
        
        /* Modal */
        .modal-overlay { 
            position: fixed; 
            top: 0; 
            left: 0; 
            right: 0; 
            bottom: 0; 
            background: rgba(0,0,0,0.5); 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            z-index: 1000;
            animation: fadeIn 0.2s ease;
        }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .modal { 
            background: white; 
            padding: 24px; 
            border-radius: 12px; 
            width: 420px; 
            max-width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            animation: slideUp 0.3s ease;
        }
        @keyframes slideUp { from { transform: translateY(20px); opacity: 0; } }
        .modal h3 { margin-bottom: 20px; color: var(--gray-700); }
        .modal-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
        
        /* Alerts */
        .alert { 
            padding: 12px 16px; 
            border-radius: 8px; 
            margin-bottom: 15px; 
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .alert-success { background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; }
        .alert-warning { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray-500);
        }
        .empty-state-icon { font-size: 3rem; margin-bottom: 10px; }
        
        /* Keyboard Shortcut Hints */
        kbd {
            background: var(--gray-100);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            border: 1px solid var(--gray-200);
            font-family: monospace;
        }
        
        /* Tooltip */
        [data-tooltip] {
            position: relative;
        }
        [data-tooltip]:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--gray-700);
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            white-space: nowrap;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🗄️ JSONBIN Admin</h1>
            <button id="logoutBtn" class="btn btn-outline hidden" onclick="app.logout()">Logout</button>
        </div>
        
        <div id="authSection" class="panel auth-section">
            <h2 style="margin-bottom: 20px;">Authentication</h2>
            <form onsubmit="event.preventDefault(); app.login();">
                <div class="form-group">
                    <input type="password" id="apiKeyInput" class="form-control" placeholder="Enter API Key" autocomplete="current-password">
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;">Connect</button>
            </form>
        </div>
        
        <div id="mainContent" class="hidden">
            <div class="content-grid">
                <div class="panel list-panel">
                    <div class="stats">
                        <div class="stat-card">
                            <div class="stat-val" id="stTotal">0</div>
                            <div class="stat-lbl">Items</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-val" id="stJson">0</div>
                            <div class="stat-lbl">JSON</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-val" id="stEnc">0</div>
                            <div class="stat-lbl">Locked</div>
                        </div>
                    </div>
                    <div style="display:flex; gap:8px; margin-bottom:10px">
                        <button class="btn btn-primary" style="flex:1" onclick="app.newItem()" data-tooltip="Create new item">+ New</button>
                        <button class="btn btn-secondary" style="flex:1" onclick="app.loadItems()" data-tooltip="Refresh list">↻ Refresh</button>
                    </div>
                    <input type="text" id="searchBox" class="form-control" placeholder="🔍 Search items..." oninput="app.handleSearch()">
                    <div id="itemsList" class="items-list"></div>
                </div>
                
                <div class="panel" style="display: flex; flex-direction: column;">
                    <div id="editorHeader" class="editor-header hidden">
                        <h2 id="editorTitle" title="">Select Item</h2>
                        <select id="typeSelector" class="type-select" onchange="app.changeType(this.value)">
                            <option value="application/json">JSON</option>
                            <option value="text/plain">Text</option>
                            <option value="text/markdown">Markdown</option>
                            <option value="image/png">Image (PNG)</option>
                            <option value="image/jpeg">Image (JPEG)</option>
                            <option value="image/gif">Image (GIF)</option>
                            <option value="image/webp">Image (WebP)</option>
                            <option value="audio/mpeg">Audio (MP3)</option>
                            <option value="audio/wav">Audio (WAV)</option>
                            <option value="audio/ogg">Audio (OGG)</option>
                            <option value="video/mp4">Video (MP4)</option>
                            <option value="video/webm">Video (WebM)</option>
                            <option value="application/pdf">PDF</option>
                            <option value="application/octet-stream">Binary</option>
                        </select>
                    </div>
                    <div id="alertArea"></div>
                    <div id="editorContainer" style="flex: 1; display: flex; flex-direction: column;">
                        <div class="empty-state">
                            <div class="empty-state-icon">📄</div>
                            <p>Select an item to view or edit</p>
                            <p style="margin-top: 10px; font-size: 0.8rem;">or click <strong>+ New</strong> to create one</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Share Modal -->
    <div id="shareModal" class="hidden modal-overlay" onclick="app.closeModalOnBackdrop(event)">
        <div class="modal" onclick="event.stopPropagation()">
            <h3>🔗 Share Public Link</h3>
            <div class="form-group">
                <label>Expires In</label>
                <select id="shareExpiry" class="form-control">
                    <option value="0">Disabled</option>
                    <option value="1">Never (Forever)</option>
                    <option value="3600">1 Hour</option>
                    <option value="86400">1 Day</option>
                    <option value="604800">1 Week</option>
                </select>
            </div>
            <div class="form-group">
                <label>Share Code (Optional password)</label>
                <input type="text" class="form-control" id="sharedCode" placeholder="Leave empty for no password">
            </div>
            <div class="form-group hidden" id="shareResultGroup">
                <label>Share URL</label>
                <div style="display: flex; gap: 8px;">
                    <input type="text" id="shareUrl" class="form-control" readonly style="flex: 1;">
                    <button class="btn btn-secondary" onclick="app.copyShareUrl()" data-tooltip="Copy to clipboard">📋</button>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-outline" onclick="app.closeShareModal()">Close</button>
                <button class="btn btn-primary" id="btnGenShare" onclick="app.generateShareLink()">Generate Link</button>
            </div>
        </div>
    </div>

    <!-- Rename Modal -->
    <div id="renameModal" class="hidden modal-overlay" onclick="app.closeModalOnBackdrop(event)">
        <div class="modal" onclick="event.stopPropagation()">
            <h3>✏️ Rename Item</h3>
            <div class="form-group">
                <label>Path</label>
                <input type="text" id="renamePath" class="form-control" placeholder="/path/to/file">
            </div>
            <div class="form-group">
                <label>Filename</label>
                <input type="text" id="renameFilename" class="form-control" placeholder="filename.ext">
            </div>
            <div class="modal-footer">
                <button class="btn btn-outline" onclick="app.closeRenameModal()">Cancel</button>
                <button class="btn btn-primary" onclick="app.submitRename()">Save Changes</button>
            </div>
        </div>
    </div>

    <script>
        // ================== UTILITY FUNCTIONS ==================
        const utils = {
            escapeHtml(str) {
                if (!str) return '';
                const div = document.createElement('div');
                div.textContent = str;
                return div.innerHTML;
            },
            
            debounce(fn, delay) {
                let timer;
                return (...args) => {
                    clearTimeout(timer);
                    timer = setTimeout(() => fn(...args), delay);
                };
            },
            
            formatSize(bytes) {
                if (!bytes || bytes === '?') return '?';
                const num = parseInt(bytes, 10);
                if (isNaN(num)) return bytes;
                if (num < 1024) return num + ' B';
                if (num < 1024 * 1024) return (num / 1024).toFixed(1) + ' KB';
                return (num / (1024 * 1024)).toFixed(1) + ' MB';
            },

            formatDuration(seconds) {
                if (isNaN(seconds) || !isFinite(seconds)) return '0:00';
                const mins = Math.floor(seconds / 60);
                const secs = Math.floor(seconds % 60);
                return mins + ':' + secs.toString().padStart(2, '0');
            },

            getAudioIcon(type) {
                if (type.includes('wav')) return '🎵';
                if (type.includes('ogg')) return '🎶';
                return '🎧'; // mp3 and others
            }
        };

        // ================== MAIN APP ==================
        const app = {
            key: '',
            items: [],
            current: null,

            // ================== AUTH ==================
            login() {
                const key = document.getElementById('apiKeyInput').value.trim();
                if (!key) {
                    this.showAlert('API key is required', 'error');
                    return;
                }
                this.key = key;
                localStorage.setItem('jsonbin_key', key);
                
                this.loadItems().then(ok => {
                    if (ok) {
                        document.getElementById('authSection').classList.add('hidden');
                        document.getElementById('mainContent').classList.remove('hidden');
                        document.getElementById('logoutBtn').classList.remove('hidden');
                    }
                });
            },

            logout() {
                this.key = '';
                this.items = [];
                this.current = null;
                localStorage.removeItem('jsonbin_key');
                document.getElementById('authSection').classList.remove('hidden');
                document.getElementById('mainContent').classList.add('hidden');
                document.getElementById('logoutBtn').classList.add('hidden');
                document.getElementById('apiKeyInput').value = '';
            },

            // ================== LIST ==================
            async loadItems() {
                try {
                    document.getElementById('itemsList').innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
                    
                    const res = await fetch(\`/?list&key=\${encodeURIComponent(this.key)}\`);
                    if (!res.ok) {
                        const errText = await res.text();
                        throw new Error(res.status === 401 ? 'Invalid API key' : errText);
                    }
                    
                    const text = await res.text();
                    this.items = this.parseList(text);
                    this.renderList();
                    this.updateStats();
                    return true;
                } catch (e) {
                    this.showAlert(e.message, 'error');
                    document.getElementById('itemsList').innerHTML = '<div class="empty-state"><p>Failed to load items</p></div>';
                    return false;
                }
            },

            parseList(txt) {
                const lines = txt.split('\\n').filter(l => l.trim() && !l.includes('---'));
                return lines.slice(1).map(line => {
                    const parts = line.split(/\\s{2,}/);
                    return {
                        name: (parts[0] || '').trim(),
                        filename: (parts[1] || '').trim() || '-',
                        type: (parts[2] || '').trim() || 'application/octet-stream',
                        enc: (parts[3] || '').trim().toLowerCase() === 'yes',
                        size: (parts[4] || '').trim() || '?'
                    };
                }).filter(i => i.name);
            },

            handleSearch: utils.debounce(function() {
                app.renderList();
            }, 200),

            renderList() {
                const query = (document.getElementById('searchBox').value || '').toLowerCase();
                const filtered = this.items.filter(i => 
                    i.name.toLowerCase().includes(query) || 
                    i.filename.toLowerCase().includes(query)
                );
                
                if (filtered.length === 0) {
                    document.getElementById('itemsList').innerHTML = \`
                        <div class="empty-state" style="padding: 40px;">
                            <p>\${this.items.length === 0 ? 'No items yet' : 'No matches found'}</p>
                        </div>\`;
                    return;
                }

                document.getElementById('itemsList').innerHTML = filtered.map((item) => {
                    const isActive = this.current && this.current.name === item.name;
                    const badgeType = this.getBadgeType(item.type);
                    const escapedName = utils.escapeHtml(item.name);
                    const escapedFilename = utils.escapeHtml(item.filename);
                    
                    return \`
                        <div class="item \${isActive ? 'active' : ''}" 
                             tabindex="0"
                             data-name="\${encodeURIComponent(item.name)}">
                            <div class="item-header">
                                <span class="item-name" title="\${escapedName}">\${escapedName}</span>
                                \${item.enc ? '<span class="badge badge-lock">🔒</span>' : ''}
                            </div>
                            <div class="item-meta">
                                <span class="badge badge-\${badgeType}">\${badgeType.toUpperCase()}</span>
                                <span title="\${escapedFilename}">\${escapedFilename.length > 15 ? escapedFilename.slice(0,12) + '...' : escapedFilename}</span>
                                <span>\${utils.formatSize(item.size)}</span>
                            </div>
                        </div>\`;
                }).join('');
            },

            getBadgeType(type) {
                if (!type) return 'raw';
                if (type.includes('json')) return 'json';
                if (type.includes('markdown')) return 'md';
                if (type.startsWith('image/')) return 'img';
                if (type.startsWith('audio/')) return 'audio';
                if (type.startsWith('video/')) return 'video';
                return 'raw';
            },

            updateStats() {
                document.getElementById('stTotal').innerText = this.items.length;
                document.getElementById('stJson').innerText = this.items.filter(i => i.type.includes('json')).length;
                document.getElementById('stEnc').innerText = this.items.filter(i => i.enc).length;
            },

            // ================== OPEN/VIEW ==================
            openByName(encodedName) {
                const name = decodeURIComponent(encodedName);
                const item = this.items.find(i => i.name === name);
                if (item) {
                    this.open(item);
                } else {
                    this.showAlert('Item not found: ' + name, 'error');
                }
            },

            async open(item, decryptKey = null) {
                if (!item || !item.name) return;
                
                this.current = { ...item, decryptKey };
                this.renderList();
                
                document.getElementById('editorHeader').classList.remove('hidden');
                document.getElementById('typeSelector').parentElement.classList.remove('hidden');
                
                const titleEl = document.getElementById('editorTitle');
                titleEl.innerText = item.name;
                titleEl.title = item.name;
                
                document.getElementById('editorContainer').innerHTML = '<div class="loading"><div class="spinner"></div>Loading content...</div>';

                let url = \`\${item.name}?key=\${encodeURIComponent(this.key)}&s=raw\`;
                if (decryptKey) {
                    url += \`&c=\${encodeURIComponent(decryptKey)}\`;
                }

                try {
                    const res = await fetch(url);
                    
                    if (res.status === 403 && item.enc && !decryptKey) {
                        this.renderDecryptForm();
                        return;
                    }
                    
                    if (!res.ok) {
                        throw new Error(await res.text());
                    }

                    const contentType = res.headers.get('content-type') || 'application/octet-stream';
                    this.setSelectorValue(contentType);
                    
                    if (contentType.includes('json')) {
                        const txt = await res.text();
                        try {
                            const json = JSON.parse(txt);
                            this.renderJsonEditor(JSON.stringify(json, null, 2));
                        } catch (e) {
                            this.renderTextEditor(txt, false);
                        }
                    } else if (contentType.startsWith('image/')) {
                        const blob = await res.blob();
                        this.renderImageViewer(URL.createObjectURL(blob), contentType);
                    } else if (contentType.startsWith('audio/')) {
                        const blob = await res.blob();
                        this.renderAudioPlayer(URL.createObjectURL(blob), contentType);
                    } else if (contentType.startsWith('video/')) {
                        const blob = await res.blob();
                        this.renderVideoPlayer(URL.createObjectURL(blob), contentType);
                    } else if (contentType.includes('markdown') || contentType.startsWith('text/') || contentType.includes('xml')) {
                        const txt = await res.text();
                        this.renderTextEditor(txt, contentType.includes('markdown'));
                    } else {
                        this.renderBinaryViewer(contentType);
                    }
                } catch (e) {
                    document.getElementById('editorContainer').innerHTML = \`
                        <div class="alert alert-error">Error: \${utils.escapeHtml(e.message)}</div>\`;
                }
            },

            setSelectorValue(type) {
                const sel = document.getElementById('typeSelector');
                const exists = [...sel.options].some(o => o.value === type);
                if (!exists) {
                    const opt = document.createElement('option');
                    opt.value = type;
                    opt.text = type;
                    sel.add(opt);
                }
                sel.value = type;
            },

            renderDecryptForm() {
                document.getElementById('editorContainer').innerHTML = \`
                    <div style="max-width: 350px; margin: 40px auto;">
                        <div class="alert alert-warning">🔒 This file is encrypted</div>
                        <form onsubmit="event.preventDefault(); app.submitDecrypt();">
                            <div class="form-group">
                                <label>Decryption Key</label>
                                <input type="password" id="decKey" class="form-control" placeholder="Enter encryption key" autofocus>
                            </div>
                            <button type="submit" class="btn btn-primary" style="width: 100%;">Decrypt & View</button>
                        </form>
                    </div>\`;
            },

            submitDecrypt() {
                const key = document.getElementById('decKey').value;
                if (!key) {
                    this.showAlert('Please enter decryption key', 'error');
                    return;
                }
                this.open(this.current, key);
            },

            // ================== EDITORS ==================
            getActions() {
                const downloadUrl = \`\${this.current.name}?key=\${encodeURIComponent(this.key)}\${this.current.decryptKey ? '&c=' + encodeURIComponent(this.current.decryptKey) : ''}&dl=1\`;
                
                return \`
                    <div class="editor-actions">
                        <button class="btn btn-success" onclick="app.save()">💾 Save</button>
                        <button class="btn btn-outline" onclick="app.showRenameModal()">✏️ Rename</button>
                        <button class="btn btn-outline" onclick="app.showShareModal()">🔗 Share</button>
                        <button class="btn btn-danger" onclick="app.del()">🗑️ Delete</button>
                        <a href="\${utils.escapeHtml(downloadUrl)}" target="_blank" class="btn btn-secondary">⬇️ Download</a>
                    </div>\`;
            },

            renderJsonEditor(content) {
                document.getElementById('editorContainer').innerHTML = \`
                    \${this.getActions()}
                    <div class="form-group" style="flex: 1; display: flex; flex-direction: column;">
                        <textarea id="editContent" class="form-control" spellcheck="false" style="flex: 1;">\${utils.escapeHtml(content)}</textarea>
                    </div>\`;
            },

            renderTextEditor(content, isMd) {
                const tabs = isMd ? \`
                    <div class="tabs">
                        <div class="tab active" onclick="app.switchTab('edit')">Edit</div>
                        <div class="tab" onclick="app.switchTab('preview')">Preview</div>
                    </div>\` : '';
                    
                const preview = isMd ? \`<div id="mdPreview" class="md-preview hidden"></div>\` : '';
                
                document.getElementById('editorContainer').innerHTML = \`
                    \${this.getActions()}
                    \${tabs}
                    <div class="form-group" style="flex: 1; display: flex; flex-direction: column;">
                        <textarea id="editContent" class="form-control" spellcheck="false" style="flex: 1;">\${utils.escapeHtml(content)}</textarea>
                        \${preview}
                    </div>\`;
                    
                if (isMd && typeof marked !== 'undefined') {
                    document.getElementById('mdPreview').innerHTML = marked.parse(content);
                }
            },

            switchTab(mode) {
                const edit = document.getElementById('editContent');
                const preview = document.getElementById('mdPreview');
                const tabs = document.querySelectorAll('.tab');
                
                if (mode === 'edit') {
                    edit.classList.remove('hidden');
                    preview.classList.add('hidden');
                    tabs[0].classList.add('active');
                    tabs[1].classList.remove('active');
                } else {
                    if (typeof marked !== 'undefined') {
                        preview.innerHTML = marked.parse(edit.value);
                    }
                    edit.classList.add('hidden');
                    preview.classList.remove('hidden');
                    tabs[0].classList.remove('active');
                    tabs[1].classList.add('active');
                }
            },

            renderImageViewer(url, type) {
                document.getElementById('editorContainer').innerHTML = \`
                    \${this.getActions()}
                    <div style="text-align: center; background: #f0f0f0; padding: 20px; border-radius: 8px; flex: 1; display: flex; flex-direction: column; justify-content: center;">
                        <img src="\${url}" style="max-width: 100%; max-height: 60vh; object-fit: contain; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <p style="margin-top: 15px; color: #666;">\${utils.escapeHtml(type)}</p>
                    </div>\`;
                // Hide save button for images
                const saveBtn = document.querySelector('.editor-actions .btn-success');
                if (saveBtn) saveBtn.style.display = 'none';
            },

            renderAudioPlayer(url, type) {
                const icon = utils.getAudioIcon(type);
                const filename = this.current.filename || this.current.name.split('/').pop() || 'Audio';
                
                document.getElementById('editorContainer').innerHTML = \`
                    \${this.getActions()}
                    <div class="audio-container" style="flex: 1; display: flex; flex-direction: column; justify-content: center;">
                        <div class="audio-icon">\${icon}</div>
                        <h3 style="margin-bottom: 10px;">\${utils.escapeHtml(filename)}</h3>
                        <div class="audio-player">
                            <audio id="audioElement" controls preload="metadata">
                                <source src="\${url}" type="\${type}">
                                Your browser does not support the audio element.
                            </audio>
                        </div>
                        <div class="audio-info">
                            <span id="audioDuration">Duration: Loading...</span>
                            <span style="margin-left: 20px;">\${utils.escapeHtml(type)}</span>
                        </div>
                    </div>\`;
                
                // Hide save button for audio
                const saveBtn = document.querySelector('.editor-actions .btn-success');
                if (saveBtn) saveBtn.style.display = 'none';

                // Update duration when metadata is loaded
                const audio = document.getElementById('audioElement');
                if (audio) {
                    audio.addEventListener('loadedmetadata', () => {
                        const durationEl = document.getElementById('audioDuration');
                        if (durationEl) {
                            durationEl.textContent = 'Duration: ' + utils.formatDuration(audio.duration);
                        }
                    });
                    audio.addEventListener('error', () => {
                        const durationEl = document.getElementById('audioDuration');
                        if (durationEl) {
                            durationEl.textContent = 'Error loading audio';
                        }
                    });
                }
            },

            renderVideoPlayer(url, type) {
                const filename = this.current.filename || this.current.name.split('/').pop() || 'Video';
                
                document.getElementById('editorContainer').innerHTML = \`
                    \${this.getActions()}
                    <div style="text-align: center; background: #1a1a2e; padding: 20px; border-radius: 8px; flex: 1; display: flex; flex-direction: column; justify-content: center;">
                        <video id="videoElement" controls preload="metadata" style="max-width: 100%; max-height: 60vh; border-radius: 8px; margin: 0 auto;">
                            <source src="\${url}" type="\${type}">
                            Your browser does not support the video element.
                        </video>
                        <div style="margin-top: 15px; color: #aaa;">
                            <span>\${utils.escapeHtml(filename)}</span>
                            <span style="margin-left: 20px;">\${utils.escapeHtml(type)}</span>
                            <span id="videoDuration" style="margin-left: 20px;">Duration: Loading...</span>
                        </div>
                    </div>\`;
                
                // Hide save button for video
                const saveBtn = document.querySelector('.editor-actions .btn-success');
                if (saveBtn) saveBtn.style.display = 'none';

                // Update duration when metadata is loaded
                const video = document.getElementById('videoElement');
                if (video) {
                    video.addEventListener('loadedmetadata', () => {
                        const durationEl = document.getElementById('videoDuration');
                        if (durationEl) {
                            durationEl.textContent = 'Duration: ' + utils.formatDuration(video.duration);
                        }
                    });
                }
            },

            renderBinaryViewer(type) {
                document.getElementById('editorContainer').innerHTML = \`
                    \${this.getActions()}
                    <div style="text-align: center; padding: 40px; background: #f8f9fa; border-radius: 8px;">
                        <div style="font-size: 4rem; margin-bottom: 15px;">📦</div>
                        <h3 style="margin-bottom: 10px;">Binary File</h3>
                        <p style="color: #666; margin-bottom: 20px;">\${utils.escapeHtml(type)}</p>
                        <div class="form-group" style="max-width: 300px; margin: 0 auto;">
                            <label>Replace with new file</label>
                            <input type="file" id="replaceFile" class="form-control">
                        </div>
                        <button class="btn btn-success" style="margin-top: 15px;" onclick="app.uploadReplacement()">⬆️ Upload & Replace</button>
                    </div>\`;
                // Hide the main save button
                const saveBtn = document.querySelector('.editor-actions .btn-success');
                if (saveBtn) saveBtn.style.display = 'none';
            },

            // ================== SAVE ==================
            async save() {
                let content = document.getElementById('editContent')?.value;
                if (content === undefined) {
                    this.showAlert('Nothing to save', 'error');
                    return;
                }

                const type = document.getElementById('typeSelector').value;
                let url = \`\${this.current.name}?key=\${encodeURIComponent(this.key)}\`;
                
                if (this.current.decryptKey) {
                    url += \`&c=\${encodeURIComponent(this.current.decryptKey)}\`;
                }

                if (type.includes('json')) {
                    try {
                        let json = JSON.parse(content);
                        content = JSON.stringify(json,null);
                        document.getElementById('editContent').value = content;
                    } catch (e) {
                        this.showAlert('Invalid JSON: ' + e.message, 'error');
                        return;
                    }
                } else {
                    url += '&s=raw';
                }

                try {
                    console.log("Upload:",content )
                    const res = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': type },
                        body: content
                    });
                    
                    if (!res.ok) throw new Error(await res.text());
                    
                    this.showAlert('Saved successfully!', 'success');
                    this.loadItems();
                } catch (e) {
                    this.showAlert('Save failed: ' + e.message, 'error');
                }
            },

            async uploadReplacement() {
                const fileInput = document.getElementById('replaceFile');
                if (!fileInput || !fileInput.files[0]) {
                    this.showAlert('Please select a file', 'error');
                    return;
                }
                
                const file = fileInput.files[0];
                let url = \`\${this.current.name}?key=\${encodeURIComponent(this.key)}&s=raw\`;
                
                if (this.current.decryptKey) {
                    url += \`&c=\${encodeURIComponent(this.current.decryptKey)}\`;
                }

                try {
                    const res = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': file.type || 'application/octet-stream' },
                        body: file
                    });
                    
                    if (!res.ok) throw new Error(await res.text());
                    
                    this.showAlert('File replaced!', 'success');
                    this.open(this.current, this.current.decryptKey);
                } catch (e) {
                    this.showAlert('Upload failed: ' + e.message, 'error');
                }
            },

            // ================== TYPE CHANGE ==================
            async changeType(newType) {
                if (!this.current) return;
                
                try {
                    const url = \`\${this.current.name}?key=\${encodeURIComponent(this.key)}&set_type=\${encodeURIComponent(newType)}\`;
                    const res = await fetch(url, { method: 'POST' });
                    
                    if (!res.ok) throw new Error('Update failed');
                    
                    this.showAlert('Type updated to ' + newType, 'success');
                    await this.loadItems();
                    
                    // Update current item and reopen
                    const updated = this.items.find(i => i.name === this.current.name);
                    if (updated) {
                        this.open(updated, this.current.decryptKey);
                    }
                } catch (e) {
                    this.showAlert(e.message, 'error');
                }
            },

            // ================== RENAME ==================
            showRenameModal() {
                if (!this.current) return;
                document.getElementById('renamePath').value = this.current.name;
                document.getElementById('renameFilename').value = this.current.filename || '';
                document.getElementById('renameModal').classList.remove('hidden');
            },

            closeRenameModal() {
                document.getElementById('renameModal').classList.add('hidden');
            },

            async submitRename() {
                const newPath = document.getElementById('renamePath').value.trim();
                const newFilename = document.getElementById('renameFilename').value.trim();
                
                if (!newPath.startsWith('/')) {
                    this.showAlert('Path must start with /', 'error');
                    return;
                }
                
                const pathChanged = newPath !== this.current.name;
                const filenameChanged = newFilename !== this.current.filename;
                
                if (!pathChanged && !filenameChanged) {
                    this.showAlert('No changes made', 'warning');
                    this.closeRenameModal();
                    return;
                }

                try {
                    let url = \`\${this.current.name}?key=\${encodeURIComponent(this.key)}\`;
                    if (filenameChanged) url += \`&filename=\${encodeURIComponent(newFilename)}\`;
                    if (pathChanged) url += \`&rename_to=\${encodeURIComponent(newPath)}\`;

                    let res = await fetch(url, { method: 'POST' });
                    
                    if (res.status === 409) {
                        if (confirm('Destination already exists. Overwrite?')) {
                            res = await fetch(url + '&force=true', { method: 'POST' });
                        } else {
                            return;
                        }
                    }
                    
                    if (!res.ok) {
                        throw new Error(await res.text());
                    }

                    this.showAlert('Renamed successfully!', 'success');
                    this.closeRenameModal();
                    await this.loadItems();
                    
                    const finalPath = pathChanged ? newPath : this.current.name;
                    const updated = this.items.find(i => i.name === finalPath);
                    if (updated) {
                        this.open(updated, this.current.decryptKey);
                    }
                } catch (e) {
                    this.showAlert('Rename failed: ' + e.message, 'error');
                }
            },

            // ================== DELETE ==================
            async del() {
                if (!this.current) return;
                if (!confirm(\`Delete "\${this.current.name}"? This cannot be undone.\`)) return;
                
                try {
                    const res = await fetch(\`\${this.current.name}?key=\${encodeURIComponent(this.key)}\`, {
                        method: 'DELETE'
                    });
                    
                    if (!res.ok) throw new Error(await res.text());
                    
                    this.showAlert('Deleted successfully', 'success');
                    this.current = null;
                    this.loadItems();
                    
                    document.getElementById('editorContainer').innerHTML = \`
                        <div class="empty-state">
                            <div class="empty-state-icon">🗑️</div>
                            <p>Item deleted</p>
                        </div>\`;
                    document.getElementById('editorHeader').classList.add('hidden');
                } catch (e) {
                    this.showAlert('Delete failed: ' + e.message, 'error');
                }
            },

            // ================== NEW ITEM ==================
            newItem() {
                this.current = null;
                document.getElementById('editorHeader').classList.remove('hidden');
                document.getElementById('typeSelector').parentElement.classList.add('hidden');
                document.getElementById('editorTitle').innerText = 'New Item';
                
                document.getElementById('editorContainer').innerHTML = \`
                    <form onsubmit="event.preventDefault(); app.create();">
                        <div class="form-group">
                            <label>Path *</label>
                            <input type="text" id="newPath" class="form-control" placeholder="/path/to/file.json" required>
                        </div>
                        
                        <div class="form-group">
                            <label>Content Type</label>
                            <div style="display: flex; gap: 20px; margin-top: 5px;">
                                <label style="cursor: pointer; display: flex; align-items: center; gap: 6px;">
                                    <input type="radio" name="newMode" value="text" checked onchange="app.toggleNewMode()">
                                    Text / JSON
                                </label>
                                <label style="cursor: pointer; display: flex; align-items: center; gap: 6px;">
                                    <input type="radio" name="newMode" value="file" onchange="app.toggleNewMode()">
                                    File Upload
                                </label>
                            </div>
                        </div>
                        
                        <div id="grpText" class="form-group">
                            <label>Content</label>
                            <textarea id="newContent" class="form-control" placeholder='{"key": "value"}'></textarea>
                        </div>
                        
                        <div id="grpFile" class="form-group hidden">
                            <label>Select File</label>
                            <input type="file" id="newFile" class="form-control" onchange="app.suggestPath(this)" accept="*/*">
                            <small style="color: #666; margin-top: 5px; display: block;">
                                Supports: JSON, Text, Images, Audio (MP3, WAV, OGG), Video, and more
                            </small>
                        </div>
                        
                        <div class="form-group">
                            <label>Filename (for downloads)</label>
                            <input type="text" id="newFilename" class="form-control" placeholder="Optional display name">
                        </div>
                        
                        <div class="form-group">
                            <label>Encryption Key (optional)</label>
                            <input type="password" id="newKey" class="form-control" placeholder="Leave empty for no encryption">
                        </div>
                        
                        <button type="submit" class="btn btn-success" style="width: 100%;">Create Item</button>
                    </form>\`;
            },

            toggleNewMode() {
                const isFile = document.querySelector('input[name="newMode"][value="file"]').checked;
                document.getElementById('grpText').classList.toggle('hidden', isFile);
                document.getElementById('grpFile').classList.toggle('hidden', !isFile);
            },

            suggestPath(input) {
                const pathInput = document.getElementById('newPath');
                const filenameInput = document.getElementById('newFilename');
                if (input.files[0]) {
                    if (!pathInput.value) pathInput.value = '/' + input.files[0].name;
                    if (!filenameInput.value) filenameInput.value = input.files[0].name;
                }
            },

            async create() {
                const path = document.getElementById('newPath').value.trim();
                if (!path.startsWith('/')) {
                    this.showAlert('Path must start with /', 'error');
                    return;
                }
                
                const key = document.getElementById('newKey').value;
                const filename = document.getElementById('newFilename').value.trim();
                const isFile = document.querySelector('input[name="newMode"][value="file"]').checked;
                
                let url = \`\${path}?key=\${encodeURIComponent(this.key)}\`;
                if (filename) url += \`&filename=\${encodeURIComponent(filename)}\`;
                if (key) url += \`&c=\${encodeURIComponent(key)}\`;
                
                let body, contentType;
                
                if (isFile) {
                    const fileInput = document.getElementById('newFile');
                    if (!fileInput || !fileInput.files[0]) {
                        this.showAlert('Please select a file', 'error');
                        return;
                    }
                    body = fileInput.files[0];
                    contentType = body.type || 'application/octet-stream';
                    url += '&s=raw';
                } else {
                    body = document.getElementById('newContent').value;
                    try {
                        JSON.parse(body);
                        contentType = 'application/json';
                    } catch (e) {
                        contentType = 'text/plain';
                        url += '&s=raw';
                    }
                }

                try {
                    const res = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': contentType },
                        body
                    });
                    
                    if (!res.ok) throw new Error(await res.text());
                    
                    this.showAlert('Created successfully!', 'success');
                    await this.loadItems();
                    
                    const newItem = this.items.find(i => i.name === path);
                    if (newItem) {
                        this.open(newItem, key || null);
                    }
                } catch (e) {
                    this.showAlert('Create failed: ' + e.message, 'error');
                }
            },

            // ================== SHARE ==================
            showShareModal() {
                if (!this.current) return;
                document.getElementById('shareModal').classList.remove('hidden');
                document.getElementById('shareResultGroup').classList.add('hidden');
                document.getElementById('btnGenShare').style.display = 'inline-flex';
                document.getElementById('shareExpiry').value = '-1';
                document.getElementById('sharedCode').value = '';
            },

            closeShareModal() {
                document.getElementById('shareModal').classList.add('hidden');
            },

            closeModalOnBackdrop(event) {
                if (event.target.classList.contains('modal-overlay')) {
                    event.target.classList.add('hidden');
                }
            },

            async generateShareLink() {
                const expiry = document.getElementById('shareExpiry').value;
                const code = document.getElementById('sharedCode').value;

                let url = \`\${this.current.name}?key=\${encodeURIComponent(this.key)}&download=1&expires=\${expiry}&code=\${encodeURIComponent(code)}&json_response=1\`;
                
                if (this.current.decryptKey) {
                    url += \`&c=\${encodeURIComponent(this.current.decryptKey)}\`;
                }

                try {
                    const res = await fetch(url);
                    if (!res.ok) throw new Error(await res.text());
                    
                    const data = await res.json();
                    const shareUrl = window.location.origin + data.url;
                    
                    document.getElementById('shareUrl').value = shareUrl;
                    document.getElementById('shareResultGroup').classList.remove('hidden');
                    document.getElementById('btnGenShare').style.display = 'none';
                } catch (e) {
                    this.showAlert('Error generating link: ' + e.message, 'error');
                }
            },

            copyShareUrl() {
                const input = document.getElementById('shareUrl');
                input.select();
                input.setSelectionRange(0, 99999); // For mobile
                
                try {
                    navigator.clipboard.writeText(input.value);
                    this.showAlert('Copied to clipboard!', 'success');
                } catch (e) {
                    document.execCommand('copy');
                    this.showAlert('Copied to clipboard!', 'success');
                }
            },

            // ================== ALERTS ==================
            showAlert(msg, type) {
                const icons = { success: '✓', error: '✕', warning: '⚠' };
                const el = document.getElementById('alertArea');
                el.innerHTML = \`<div class="alert alert-\${type}">\${icons[type] || ''} \${utils.escapeHtml(msg)}</div>\`;
                setTimeout(() => el.innerHTML = '', 4000);
            }
        };

        // ================== KEYBOARD SHORTCUTS ==================
        document.addEventListener('keydown', (e) => {
            // Escape to close modals
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal-overlay:not(.hidden)').forEach(m => m.classList.add('hidden'));
            }
            // Ctrl/Cmd + S to save
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                if (app.current && document.getElementById('editContent')) {
                    e.preventDefault();
                    app.save();
                }
            }
            // Space to play/pause audio/video
            if (e.key === ' ' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
                const audio = document.getElementById('audioElement');
                const video = document.getElementById('videoElement');
                const media = audio || video;
                if (media) {
                    e.preventDefault();
                    if (media.paused) {
                        media.play();
                    } else {
                        media.pause();
                    }
                }
            }
        });

        // ================== EVENT DELEGATION FOR ITEMS LIST ==================
        document.getElementById('itemsList').addEventListener('click', (e) => {
            const itemEl = e.target.closest('.item');
            if (itemEl && itemEl.dataset.name) {
                app.openByName(itemEl.dataset.name);
            }
        });

        document.getElementById('itemsList').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const itemEl = e.target.closest('.item');
                if (itemEl && itemEl.dataset.name) {
                    app.openByName(itemEl.dataset.name);
                }
            }
        });

        // ================== INIT ==================
        if (localStorage.getItem('jsonbin_key')) {
            document.getElementById('apiKeyInput').value = localStorage.getItem('jsonbin_key');
            app.login();
        }
    <\/script>
</body>
</html>`;
}
