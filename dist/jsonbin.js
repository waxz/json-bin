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
        if (originPathname === '/_admin' || originPathname === '/_admin/') {
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
            return await handleTokenDownload(pathname, env, crypt);
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
            return await handleList(env);
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

async function handleTokenDownload(pathname, env, crypt) {
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
        await env.JSONBIN.delete(tokenPath).catch(() => { });
        return jsonError("Token expired", 404);
    }

    const result = await env.JSONBIN.getWithMetadata(tokenObj.target, "arrayBuffer");
    if (!result?.value) return jsonError(`${tokenObj.target} Not Found`, 404);

    let value = result.value;
    const meta = result.metadata || {};
    const filetype = tokenObj.filetype || meta.filetype || "application/octet-stream";
    const filename = tokenObj.filename || meta.filename || tokenObj.target.split("/").pop() || "file";

    if (tokenObj.crypt) {
        const ciphertext = new TextDecoder().decode(value);
        const decryptedBase64 = await decryptData(ciphertext, tokenObj.crypt);
        value = base64ToUint8Array(decryptedBase64).buffer;
    }

    return new Response(value, {
        headers: {
            "Content-Type": filetype,
            "Content-Disposition": `attachment; filename="${sanitizeFilename(filename)}"; filename*=UTF-8''${encodeURIComponent(sanitizeFilename(filename))}`,
            "Content-Length": String(value.byteLength || 0),
            "Cache-Control": "no-store",
        }
    });
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

async function handleList(env) {
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
    const header = `${"name".padEnd(20)}  ${"filename".padEnd(20)}  ${"filetype".padEnd(20)}  ${"encrypted".padEnd(10)}\n${"-".repeat(80)}\n`;
    const rows = items.map(r => `${r.name.padEnd(20)}  ${r.filename.padEnd(20)}  ${r.filetype.padEnd(25)}  ${r.encrypted.padEnd(10)}  ${r.size}`).join("\n");
    return new Response(header + rows + "\n", { headers: { "Content-Type": "text/plain" } });
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
        newMeta.filename = newPath.split('/').pop();

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

        await env.JSONBIN.put(pathname, dataToStore, { metadata: { crypt: !!crypt, filetype: "application/json" } });
        return jsonOK({ ok: true, type: "json", encrypted: !!crypt });
    }

    // Store as raw binary
    if (storetype === "raw") {
        const buffer = await request.arrayBuffer();
        let toStore = buffer;
        
        let filename = pathname.split("/").pop() || "file";
        if (!filename.includes(".")) {
            const ext = contentType.split("/")[1] || "bin";
            filename = `${filename}.${ext}`;
        }

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
    const token = generateToken();
    const expiresSec = parseInt(searchParams.get("expires") || "60", 10) || 60;

    const tokenObj = {
        target: pathname,
        expires: Date.now() + expiresSec * 1000,
        filename: filenameForToken,
        filetype,
        crypt
    };

    await env.JSONBIN.put(`/__token/${token}`, JSON.stringify(tokenObj));

    // ✅ MODIFICATION: Support returning JSON info instead of 302 redirect for Admin Panel
    if (searchParams.has("json_response")) {
        const urlObj = new URL(env.BASE_URL || "http://localhost"); // Fallback
        return jsonOK({
            url: `/_download/${token}/${encodeURIComponent(filenameForToken)}`,
            token: token,
            expires_at: new Date(tokenObj.expires).toISOString(),
            filename: filenameForToken
        });
    }

    return new Response(null, {
        status: 302,
        headers: {
            Location: `/_download/${token}/${encodeURIComponent(filenameForToken)}`,
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
    <title>JSONBIN Admin Panel</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root { --primary: #667eea; --primary-dark: #5568d3; --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, system-ui, sans-serif; background: var(--bg-gradient); min-height: 100vh; padding: 20px; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; }
        .hidden { display: none !important; }
        
        /* Panels */
        .panel { background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { margin-bottom: 20px; color: white; text-shadow: 0 2px 4px rgba(0,0,0,0.2); }
        .auth-section { max-width: 400px; margin: 40px auto; text-align: center; }
        
        /* Grid */
        .content-grid { display: grid; grid-template-columns: 350px 1fr; gap: 20px; height: calc(100vh - 180px); }
        @media (max-width: 968px) { .content-grid { grid-template-columns: 1fr; height: auto; } }
        
        /* List */
        .list-panel { display: flex; flex-direction: column; height: 100%; }
        .items-list { flex: 1; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px; margin-top: 10px; }
        .item { padding: 12px; border-bottom: 1px solid #f0f0f0; cursor: pointer; transition: 0.2s; }
        .item:hover { background: #f8f9fa; }
        .item.active { background: #eff6ff; border-left: 4px solid var(--primary); }
        .item-header { display: flex; justify-content: space-between; align-items: center; }
        .item-name { font-weight: 500; font-size: 14px; word-break: break-all; }
        .item-meta { font-size: 11px; color: #666; margin-top: 4px; display: flex; gap: 8px; align-items: center;}
        
        /* Badges */
        .badge { padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
        .badge-json { background: #dbeafe; color: #1e40af; }
        .badge-md { background: #fce7f3; color: #9d174d; }
        .badge-img { background: #dcfce7; color: #166534; }
        .badge-raw { background: #f3f4f6; color: #374151; }
        .badge-lock { background: #fef3c7; color: #92400e; }
        
        /* Forms */
        .form-group { margin-bottom: 15px; }
        .form-control { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
        textarea.form-control { font-family: 'Monaco', monospace; min-height: 400px; resize: vertical; }
        .md-preview { border: 1px solid #ddd; border-radius: 6px; padding: 20px; min-height: 400px; background: #fff; overflow-y: auto; }
        
        /* Toolbar */
        .editor-header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 15px; border-bottom: 1px solid #eee; margin-bottom: 15px; }
        .type-select { padding: 4px 8px; border-radius: 4px; border: 1px solid #ddd; font-size: 12px; background: #f8f9fa; cursor: pointer; }
        
        /* Buttons */
        .btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; transition: 0.2s; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-success { background: #10b981; color: white; }
        .btn-danger { background: #ef4444; color: white; }
        .btn-secondary { background: #6b7280; color: white; }
        .editor-actions { margin-top: 20px; display: flex; gap: 10px; border-top: 1px solid #eee; padding-top: 20px; flex-wrap: wrap; }
        
        /* Misc */
        .tabs { display: flex; gap: 2px; margin-bottom: -1px; }
        .tab { padding: 8px 16px; cursor: pointer; border: 1px solid transparent; border-radius: 6px 6px 0 0; background: #f3f4f6; color: #666; }
        .tab.active { background: white; border-color: #ddd; color: var(--primary); border-bottom: 1px solid white; font-weight: 600; }
        .stats { display: flex; gap: 10px; margin-bottom: 10px; }
        .stat-card { background: #f8f9fa; padding: 10px; border-radius: 8px; flex: 1; text-align: center; }
        .stat-val { font-size: 1.2rem; font-weight: bold; color: var(--primary); }
        .stat-lbl { font-size: 0.75rem; color: #666; }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1000; }
        .modal { background: white; padding: 24px; border-radius: 12px; width: 400px; max-width: 90%; }
        .alert { padding: 10px; border-radius: 6px; margin-bottom: 15px; font-size: 0.9rem; }
        .alert-error { background: #fee2e2; color: #991b1b; }
        .alert-success { background: #d1fae5; color: #065f46; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>🗄️ JSONBIN Admin</h1></div>
        
        <div id="authSection" class="panel auth-section">
            <h2>Authentication</h2>
            <div class="form-group" style="margin-top: 15px;">
                <input type="password" id="apiKeyInput" class="form-control" placeholder="Enter API Key">
            </div>
            <button class="btn btn-primary" style="width: 100%;" onclick="app.login()">Connect</button>
        </div>
        
        <div id="mainContent" class="hidden">
            <div class="content-grid">
                <div class="panel list-panel">
                    <div class="stats">
                        <div class="stat-card"><div class="stat-val" id="stTotal">0</div><div class="stat-lbl">Items</div></div>
                        <div class="stat-card"><div class="stat-val" id="stJson">0</div><div class="stat-lbl">JSON</div></div>
                        <div class="stat-card"><div class="stat-val" id="stEnc">0</div><div class="stat-lbl">Locked</div></div>
                    </div>
                    <div style="display:flex; gap:5px; margin-bottom:10px">
                        <button class="btn" style="flex:1" onclick="app.newItem()">+ New</button>
                        <button class="btn btn-secondary" style="flex:1" onclick="app.loadItems()">↻ Refresh</button>
                    </div>
                    <input type="text" id="searchBox" class="form-control" placeholder="Search..." oninput="app.renderList()">
                    <div id="itemsList" class="items-list"></div>
                </div>
                
                <div class="panel" style="display: flex; flex-direction: column;">
                    <div id="editorHeader" class="editor-header hidden">
                        <h2 id="editorTitle">Select Item</h2>
                        <select id="typeSelector" class="type-select" onchange="app.changeType(this.value)">
                            <option value="application/json">JSON</option>
                            <option value="text/plain">Text</option>
                            <option value="text/markdown">Markdown</option>
                            <option value="image/png">Image (PNG)</option>
                            <option value="image/jpeg">Image (JPEG)</option>
                            <option value="application/octet-stream">Binary</option>
                        </select>
                    </div>
                    <div id="alertArea"></div>
                    <div id="editorContainer" style="flex: 1; display: flex; flex-direction: column;">
                        <div style="text-align:center; padding:40px; color:#999">Select an item to view or edit</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Share Modal -->
    <div id="shareModal" class="hidden modal-overlay">
        <div class="modal">
            <h3>Share Public Link</h3>
            <div class="form-group">
                <label>Expires In</label>
                <select id="shareExpiry" class="form-control">
                    <option value="3600">1 Hour</option>
                    <option value="86400">1 Day</option>
                    <option value="604800">1 Week</option>
                </select>
            </div>
            <div class="form-group hidden" id="shareResultGroup">
                <input type="text" id="shareUrl" class="form-control" readonly>
            </div>
            <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:20px">
                <button class="btn btn-secondary" onclick="document.getElementById('shareModal').classList.add('hidden')">Close</button>
                <button class="btn btn-primary" id="btnGenShare" onclick="app.generateShareLink()">Generate</button>
            </div>
        </div>
    </div>

    <script>
        const app = {
            key: '', items: [], current: null,

            login() {
                const key = document.getElementById('apiKeyInput').value;
                if(!key) return alert("Key required");
                this.key = key;
                localStorage.setItem('jsonbin_key', key);
                this.loadItems().then(ok => {
                    if(ok) {
                        document.getElementById('authSection').classList.add('hidden');
                        document.getElementById('mainContent').classList.remove('hidden');
                    }
                });
            },

            async loadItems() {
                try {
                    const res = await fetch(\`/?list&key=\${this.key}\`);
                    if(!res.ok) throw new Error("Auth failed");
                    this.items = this.parseList(await res.text());
                    this.renderList();
                    this.updateStats();
                    return true;
                } catch(e) { alert(e.message); return false; }
            },

            parseList(txt) {
                return txt.split('\\n').filter(l => l.trim() && !l.includes('---')).slice(1).map(l => {
                    const p = l.split(/\\s{2,}/);
                    return { name: p[0]?.trim(), filename: p[1]?.trim(), type: p[2]?.trim(), enc: p[3]?.trim() === 'yes', size: p[4]?.trim() };
                }).filter(i => i.name);
            },

            renderList() {
                const q = document.getElementById('searchBox').value.toLowerCase();
                document.getElementById('itemsList').innerHTML = this.items.filter(i => i.name.toLowerCase().includes(q)).map(i => {
                    let badge = i.type.includes('json') ? 'json' : i.type.includes('image') ? 'img' : i.type.includes('markdown') ? 'md' : 'raw';
                    return \`<div class="item \${this.current?.name === i.name ? 'active' : ''}" onclick="app.open('\${i.name}', \${i.enc})">
                        <div class="item-header"><span class="item-name">\${i.name}</span>\${i.enc?'<span class="badge badge-lock">LOCK</span>':''}</div>
                        <div class="item-meta"><span class="badge badge-\${badge}">\${badge}</span><span>\${i.size}</span></div>
                    </div>\`;
                }).join('');
            },

            updateStats() {
                document.getElementById('stTotal').innerText = this.items.length;
                document.getElementById('stJson').innerText = this.items.filter(i => i.type.includes('json')).length;
                document.getElementById('stEnc').innerText = this.items.filter(i => i.enc).length;
            },

            async open(name, isEnc, key = null) {
                this.current = { name, isEnc, key };
                this.renderList();
                
                document.getElementById('editorHeader').classList.remove('hidden');
                document.getElementById('typeSelector').parentNode.classList.remove('hidden'); 
                document.getElementById('editorTitle').innerText = name;
                document.getElementById('editorContainer').innerHTML = 'Loading...';

                let url = \`\${name}?key=\${this.key}\`;
                if(key) url += \`&c=\${encodeURIComponent(key)}\`;
                
                url += '&s=raw';

                try {
                    const res = await fetch(url);
                    if(res.status === 403 && isEnc && !key) return this.renderDecryptForm(name);
                    if(!res.ok) throw new Error(await res.text());

                    const type = res.headers.get('content-type') || 'application/octet-stream';
                    this.setSelectorValue(type);
                    
                    if(type.includes('json')) {
                        const txt = await res.text();
                        try {
                            const json = JSON.parse(txt);
                            this.renderJsonEditor(JSON.stringify(json, null, 2));
                        } catch(e) { this.renderTextEditor(txt, false); }
                    } else if(type.startsWith('image/')) {
                        const blob = await res.blob();
                        this.renderImageViewer(URL.createObjectURL(blob), type);
                    } else if(type.includes('markdown') || type.startsWith('text/') || type.includes('xml')) {
                        this.renderTextEditor(await res.text(), type.includes('markdown'));
                    } else {
                        this.renderBinaryViewer(type);
                    }
                } catch(e) { document.getElementById('editorContainer').innerHTML = \`<div class="alert alert-error">\${e.message}</div>\`; }
            },

            setSelectorValue(type) {
                const sel = document.getElementById('typeSelector');
                if(![...sel.options].some(o => o.value === type)) {
                    const opt = document.createElement('option');
                    opt.value = type;
                    opt.text = type;
                    sel.add(opt);
                }
                sel.value = type;
            },

            async changeType(newType) {
                if(!this.current) return;
                try {
                    const url = \`\${this.current.name}?key=\${this.key}&set_type=\${newType}\`;
                    const res = await fetch(url, { method: 'POST' });
                    if(!res.ok) throw new Error("Update failed");
                    this.showAlert("Type updated to " + newType, "success");
                    await this.loadItems(); 
                    this.open(this.current.name, this.current.isEnc, this.current.key);
                } catch(e) { this.showAlert(e.message, "error"); }
            },

            async rename() {
                if(!this.current) return;
                const newName = prompt("Enter new path:", this.current.name);
                if(!newName || newName === this.current.name) return;
                if(!newName.startsWith('/')) return alert("Path must start with /");

                try {
                    const url = \`\${this.current.name}?key=\${this.key}&rename_to=\${encodeURIComponent(newName)}\`;
                    const res = await fetch(url, { method: 'POST' });
                    
                    if(res.status === 409) {
                        if(confirm("Destination exists. Overwrite?")) {
                            await fetch(url + "&force=true", { method: 'POST' });
                        } else return;
                    } else if(!res.ok) throw new Error(await res.text());

                    this.showAlert("Renamed successfully!", "success");
                    await this.loadItems();
                    this.open(newName, this.current.isEnc, this.current.key);
                } catch(e) { this.showAlert("Rename failed: " + e.message, "error"); }
            },

            renderDecryptForm(name) {
                document.getElementById('editorContainer').innerHTML = \`
                    <div style="max-width:300px; margin: 40px auto;">
                        <div class="alert alert-error">🔒 Encrypted File</div>
                        <input type="password" id="decKey" class="form-control" placeholder="Enter Key">
                        <button class="btn btn-primary" style="margin-top:10px; width:100%" 
                            onclick="app.open('\${name}', true, document.getElementById('decKey').value)">Decrypt</button>
                    </div>\`;
            },

            getActions() {
                return \`<div class="editor-actions">
                    <button class="btn btn-success" onclick="app.save()">💾 Save</button>
                    <button class="btn btn-secondary" onclick="app.rename()">✏️ Rename</button>
                    <button class="btn btn-primary" onclick="app.showShareModal()">🔗 Share</button>
                    <button class="btn btn-danger" onclick="app.del()">🗑️ Delete</button>
                    <a href="\${this.current.name}?key=\${this.key}\${this.current.key ? '&c='+this.current.key : ''}&dl=1" target="_blank" class="btn btn-secondary">⬇️ DL</a>
                </div>\`;
            },

            renderJsonEditor(content) {
                document.getElementById('editorContainer').innerHTML = \`<div class="form-group" style="flex:1; display:flex; flex-direction:column;">
                    <textarea id="editContent" class="form-control" spellcheck="false" style="flex:1;">\${content}</textarea>
                </div>\${this.getActions()}\`;
            },

            renderTextEditor(content, isMd) {
                const tabs = isMd ? \`<div class="tabs"><div class="tab active" onclick="app.tab('edit')">Edit</div><div class="tab" onclick="app.tab('view')">Preview</div></div>\` : '';
                const preview = isMd ? \`<div id="mdPreview" class="md-preview hidden"></div>\` : '';
                document.getElementById('editorContainer').innerHTML = \`\${tabs}
                    <div class="form-group" style="flex:1; display:flex; flex-direction:column;">
                        <textarea id="editContent" class="form-control" spellcheck="false" style="flex:1;">\${content}</textarea>
                        \${preview}
                    </div>\${this.getActions()}\`;
                if(isMd) document.getElementById('mdPreview').innerHTML = marked.parse(content);
            },

            tab(mode) {
                const edit = document.getElementById('editContent'), view = document.getElementById('mdPreview');
                const tabs = document.querySelectorAll('.tab');
                if(mode==='edit') { edit.classList.remove('hidden'); view.classList.add('hidden'); tabs[0].classList.add('active'); tabs[1].classList.remove('active'); }
                else { view.innerHTML = marked.parse(edit.value); edit.classList.add('hidden'); view.classList.remove('hidden'); tabs[0].classList.remove('active'); tabs[1].classList.add('active'); }
            },

            renderImageViewer(url, type) {
                document.getElementById('editorContainer').innerHTML = \`<div style="text-align:center; background:#f0f0f0; padding:20px; border-radius:8px;">
                    <img src="\${url}" style="max-width:100%; box-shadow:0 2px 5px rgba(0,0,0,0.1)">
                    <p style="margin-top:10px; color:#666">\${type}</p>
                </div>\${this.getActions()}\`;
                document.querySelector('.btn-success').style.display = 'none'; 
            },

            renderBinaryViewer(type) {
                document.getElementById('editorContainer').innerHTML = \`<div style="text-align:center; padding:40px; background:#f8f9fa; border-radius:8px;">
                    <div style="font-size:3rem;">💾</div><h3>Binary File</h3><p>\${type}</p>
                    <div class="form-group" style="margin-top:20px;"><input type="file" id="replaceFile" class="form-control"></div>
                    <button class="btn btn-success" onclick="app.uploadReplacement()">⬆️ Replace Content</button>
                </div>\${this.getActions()}\`;
                document.querySelector('.editor-actions .btn-success').style.display = 'none'; 
            },

            async save() {
                const content = document.getElementById('editContent').value;
                let url = \`\${this.current.name}?key=\${this.key}\`;
                if(this.current.key) url += \`&c=\${encodeURIComponent(this.current.key)}\`;
                
                if(document.getElementById('typeSelector').value.includes('json')) {
                    try { JSON.parse(content); } catch(e) { return alert("Invalid JSON"); }
                } else {
                    url += '&s=raw';
                }

                try {
                    await fetch(url, { method: 'POST', body: content });
                    this.showAlert("Saved!", "success");
                    this.loadItems();
                } catch(e) { this.showAlert(e.message, "error"); }
            },

            async uploadReplacement() {
                const file = document.getElementById('replaceFile').files[0];
                if(!file) return alert("No file selected");
                let url = \`\${this.current.name}?key=\${this.key}&s=raw\`;
                if(this.current.key) url += \`&c=\${encodeURIComponent(this.current.key)}\`;
                try {
                    await fetch(url, { method: 'POST', headers: {'Content-Type': file.type}, body: file });
                    this.showAlert("Replaced!", "success");
                    this.open(this.current.name, this.current.isEnc, this.current.key);
                } catch(e) { this.showAlert(e.message, "error"); }
            },

            newItem() {
                this.current = null;
                document.getElementById('editorHeader').classList.remove('hidden');
                document.getElementById('typeSelector').parentNode.classList.add('hidden'); 
                document.getElementById('editorTitle').innerText = "New Item";
                
                document.getElementById('editorContainer').innerHTML = \`
                    <div class="form-group"><label>Path (e.g. /files/doc.pdf)</label><input type="text" id="newPath" class="form-control" placeholder="/path/to/file"></div>
                    <div class="form-group"><div style="display:flex; gap:20px; margin-bottom:10px;">
                        <label style="cursor:pointer"><input type="radio" name="nMode" value="text" checked onchange="app.toggleNewMode()"> Text/JSON</label>
                        <label style="cursor:pointer"><input type="radio" name="nMode" value="file" onchange="app.toggleNewMode()"> File Upload</label>
                    </div></div>
                    <div id="grpText" class="form-group"><label>Content</label><textarea id="newContent" class="form-control" placeholder='{"key": "value"} or Plain text'></textarea></div>
                    <div id="grpFile" class="form-group hidden"><label>Select File</label><input type="file" id="newFile" class="form-control" onchange="app.suggestPath(this)"></div>
                    <div class="form-group"><label>Encryption Key (Optional)</label><input type="password" id="newKey" class="form-control"></div>
                    <button class="btn btn-success" onclick="app.create()">Create Item</button>\`;
            },
            
            toggleNewMode() {
                const isFile = document.querySelector('input[name="nMode"][value="file"]').checked;
                document.getElementById('grpText').classList.toggle('hidden', isFile);
                document.getElementById('grpFile').classList.toggle('hidden', !isFile);
            },
            
            suggestPath(input) {
                const pathIn = document.getElementById('newPath');
                if(input.files[0] && !pathIn.value) pathIn.value = '/' + input.files[0].name;
            },

            async create() {
                const path = document.getElementById('newPath').value;
                if(!path.startsWith('/')) return alert("Path must start with /");
                const key = document.getElementById('newKey').value;
                const isFile = document.querySelector('input[name="nMode"][value="file"]').checked;
                let url = \`\${path}?key=\${this.key}\`;
                if(key) url += \`&c=\${encodeURIComponent(key)}\`;
                
                let body, headers = {};
                if(isFile) {
                    const fileInput = document.getElementById('newFile');
                    if(!fileInput.files[0]) return alert("Select a file");
                    body = fileInput.files[0];
                    headers['Content-Type'] = body.type || 'application/octet-stream';
                    url += '&s=raw';
                } else {
                    body = document.getElementById('newContent').value;
                    try { JSON.parse(body); headers['Content-Type']='application/json'; } 
                    catch(e) { url += '&s=raw'; headers['Content-Type']='text/plain'; }
                }

                try {
                    await fetch(url, { method: 'POST', headers, body });
                    this.showAlert("Created!", "success");
                    this.loadItems();
                    this.open(path, !!key, key);
                } catch(e) { this.showAlert(e.message, "error"); }
            },

            async del() {
                if(!confirm("Delete?")) return;
                await fetch(\`\${this.current.name}?key=\${this.key}\`, { method: 'DELETE' });
                this.loadItems();
                document.getElementById('editorContainer').innerHTML = 'Deleted';
                document.getElementById('editorHeader').classList.add('hidden');
            },

            showShareModal() {
                document.getElementById('shareModal').classList.remove('hidden');
                document.getElementById('shareResultGroup').classList.add('hidden');
                document.getElementById('btnGenShare').style.display = 'block';
            },

            async generateShareLink() {
                const expiry = document.getElementById('shareExpiry').value;
                let url = \`\${this.current.name}?key=\${this.key}&download=1&expires=\${expiry}&json_response=1\`;
                if(this.current.key) url += \`&c=\${encodeURIComponent(this.current.key)}\`;
                try {
                    const res = await fetch(url);
                    const data = await res.json();
                    document.getElementById('shareUrl').value = window.location.origin + data.url;
                    document.getElementById('shareResultGroup').classList.remove('hidden');
                    document.getElementById('btnGenShare').style.display = 'none';
                } catch(e) { alert("Error generating link"); }
            },

            showAlert(msg, type) {
                const el = document.getElementById('alertArea');
                el.innerHTML = \`<div class="alert alert-\${type}">\${msg}</div>\`;
                setTimeout(()=>el.innerHTML='', 3000);
            }
        };

        if(localStorage.getItem('jsonbin_key')) {
            document.getElementById('apiKeyInput').value = localStorage.getItem('jsonbin_key');
            app.login();
        }
    </script>
</body>
</html>`;
}

