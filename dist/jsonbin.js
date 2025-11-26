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

/**
 * Main request handler for JSONBIN with forward proxy capability
 * 
 * Features:
 * - JSON and raw binary storage with optional encryption
 * - Public download links with expiring tokens
 * - Request forwarding/proxying (including WebDAV support)
 * - Query parameter field access
 * - URL redirection
 * 
 * @param {Request} request - Incoming request
 * @param {Object} env - Environment variables and bindings
 * @returns {Promise<Response>}
 */
export async function handleRequest(request, env) {
  // ============================================================
  // INITIALIZATION & VALIDATION
  // ============================================================

  const JSONBIN = env.JSONBIN;
  if (!JSONBIN) return jsonError("Missing env.JSONBIN", 500);

  const APIKEY = env.APIKEYSECRET;
  if (!APIKEY) return jsonError("Missing env.APIKEYSECRET", 500);

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return handleCORS(request, env);
  }

  try {
    // ============================================================
    // URL PARSING & PATH PROCESSING
    // ============================================================

    const urlObj = new URL(request.url);
    const originPathname = urlObj.pathname;
    const { searchParams } = urlObj;

    // Check if this is a forward/proxy request
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

    // Parse forward request format: /_forward/KEY/JSONBIN_PATH/urlsplit/TARGET_PATH
    if (isForward) {
      pathname = originPathname.slice(forwardPath.length);

      if (pathname.includes(urlSplitMarker)) {
        const [jsonbinPath, targetPath] = pathname.split(urlSplitMarker);
        pathname = jsonbinPath;
        forwardPathname = targetPath || "/";
      }
    }

    // Normalize pathname (remove trailing slash except for root)
    if (pathname.endsWith("/") && pathname.length > 1) {
      pathname = pathname.slice(0, -1);
    }

    // Extract common parameters
    const headers = request.headers;
    const crypt = searchParams.get("c");           // Encryption key
    const q = searchParams.get("q");               // Query field
    const sParam = searchParams.get("s");          // Storage type hint

    console.log(`[REQUEST] ${request.method} ${pathname}${isForward ? ` -> ${forwardPathname}` : ''}`);

    // ============================================================
    // PUBLIC TOKEN DOWNLOAD
    // ============================================================
    // Path: /_download/<token>/<filename>

    if (pathname.startsWith("/_download/")) {
      return await handleTokenDownload(pathname, env, crypt);
    }

    // ============================================================
    // FORWARD/PROXY HANDLER
    // ============================================================
    // Forwards requests to remote servers (supports WebDAV, REST APIs, etc.)

    if (isForward) {
      return await handleForward(pathname, forwardPathname, request, env, { crypt, q });
    }

    // ============================================================
    // AUTHENTICATION
    // ============================================================
    // Required for all non-public, non-forward operations

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

    // LIST: Show all stored items
    if (listFlag) {
      return await handleList(env);
    }

    // GET: Retrieve data
    if (request.method === "GET") {
      return await handleGet(pathname, env, { sParam, q, crypt, encbase64, redirect, isJson, searchParams });
    }

    // POST/PATCH: Store or update data
    if (request.method === "POST" || request.method === "PATCH") {
      return await handleStore(pathname, request, env, { sParam, q, crypt, encbase64, isJson });
    }

    // DELETE: Remove data
    if (request.method === "DELETE") {
      await env.JSONBIN.delete(pathname);
      console.log(`[DELETE] Deleted: ${pathname}`);
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

/**
 * Handle public download via expiring token
 */
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

  // Check expiration
  if (Date.now() > tokenObj.expires) {
    await env.JSONBIN.delete(tokenPath).catch(() => { });
    return jsonError("Token expired", 404);
  }

  // Fetch target file
  const result = await env.JSONBIN.getWithMetadata(tokenObj.target, "arrayBuffer");
  if (!result?.value) return jsonError(`${tokenObj.target} Not Found`, 404);

  let value = result.value;
  const meta = result.metadata || {};
  const filetype = tokenObj.filetype || meta.filetype || "application/octet-stream";
  const filename = tokenObj.filename || meta.filename || tokenObj.target.split("/").pop() || "file";

  // Decrypt if needed
  if (tokenObj.crypt) {
    const ciphertext = new TextDecoder().decode(value);
    const decryptedBase64 = await decryptData(ciphertext, tokenObj.crypt);
    value = base64ToUint8Array(decryptedBase64).buffer;
  }

  console.log(`[DOWNLOAD] Token: ${token}, File: ${filename}`);

  return new Response(value, {
    headers: {
      "Content-Type": filetype,
      "Content-Disposition": `attachment; filename="${sanitizeFilename(filename)}"; filename*=UTF-8''${encodeURIComponent(sanitizeFilename(filename))}`,
      "Content-Length": String(value.byteLength || 0),
      "Cache-Control": "no-store",
    }
  });
}

/**
 * Handle request forwarding/proxying
 */
async function handleForward(pathname, forwardPathname, request, env, { crypt, q }) {
  console.log(`[FORWARD] Config: ${pathname}, Target: ${forwardPathname}`);

  // Fetch forwarding configuration from JSONBIN
  const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
  if (!result?.value) {
    return jsonError(`Forward config not found: ${pathname}`, 404);
  }

  // Convert to text
  let text = bufferToText(result.value);

  // Decrypt if needed
  if (crypt) {
    text = await decryptAndDecode(text, crypt);
  }

  // Parse JSON config
  let config;
  try {
    config = JSON.parse(text);
  } catch (e) {
    return jsonError(`Invalid JSON in forward config: ${e.message}`, 500);
  }

  // Extract target URL from config
  let targetUrl = "";
  if (q && config.hasOwnProperty(q)) {
    targetUrl = config[q];
  } else if (config.url) {
    targetUrl = config.url;
  } else {
    return jsonError(`No target URL found in ${pathname}`, 404);
  }

  console.log(`[FORWARD] Proxying to: ${targetUrl}${forwardPathname}`);

  // Forward the request
  try {
    const forwardConfig = {
      targetUrl: targetUrl,
      forwardPathname: forwardPathname,
      allowedOrigins: env.ALLOWED_ORIGINS?.split(',') || ['*'],
      timeout: parseInt(env.TIMEOUT || '30000'),
      logRequests: env.LOG_REQUESTS === 'true',
    };

    // Check origin
    if (!isOriginAllowed(request, forwardConfig.allowedOrigins)) {
      return new Response('Origin not allowed', { status: 403 });
    }

    // Process and forward
    const processedRequest = await processRequest(request, forwardConfig);
    const response = await forwardRequest(processedRequest, forwardConfig);

    return addCORSHeaders(response, request, forwardConfig);

  } catch (error) {
    console.error('[FORWARD ERROR]', error.message);
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

/**
 * Handle LIST operation - show all stored items with metadata
 */
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
      encrypted: meta.crypt ? "yes" : "no"  // ✅ ADD THIS
    });
  }

  // Format as text table
  const header = `${"name".padEnd(20)}  ${"filename".padEnd(20)}  ${"filetype".padEnd(20)}  ${"encrypted".padEnd(10)}\n${"-".repeat(80)}\n`;
  const rows = items
    .map(r => `${r.name.padEnd(20)}  ${r.filename.padEnd(20)}  ${r.filetype.padEnd(25)}  ${r.encrypted.padEnd(10)}  ${r.size}`)
    .join("\n");

  return new Response(header + rows + "\n", {
    headers: { "Content-Type": "text/plain" }
  });
}

/**
 * Handle GET operation - retrieve data
 */
async function handleGet(pathname, env, { sParam, q, crypt, encbase64, redirect, isJson, searchParams }) {
  // Determine storage type
  let storeHint = sParam || "raw";
  if (q || isJson || redirect) storeHint = "json";
  const isRaw = storeHint === "raw";
  const wantDownload = searchParams.has("download") || searchParams.has("dl");

  console.log(`[GET] ${pathname} (type: ${storeHint}, download: ${wantDownload})`);

  // Try JSON first (unless explicitly raw)
  if (!isRaw) {
    const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
    if (!result?.value) return jsonError(`${pathname} Not Found`, 404);

    let text = bufferToText(result.value);
    const meta = result.metadata || {};
    
    // ✅ FIX: Check if encrypted and validate key is provided
    if (meta.crypt) {
      if (!crypt) {
        return jsonError(`${pathname} is encrypted, provide key with ?c=KEY`, 403);
      }
      text = await decryptAndDecode(text, crypt);
    }

    const json = JSON.parse(text);
    const disposition = `attachment; filename="${pathname.split("/").pop() || "data.json"}"`;

    // Handle download token
    if (wantDownload) {
      return createDownloadToken(pathname, "application/json", searchParams, env, crypt);
    }

    // Handle redirect
    if (redirect) {
      const url = (q && json[q]) || json.url;
      if (!url) return jsonError(`Redirect URL not found`, 404);

      console.log(`[REDIRECT] ${pathname} -> ${url}`);
      return new Response(null, {
        status: 302,
        headers: { "Location": url, "Cache-Control": "no-store" }
      });
    }

    // Return specific field or entire JSON
    if (q) {
      if (!json.hasOwnProperty(q)) return jsonError(`Field '${q}' not found`, 404);

      let fieldText = String(json[q]);
      if (encbase64) fieldText = base64ToUtf8(fieldText);

      return new Response(fieldText, {
        headers: {
          "Content-Type": "text/plain",
          "Content-Disposition": disposition
        }
      });
    }

    return new Response(text, {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": disposition
      }
    });
  }

  // Handle raw binary data
  const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
  if (!result?.value) return jsonError(`${pathname} Not Found`, 404);

  let value = result.value;
  const meta = result.metadata || {};
  const filetype = meta.filetype || "application/octet-stream";
  let filename = searchParams.get("filename") || meta.filename || pathname.split("/").pop() || "file";
  filename = sanitizeFilename(filename);

  // Add extension if missing
  if (!filename.includes(".")) {
    const ext = filetype.split("/")[1] || "bin";
    filename = `${filename}.${ext}`;
  }

  // ✅ FIX: Check metadata for encryption
  if (meta.crypt) {
    if (!crypt) {
      return jsonError(`${pathname} is encrypted, provide key with ?c=KEY`, 403);
    }
    const ciphertext = new TextDecoder().decode(value);
    const decryptedBase64 = await decryptData(ciphertext, crypt);
    value = base64ToUint8Array(decryptedBase64).buffer;
  }

  // Handle download token
  if (wantDownload) {
    return createDownloadToken(pathname, filetype, searchParams, env, crypt, filename);
  }

  return new Response(value, {
    headers: {
      "Content-Type": filetype,
      "Content-Disposition": `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
      "Content-Length": String(value.byteLength || 0),
      "Cache-Control": "no-store"
    }
  });
}

/**
 * Handle POST/PATCH operation - store or update data
 */
async function handleStore(pathname, request, env, { sParam, q, crypt, encbase64, isJson }) {
  const contentType = request.headers.get("content-type") || "";

  // Determine storage type
  let storetype = sParam;
  if (!storetype) {
    storetype = (q || isJson || contentType.includes("json")) ? "json" : "raw";
  }

  console.log(`[STORE] ${pathname} (type: ${storetype}, encrypted: ${!!crypt})`);

  // Store as JSON
  if (storetype === "json") {
    let existing = {};

    // ✅ FIX: Cleaner structure - check existing data
    const result = await env.JSONBIN.getWithMetadata(pathname);
    
    if (result?.value) {
      const meta = result.metadata || {};
      
      // Check encryption compatibility
      if (meta.crypt && !crypt) {
        return jsonError(`${pathname} is encrypted, provide key with ?c=KEY`, 403);
      }
      
      if (!meta.crypt && crypt) {
        console.log(`[STORE] Converting ${pathname} from unencrypted to encrypted`);
      }

      // Decrypt existing data if needed
      let val = result.value;
      if (meta.crypt) {
        try {
          val = await decryptData(val, crypt);
        } catch (e) {
          return jsonError(`Failed to decrypt ${pathname}: Invalid key`, 403);
        }
      }
      
      // Parse existing data
      try {
        existing = JSON.parse(val);
      } catch (e) {
        console.warn(`[STORE] Failed to parse existing data for ${pathname}, replacing`);
      }
    }

    // Process new data
    let bodyText = await request.text();
    if (encbase64) bodyText = utf8ToBase64(bodyText);

    if (q) {
      // Update specific field
      existing[q] = bodyText;
    } else {
      // Replace entire object
      try {
        existing = JSON.parse(bodyText);
      } catch (e) {
        return jsonError("Invalid JSON: " + e.message, 400);
      }
    }

    // Encrypt and store
    let dataToStore = JSON.stringify(existing);
    if (crypt) {
      dataToStore = await encryptData(dataToStore, crypt);
    }

    await env.JSONBIN.put(pathname, dataToStore, {
      metadata: { crypt: !!crypt }
    });

    console.log(`[STORED] ${pathname} (JSON, ${dataToStore.length} bytes, encrypted: ${!!crypt})`);
    return jsonOK({ ok: true, type: "json", encrypted: !!crypt });
  }

  // Store as raw binary
  if (storetype === "raw") {
    const buffer = await request.arrayBuffer();
    const segments = pathname.split("/");
    let filename = segments.pop() || "file";

    // Add extension if missing
    if (!filename.includes(".")) {
      const ext = contentType.split("/")[1] || "bin";
      filename = `${filename}.${ext}`;
    }

    // Encrypt if requested
    let toStore = buffer;
    if (crypt) {
      const encrypted = await encryptBinary(buffer, crypt);
      toStore = new TextEncoder().encode(encrypted).buffer;
    }

    await env.JSONBIN.put(pathname, toStore, {
      metadata: {
        filetype: contentType || "application/octet-stream",
        filename,
        size: toStore.byteLength,
        crypt: !!crypt  // ✅ ADD: Track encryption for raw files too
      }
    });

    console.log(`[STORED] ${pathname} (raw, ${toStore.byteLength} bytes, encrypted: ${!!crypt})`);
    return jsonOK({ stored: filename, type: "raw", size: toStore.byteLength, encrypted: !!crypt });
  }

  return jsonError("Unsupported store type", 400);
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Create expiring download token and redirect
 */
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

  console.log(`[TOKEN] Created: ${token} (expires in ${expiresSec}s)`);

  return new Response(null, {
    status: 302,
    headers: {
      Location: `/_download/${token}/${encodeURIComponent(filenameForToken)}`,
      "Cache-Control": "no-store"
    }
  });
}


/**
 * Generate admin panel HTML
 */
function getAdminHTML(env) {
  const apiUrl = '';
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSONBIN Admin Panel</title>
    <style>
        /* ... keep all existing styles ... */
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            color: #333;
            margin-bottom: 8px;
        }
        
        .header p {
            color: #666;
        }
        
        .auth-section {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .auth-section input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 12px;
        }
        
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
        }
        
        @media (max-width: 968px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .panel {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .panel h2 {
            color: #333;
            margin-bottom: 16px;
            font-size: 18px;
        }
        
        .items-list {
            max-height: 600px;
            overflow-y: auto;
        }
        
        .item {
            padding: 12px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .item:hover {
            background: #f5f5f5;
            border-color: #667eea;
        }
        
        .item.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        .item-name {
            font-weight: 500;
            flex: 1;
            word-break: break-all;
        }
        
        .item-meta {
            font-size: 12px;
            color: #999;
            margin-top: 4px;
        }
        
        .item.active .item-meta {
            color: rgba(255,255,255,0.8);
        }
        
        .item-actions {
            display: flex;
            gap: 8px;
            margin-left: 12px;
        }
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
            white-space: nowrap;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5568d3;
        }
        
        .btn-success {
            background: #10b981;
            color: white;
        }
        
        .btn-success:hover {
            background: #059669;
        }
        
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        .btn-secondary {
            background: #6b7280;
            color: white;
        }
        
        .btn-secondary:hover {
            background: #4b5563;
        }
        
        .btn-warning {
            background: #f59e0b;
            color: white;
        }
        
        .btn-warning:hover {
            background: #d97706;
        }
        
        .btn-small {
            padding: 4px 8px;
            font-size: 12px;
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 6px;
            font-weight: 500;
            color: #333;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            font-family: inherit;
        }
        
        .form-group textarea {
            font-family: 'Monaco', 'Courier New', monospace;
            min-height: 300px;
            resize: vertical;
        }
        
        .form-actions {
            display: flex;
            gap: 12px;
            margin-top: 20px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        .hidden {
            display: none !important;
        }
        
        .alert {
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 16px;
        }
        
        .alert-success {
            background: #d1fae5;
            color: #065f46;
            border: 1px solid #10b981;
        }
        
        .alert-error {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #ef4444;
        }
        
        .alert-info {
            background: #dbeafe;
            color: #1e40af;
            border: 1px solid #3b82f6;
        }
        
        .alert-warning {
            background: #fef3c7;
            color: #92400e;
            border: 1px solid #f59e0b;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }
        
        .empty-state svg {
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        .stats {
            display: flex;
            gap: 16px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }
        
        .stat {
            background: #f5f5f5;
            padding: 12px 16px;
            border-radius: 8px;
            flex: 1;
            min-width: 120px;
        }
        
        .stat-label {
            font-size: 12px;
            color: #666;
            margin-bottom: 4px;
        }
        
        .stat-value {
            font-size: 24px;
            font-weight: 600;
            color: #333;
        }
        
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 500;
            margin-left: 8px;
        }
        
        .badge-encrypted {
            background: #fef3c7;
            color: #92400e;
        }
        
        .badge-json {
            background: #dbeafe;
            color: #1e40af;
        }
        
        .badge-raw {
            background: #e0e7ff;
            color: #3730a3;
        }
        
        /* NEW: Decryption input styles */
        .decrypt-section {
            background: #fef3c7;
            border: 2px solid #f59e0b;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        
        .decrypt-section h3 {
            color: #92400e;
            margin-bottom: 12px;
            font-size: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .decrypt-input-group {
            display: flex;
            gap: 8px;
        }
        
        .decrypt-input-group input {
            flex: 1;
        }
        
        /* NEW: Image preview styles */
        .image-preview {
            max-width: 100%;
            border-radius: 8px;
            margin: 16px 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .image-preview img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            display: block;
        }
        
        .image-info {
            background: #f5f5f5;
            padding: 12px;
            border-radius: 6px;
            margin-top: 12px;
            font-size: 14px;
            color: #666;
        }
        
        /* NEW: Text file viewer */
        .text-viewer {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 16px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 500px;
            overflow-y: auto;
            line-height: 1.5;
        }
        /* ADD these new styles */
        .view-as-section {
            background: #e0e7ff;
            border: 2px solid #6366f1;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        
        .view-as-section h3 {
            color: #3730a3;
            margin-bottom: 12px;
            font-size: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .view-as-controls {
            display: flex;
            gap: 8px;
            align-items: center;
        }
        
        .view-as-controls select {
            flex: 1;
            padding: 8px 12px;
            border: 2px solid #c7d2fe;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .badge-lock {
            background: #fef3c7;
            color: #92400e;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <!-- Keep existing HTML structure, just update the script section -->
    <!-- ... same HTML as before ... -->
     <div class="container">
        <div class="header">
            <h1>🗄️ JSONBIN Admin Panel</h1>
            <p>Manage your JSON and binary data storage</p>
        </div>
        
        <div class="auth-section" id="authSection">
            <div class="form-group">
                <label>API Key</label>
                <input type="password" id="apiKeyInput" placeholder="Enter your API key">
            </div>
            <button class="btn btn-primary" onclick="app.authenticate()">Connect</button>
        </div>
        
        <div id="mainContent" class="hidden">
            <div class="panel" style="margin-bottom: 20px;">
                <div class="stats">
                    <div class="stat">
                        <div class="stat-label">Total Items</div>
                        <div class="stat-value" id="statTotal">0</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">JSON</div>
                        <div class="stat-value" id="statJson">0</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Raw/Binary</div>
                        <div class="stat-value" id="statRaw">0</div>
                    </div>
                    <div class="stat">
                        <div class="stat-label">Encrypted</div>
                        <div class="stat-value" id="statEncrypted">0</div>
                    </div>
                </div>
                <button class="btn btn-success" onclick="app.showCreateForm()">+ New Item</button>
                <button class="btn btn-secondary" onclick="app.loadItems()">🔄 Refresh</button>
                <div class="form-group">
                    <label>Search</label>
                    <input type="text" id="SearchId" oninput="app.renderItems()" placeholder="Search...">
                </div>
            </div>
            
            <div class="content-grid">
                <div class="panel">
                    <h2>Items</h2>
                    
                    <div id="itemsList" class="items-list">
                        <div class="loading">
                            <div class="spinner"></div>
                            Loading items...
                        </div>
                    </div>
                </div>
                
                <div class="panel">
                    <h2 id="editorTitle">Select an item</h2>
                    <div id="editorContent">
                        <div class="empty-state">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                            </svg>
                            <p>Select an item from the list or create a new one</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const app = {
            apiKey: '',
            apiUrl: '${apiUrl}',
            currentItem: null,
            items: [],
            
            authenticate() {
                this.apiKey = document.getElementById('apiKeyInput').value;
                if (!this.apiKey) {
                    alert('Please enter an API key');
                    return;
                }
                
                this.loadItems().then(success => {
                    if (success) {
                        document.getElementById('authSection').classList.add('hidden');
                        document.getElementById('mainContent').classList.remove('hidden');
                    }
                });
            },
            
            async loadItems() {
                try {
                    const url = this.apiUrl + '/?list&key=' + encodeURIComponent(this.apiKey);

                    const response = await fetch(url);
                    
                    if (!response.ok) {
                        if (response.status === 401) {
                            alert('Invalid API key');
                            return false;
                        }
                        throw new Error('Failed to load items');
                    }
                    
                    const text = await response.text();
                    this.items = this.parseList(text);
                    this.renderItems();
                    this.updateStats();
                    return true;
                } catch (error) {
                    console.error('Error loading items:', error);
                    this.showAlert('Failed to load items: ' + error.message, 'error');
                    return false;
                }
            },
            
            parseList(text) {
                const lines = text.split('\\n').filter(l => l.trim() && !l.includes('---'));
                const items = [];
                
                for (let i = 1; i < lines.length; i++) {
                    const parts = lines[i].split(/\\s{2,}/);
                    if (parts.length >= 4) {
                        items.push({
                            name: parts[0].trim(),
                            filename: parts[1].trim(),
                            filetype: parts[2].trim(),
                            encrypted: parts[3].trim() === 'yes',  // ✅ FIXED
                            size: parts[4]?.trim() || '?'
                        });
                    }
                }
                
                return items;
            },
            
            renderItems() {
                const container = document.getElementById('itemsList');
                
                if (this.items.length === 0) {
                    container.innerHTML = '<div class="empty-state">No items found</div>';
                    return;
                }
                
                var search = document.getElementById('SearchId').value;
                container.innerHTML = this.items.filter( item => item.name.includes(search) ).map(item => {
                    const isJson = item.filetype.includes('json');
                    const lockIcon = item.encrypted ? ' <span class="badge-lock">🔒</span>' : '';
                    const onclick = item.encrypted ? 'showDecryptionForm' : 'loadItem';

                    return \`
                        <div class="item" onclick="app.\${onclick}('\${item.name}')">
                            <div>
                                <div class="item-name">
                                    \${item.name}
                                    <span class="badge badge-\${isJson ? 'json' : 'raw'}">\${isJson ? 'JSON' : 'RAW'}</span>
                                    \${lockIcon}
                                </div>
                                <div class="item-meta">\${item.filetype} • \${item.size}</div>
                            </div>
                            <div class="item-actions">
                                <button class="btn btn-danger btn-small" onclick="event.stopPropagation(); app.deleteItem('\${item.name}')">Delete</button>
                            </div>
                        </div>
                    \`;
                }).join('');
            },
            
            async loadItem(name, decryptKey = null, viewAs = null) {
                try {
                    let url = this.apiUrl + name + '?key=' + encodeURIComponent(this.apiKey);
                    if (decryptKey) {
                        url += '&c=' + encodeURIComponent(decryptKey);
                    }
                    
                    // ✅ NEW: Force storage type for viewing
                    if (viewAs === 'json') {
                        url += '&s=json';
                    } else if (viewAs === 'raw') {
                        url += '&s=raw';
                    }
                    
                    const response = await fetch(url);
                    
                    // Handle encrypted content
                    if (!response.ok && response.status === 403) {
                        this.showDecryptionForm(name, viewAs);
                        return;
                    }
                    
                    if (!response.ok) {
                        throw new Error('Failed to load item: ' + response.statusText);
                    }
                    
                    const contentType = response.headers.get('content-type') || '';
                    
                    // ✅ IMPROVED: Override content type based on viewAs
                    let isJson = contentType.includes('json');
                    let isImage = contentType.startsWith('image/');
                    let isText = contentType.startsWith('text/') || 
                                 contentType.includes('xml') || 
                                 contentType.includes('javascript') ||
                                 contentType.includes('html');
                    
                    if (viewAs === 'json') {
                        isJson = true;
                        isImage = false;
                        isText = false;
                    } else if (viewAs === 'image') {
                        isJson = false;
                        isImage = true;
                        isText = false;
                    } else if (viewAs === 'text') {
                        isJson = false;
                        isImage = false;
                        isText = true;
                    }
                    
                    let content;
                    let blob = null;
                    
                    if (isJson) {
                        content = await response.text();
                        try {
                            content = JSON.stringify(JSON.parse(content), null, 2);
                        } catch (e) {
                            // Not valid JSON, treat as text
                            if (!viewAs) {
                                this.showAlert('Not valid JSON. Try "View As" text or raw.', 'warning');
                            }
                        }
                    } else if (isImage) {
                        blob = await response.blob();
                        content = URL.createObjectURL(blob);
                    } else if (isText) {
                        content = await response.text();
                    } else {
                        content = '[Binary data - ' + contentType + ']';
                    }
                    
                    // ✅ Get item info for encryption status
                    const itemInfo = this.items.find(i => i.name === name);
                    
                    this.currentItem = { 
                        name, 
                        content, 
                        blob,
                        isJson, 
                        isImage,
                        isText,
                        contentType,
                        decryptKey,
                        encrypted: itemInfo?.encrypted || false,
                        viewAs
                    };
                    
                    this.renderEditor();
                    
                    // Highlight selected item
                    document.querySelectorAll('.item').forEach(el => el.classList.remove('active'));
                    document.querySelectorAll('.item').forEach(el => {
                      const eltext = el.textContent.trim();
                      if(eltext.startsWith(name)){
                          el.classList.add('active');
                      }
                    
                    });
                    
                } catch (error) {
                    console.error('Error loading item:', error);
                    this.showAlert('Failed to load item: ' + error.message, 'error');
                }
            },
            
            showDecryptionForm(name, viewAs = null) {
                const title = document.getElementById('editorTitle');
                const content = document.getElementById('editorContent');
                
                title.textContent = '🔒 ' + name;
                
                content.innerHTML = \`
                    <div class="decrypt-section">
                        <h3>
                            <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                            </svg>
                            This item is encrypted
                        </h3>
                        <p style="margin-bottom: 12px; color: #92400e;">Enter the decryption key to view the content:</p>
                        <div class="decrypt-input-group">
                            <input type="password" id="decryptKeyInput" placeholder="Enter decryption key" 
                                   onkeypress="if(event.key==='Enter') app.decryptAndLoad('\${name}', '\${viewAs || ''}')">
                            <button class="btn btn-warning" onclick="app.decryptAndLoad('\${name}', '\${viewAs || ''}')">
                                🔓 Decrypt
                            </button>
                        </div>
                    </div>
                    <div class="alert alert-info">
                        <strong>Tip:</strong> The decryption key was set when this item was created. 
                        If you don't have the key, you won't be able to access the content.
                    </div>
                \`;
                
                setTimeout(() => document.getElementById('decryptKeyInput')?.focus(), 100);
            },
            
            decryptAndLoad(name, viewAs = null) {
                const key = document.getElementById('decryptKeyInput').value;
                if (!key) {
                    this.showAlert('Please enter a decryption key', 'error');
                    return;
                }
                this.loadItem(name, key, viewAs || null);
            },
            
            // ✅ NEW: Show view as selector for binary files
            showViewAsSelector(name, decryptKey) {
                const title = document.getElementById('editorTitle');
                const content = document.getElementById('editorContent');
                
                title.textContent = name;
                
                content.innerHTML = \`
                    <div class="view-as-section">
                        <h3>
                            <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                            </svg>
                            Try viewing this file as:
                        </h3>
                        <div class="view-as-controls" >
                            <select id="viewAsSelect" >
                                <option value="">Auto-detect</option>
                                <option value="json">JSON</option>
                                <option value="text">Text</option>
                                <option value="image">Image</option>
                                <option value="raw">Binary/Raw</option>
                            </select>
                            <button class="btn btn-primary" onclick="app.changeViewAs('\${name}', '\${decryptKey || ''}')">
                                👁️ View
                            </button>
                        </div>
                    </div>
                    <div class="alert alert-info">
                        This file is stored as raw/binary data. Select a format above to view it differently.
                    </div>
                    <div class="form-actions">
                        <a href="\${this.apiUrl}\${name}?key=\${encodeURIComponent(this.apiKey)}\${decryptKey ? '&c=' + encodeURIComponent(decryptKey) : ''}" 
                           class="btn btn-secondary" download>💾 Download Original</a>
                        <button class="btn btn-danger" onclick="app.deleteItem('\${name}')">🗑️ Delete</button>
                    </div>
                \`;
            },
            
            changeViewAs(name, decryptKey) {
                const viewAs = document.getElementById('viewAsSelect').value || null;
                this.loadItem(name, decryptKey || null, viewAs);
            },
            
            renderEditor() {
                if (!this.currentItem) return;
                
                const title = document.getElementById('editorTitle');
                const content = document.getElementById('editorContent');
                
                const encryptBadge = this.currentItem.encrypted ? ' <span class="badge-lock">🔒 Encrypted</span>' : '';
                title.innerHTML = this.currentItem.name + encryptBadge;
                
                const decryptParam = this.currentItem.decryptKey ? '&c=' + encodeURIComponent(this.currentItem.decryptKey) : '';
                
                // Render images
                if (this.currentItem.isImage) {
                    const imageUrl = this.currentItem.content;
                    content.innerHTML = \`
                        <div id="alertContainer"></div>
                        <div class="image-preview">
                            <img src="\${imageUrl}" alt="\${this.currentItem.name}" onerror="this.parentElement.innerHTML='<div class=alert-error>Failed to load image. File may be corrupted or not a valid image.</div>'">
                        </div>
                        <div class="image-info">
                            <strong>Type:</strong> \${this.currentItem.contentType}<br>
                            <strong>Path:</strong> \${this.currentItem.name}<br>
                            <strong>View As:</strong> Image \${this.currentItem.viewAs ? '(forced)' : '(auto)'}
                        </div>
                        <div class="form-actions">
                            <button class="btn btn-secondary" onclick="app.showViewAsSelector('\${this.currentItem.name}', '\${this.currentItem.decryptKey || ''}')">
                                🔄 View As...
                            </button>
                            <a href="\${this.apiUrl}\${this.currentItem.name}?key=\${encodeURIComponent(this.apiKey)}\${decryptParam}" 
                               class="btn btn-primary" download>💾 Download</a>
                            <button class="btn btn-danger" onclick="app.deleteItem('\${this.currentItem.name}')">🗑️ Delete</button>
                        </div>
                    \`;
                    return;
                }
                
                // Render text files
                if (this.currentItem.isText && !this.currentItem.isJson) {
                    content.innerHTML = \`
                        <div id="alertContainer"></div>
                        <div class="form-group">
                            <label>Path</label>
                            <input type="text" value="\${this.currentItem.name}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Content (\${this.currentItem.contentType}) \${this.currentItem.viewAs ? '- Viewing as: ' + this.currentItem.viewAs : ''}</label>
                            <textarea id="editTextContent">\${this.escapeHtml(this.currentItem.content)}</textarea>
                        </div>
                        <div class="form-actions">
                            <button class="btn btn-success" onclick="app.saveTextFile()">💾 Save</button>
                            <button class="btn btn-secondary" onclick="app.showViewAsSelector('\${this.currentItem.name}', '\${this.currentItem.decryptKey || ''}')">
                                🔄 View As...
                            </button>
                            <a href="\${this.apiUrl}\${this.currentItem.name}?key=\${encodeURIComponent(this.apiKey)}\${decryptParam}" 
                               class="btn btn-secondary" download>⬇️ Download</a>
                            <button class="btn btn-danger" onclick="app.deleteItem('\${this.currentItem.name}')">🗑️ Delete</button>
                        </div>
                    \`;
                    return;
                }
                
                // Render JSON
                if (this.currentItem.isJson) {
                    content.innerHTML = \`
                        <div id="alertContainer"></div>
                        <div class="form-group">
                            <label>Path</label>
                            <input type="text" id="editPath" value="\${this.currentItem.name}" readonly>
                        </div>
                        <div class="form-group">
                            <label>Content (JSON) \${this.currentItem.viewAs ? '- Viewing as: ' + this.currentItem.viewAs : ''}</label>
                            <textarea id="editContent">\${this.escapeHtml(this.currentItem.content)}</textarea>
                        </div>
                        <div class="form-group checkbox-group">
                            <input type="checkbox" id="editEncrypt" \${this.currentItem.encrypted ? 'checked' : ''}>
                            <label for="editEncrypt">Encrypt data</label>
                        </div>
                        <div class="form-group \${this.currentItem.encrypted ? '' : 'hidden'}" id="editEncryptKeyGroup">
                            <label>Encryption Key</label>
                            <input type="password" id="editEncryptKey" placeholder="Enter encryption key" value="\${this.currentItem.decryptKey || ''}">
                        </div>
                        <div class="form-actions">
                            <button class="btn btn-success" onclick="app.saveItem()">💾 Save</button>
                            <button class="btn btn-secondary" onclick="app.showViewAsSelector('\${this.currentItem.name}', '\${this.currentItem.decryptKey || ''}')">
                                🔄 View As...
                            </button>
                            <button class="btn btn-danger" onclick="app.deleteItem('\${this.currentItem.name}')">🗑️ Delete</button>
                        </div>
                    \`;
                    
                    document.getElementById('editEncrypt').addEventListener('change', (e) => {
                        document.getElementById('editEncryptKeyGroup').classList.toggle('hidden', !e.target.checked);
                    });
                    return;
                }
                
                // ✅ IMPROVED: Binary data - show view as selector
                this.showViewAsSelector(this.currentItem.name, this.currentItem.decryptKey);
            },
            
            escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            },
            
            async saveTextFile() {
                if (!this.currentItem) return;
                
                const content = document.getElementById('editTextContent').value;
                
                try {
                    let url = this.apiUrl + this.currentItem.name + '?key=' + encodeURIComponent(this.apiKey) + '&s=raw';
                    if (this.currentItem.decryptKey) {
                        url += '&c=' + encodeURIComponent(this.currentItem.decryptKey);
                    }
                    
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': this.currentItem.contentType },
                        body: content
                    });
                    
                    if (!response.ok) {
                        throw new Error('Failed to save file');
                    }
                    
                    this.showAlert('Saved successfully!', 'success');
                    await this.loadItems();
                    
                } catch (error) {
                    console.error('Error saving file:', error);
                    this.showAlert('Failed to save: ' + error.message, 'error');
                }
            },
            
            // ... rest of the methods remain the same ...
            
            showCreateForm() {
                this.currentItem = null;
                document.getElementById('editorTitle').textContent = 'Create New Item';
                document.getElementById('editorContent').innerHTML = \`
                    <div id="alertContainer"></div>
                    <div class="form-group">
                        <label>Path (e.g., /my/data or /files/image)</label>
                        <input type="text" id="newPath" placeholder="/my/new/item">
                    </div>
                    <div class="form-group">
                        <label>Type</label>
                        <select id="newType" onchange="app.toggleContentType()">
                            <option value="json">JSON</option>
                            <option value="raw">Raw/Binary</option>
                        </select>
                    </div>
                    <div class="form-group" id="newContentGroup">
                        <label>Content (JSON)</label>
                        <textarea id="newContent" placeholder='{"key": "value"}'></textarea>
                    </div>
                    <div class="form-group hidden" id="newFileGroup">
                        <label>File</label>
                        <input type="file" id="newFile">
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" id="newEncrypt">
                        <label for="newEncrypt">Encrypt data</label>
                    </div>
                    <div class="form-group hidden" id="newEncryptKeyGroup">
                        <label>Encryption Key</label>
                        <input type="password" id="newEncryptKey" placeholder="Enter encryption key">
                        <small style="color: #666;">Remember this key - you'll need it to decrypt the data</small>
                    </div>
                    <div class="form-actions">
                        <button class="btn btn-success" onclick="app.createItem()">✨ Create Item</button>
                        <button class="btn btn-secondary" onclick="app.renderEditor()">Cancel</button>
                    </div>
                \`;
                
                document.getElementById('newEncrypt').addEventListener('change', (e) => {
                    document.getElementById('newEncryptKeyGroup').classList.toggle('hidden', !e.target.checked);
                });
            },
            
            toggleContentType() {
                const type = document.getElementById('newType').value;
                const isJson = type === 'json';
                
                document.getElementById('newContentGroup').classList.toggle('hidden', !isJson);
                document.getElementById('newFileGroup').classList.toggle('hidden', isJson);
            },
            
            async createItem() {
                const path = document.getElementById('newPath').value.trim();
                const type = document.getElementById('newType').value;
                const encrypt = document.getElementById('newEncrypt').checked;
                const encryptKey = document.getElementById('newEncryptKey').value;
                
                if (!path || !path.startsWith('/')) {
                    this.showAlert('Path must start with /', 'error');
                    return;
                }
                
                if (encrypt && !encryptKey) {
                    this.showAlert('Encryption key required', 'error');
                    return;
                }
                
                try {
                    let url = this.apiUrl + path + '?key=' + encodeURIComponent(this.apiKey);
                    if (encrypt) url += '&c=' + encodeURIComponent(encryptKey);
                    
                    let body;
                    let headers = {};
                    
                    if (type === 'json') {
                        const content = document.getElementById('newContent').value;
                        try {
                            JSON.parse(content);
                        } catch (e) {
                            this.showAlert('Invalid JSON: ' + e.message, 'error');
                            return;
                        }
                        body = content;
                        headers['Content-Type'] = 'application/json';
                    } else {
                        const file = document.getElementById('newFile').files[0];
                        if (!file) {
                            this.showAlert('Please select a file', 'error');
                            return;
                        }
                        body = await file.arrayBuffer();
                        headers['Content-Type'] = file.type || 'application/octet-stream';
                    }
                    
                    const response = await fetch(url, {
                        method: 'POST',
                        headers,
                        body
                    });
                    
                    if (!response.ok) {
                        throw new Error('Failed to create item');
                    }
                    
                    this.showAlert('Item created successfully!', 'success');
                    await this.loadItems();
                    this.loadItem(path, encrypt ? encryptKey : null);
                    
                } catch (error) {
                    console.error('Error creating item:', error);
                    this.showAlert('Failed to create item: ' + error.message, 'error');
                }
            },
            
            async saveItem() {
                if (!this.currentItem) return;
                
                const content = document.getElementById('editContent').value;
                const encrypt = document.getElementById('editEncrypt').checked;
                const encryptKey = document.getElementById('editEncryptKey').value;
                
                if (encrypt && !encryptKey) {
                    this.showAlert('Encryption key required', 'error');
                    return;
                }
                
                try {
                    JSON.parse(content);
                } catch (e) {
                    this.showAlert('Invalid JSON: ' + e.message, 'error');
                    return;
                }
                
                try {
                    let url = this.apiUrl + this.currentItem.name + '?key=' + encodeURIComponent(this.apiKey);
                    if (encrypt) url += '&c=' + encodeURIComponent(encryptKey);
                    
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: content
                    });
                    
                    if (!response.ok) {
                        throw new Error('Failed to save item');
                    }
                    
                    this.showAlert('Saved successfully!', 'success');
                    await this.loadItems();
                    
                } catch (error) {
                    console.error('Error saving item:', error);
                    this.showAlert('Failed to save: ' + error.message, 'error');
                }
            },
            
            async deleteItem(name) {
                if (!confirm(\`Delete "\${name}"?\\n\\nThis action cannot be undone.\`)) {
                    return;
                }
                
                try {
                    const url = this.apiUrl + name + '?key=' + encodeURIComponent(this.apiKey);
                    const response = await fetch(url, { method: 'DELETE' });
                    
                    if (!response.ok) {
                        throw new Error('Failed to delete item');
                    }
                    
                    this.showAlert('Item deleted', 'success');
                    this.currentItem = null;
                    document.getElementById('editorTitle').textContent = 'Select an item';
                    document.getElementById('editorContent').innerHTML = '<div class="empty-state">Item deleted</div>';
                    await this.loadItems();
                    
                } catch (error) {
                    console.error('Error deleting item:', error);
                    this.showAlert('Failed to delete: ' + error.message, 'error');
                }
            },
            
            showAlert(message, type = 'info') {
                const container = document.getElementById('alertContainer') || document.getElementById('editorContent');
                const alert = document.createElement('div');
                alert.className = \`alert alert-\${type}\`;
                alert.textContent = message;
                container.insertBefore(alert, container.firstChild);
                
                setTimeout(() => alert.remove(), 5000);
            },
            updateStats() {
                const json = this.items.filter(i => i.filetype.includes('json')).length;
                const total = this.items.length;
                const raw = total - json;
                const encrypted = this.items.filter(i => i.encrypted).length;  // ✅ FIXED
                
                document.getElementById('statTotal').textContent = total;
                document.getElementById('statJson').textContent = json;
                document.getElementById('statRaw').textContent = raw;
                document.getElementById('statEncrypted').textContent = encrypted;
            }
        };
        
        const savedKey = localStorage.getItem('jsonbin_api_key');
        if (savedKey) {
            document.getElementById('apiKeyInput').value = savedKey;
            app.apiKey = savedKey;
            app.loadItems().then(success => {
                if (success) {
                    document.getElementById('authSection').classList.add('hidden');
                    document.getElementById('mainContent').classList.remove('hidden');
                }
            });
        }
        
        document.getElementById('apiKeyInput').addEventListener('change', (e) => {
            localStorage.setItem('jsonbin_api_key', e.target.value);
        });
    </script>
</body>
</html>`;
}

