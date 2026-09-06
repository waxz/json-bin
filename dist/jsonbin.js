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
    decryptAndDecode,
    timingSafeEqual
} from './helpers.js';

import { checkRateAndBan, recordAuthResult } from './security.js';
// Define your parameters globally or pull them from an external configuration file
const securityOptions = {
  rateLimit: 10,          // Stricter rate limit
  maxAuthFails: 3,        // Lower tolerance for bad login attempts
  banDuration: 60000     // Shorter ban duration (1 minutes in ms)
};

export async function handleRequest(request, env) {
    const JSONBIN = env.JSONBIN;
    if (!JSONBIN) return jsonError("Missing env.JSONBIN", 500);

    const APIKEY = env.APIKEYSECRET;
    if (!APIKEY) return jsonError("Missing env.APIKEYSECRET", 500);

    if (request.method === 'OPTIONS') {
        return handleCORS(request, env);
    }

    // 1. Initial Gatekeeping: Rate limits & pre-existing bans

    const rateCheck = checkRateAndBan(request, securityOptions);
    if (rateCheck instanceof Response) return rateCheck;

    try {
        const urlObj = new URL(request.url);
        const originPathname = urlObj.pathname;
        const { searchParams } = urlObj;

        const forwardPath = `/_forward/${APIKEY}`;
        const urlSplitMarker = env.URLSPLIT || "/urlsplit";
        const isForward = originPathname.startsWith(forwardPath);
        let pathname = originPathname;
        let forwardPathname = "/";

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
        const listFlag = searchParams.has("list");
        const encbase64 = searchParams.has("b64");
        const redirect = searchParams.has("redirect") || searchParams.has("r");
        const isJson = pathname.endsWith(".json");



        if (pathname.startsWith("/_download/")) {
            const result =   await handleTokenDownload(request, env);
            if (result instanceof Response) {
                return result;
            }else{
                return await handleStore(result, request, env, { sParam, q, crypt, encbase64, isJson });
            }
        }

        if (isForward) {
            return await handleForward(pathname, forwardPathname, request, env, { crypt, q });
        }

        const authHeader = headers.get("Authorization");
        const keyFromQuery = searchParams.get("key");
        const expectedHeader = `Bearer ${APIKEY}`;

        if (authHeader && !timingSafeEqual(authHeader, expectedHeader)) {
            recordAuthResult(request, false);
            return jsonError("Authorization Failed: Invalid Authorization header", 401);
        } else if (keyFromQuery && !timingSafeEqual(keyFromQuery, APIKEY)) {
            recordAuthResult(request, false);
            return jsonError("Authorization Failed: Invalid key", 401);
        } else if (!authHeader && !keyFromQuery) {
            recordAuthResult(request, false);
            return jsonError("Authorization Failed: Missing Authorization or key", 401);
        }
        recordAuthResult(request, true);




        if (listFlag) {
            return await handleList(searchParams, env);
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

async function handleForwardRequest(request, result, forwardPathname) {

    let text = bufferToText(result.value);
    let config;
    try { config = JSON.parse(text); } catch (e) { return jsonError("Invalid Config", 500); }

    let targetUrl = config.url || null;
    if (!targetUrl) return jsonError("No target URL", 404);

    const forwardConfig = {
        targetUrl: targetUrl,
        forwardPathname: forwardPathname,
        allowedOrigins: ['*'],
        timeout: 100000
    };

    const processedRequest = await processRequest(request, forwardConfig);
    const response = await forwardRequest(processedRequest, forwardConfig);

    const content_type = response.headers.get("content-type");
    if (content_type && content_type.includes("text/html")) {
        return new Response(null, {
            status: 302,
            headers: { "Location": `${targetUrl}${forwardPathname}`, "Cache-Control": "no-store" }
        });
    }
    return addCORSHeaders(response, request, forwardConfig);

}

async function handleTokenDownload(request, env) {
    const url = new URL(request.url);
    const { searchParams } = url;
    const pathname = url.pathname;
    var path_list = pathname.slice(1).split("/");

    var shareCode = "";
    if (path_list.length < 2) {
        return jsonError(`URL ${url} is Invalid`, 404);
    }
    if (path_list.length >= 3 && path_list[2].startsWith("share=")) {
        shareCode = path_list[2].slice(6);
    }
    var forward = false;
    if (shareCode) {
        forward = path_list.length >= 4;
    } else {
        forward = path_list.length >= 3;
    }




    const link = decodeURIComponent(path_list[1]);

    const shareLink = decodeURIComponent(await decryptData(link, shareCode));

    const path = shareLink.slice(3);

    if (shareLink.startsWith("/_s/")) {

        const result = await env.JSONBIN.getWithMetadata(path, "arrayBuffer");
        if (!result || !result.value) return jsonError("Source item not found", 404);
        const newMeta = result.metadata || {};


        if (newMeta.expiresSec == 0) {
            return jsonError("Share is Disabled", 404);
        }

        let shared_ok = false;
        if (timingSafeEqual(shareCode, newMeta.code)) {
            if (newMeta.expiresSec == 1) {
                shared_ok = true;
            } else {
                const now = Date.now();
                const dt = now - newMeta.shareActivateStamp;
                const sec = dt / 1000;
                if (sec > newMeta.expiresSec) {
                    shared_ok = false;
                } else {
                    shared_ok = true;
                }
            }
        } else {
            return jsonError(`shareCode ${shareCode} is Wrong`, 404);
        }


        if (shared_ok) {

            const filename = sanitizeFilename(newMeta.filename || path.split("/").pop() || "data");

            // check valid url
            let slice_index = 2 + path_list[0].length + path_list[1].length;
            if (shareCode) {
                slice_index += 1 + path_list[2].length
            }

            let forwardPathname = pathname.slice(slice_index);
            console.log("handleTokenDownload: ",request.method)

            if (request.method === "POST" || request.method === "PATCH") {
                console.log("handleTokenDownload process post")

                console.log("handleTokenDownload: pathname",pathname)
                console.log("handleTokenDownload: path",path)

                return path;
            }


            if (!forward) {

                forwardPathname = "/";

                let config = null;
                let config_url = null;
                try {
                    let text = bufferToText(result.value);
                    config = JSON.parse(text); config_url = config.url || null;
                } catch (e) { config = null }

                if (!config_url) {

                    return new Response(result.value, {
                        headers: {
                            "Content-Type": newMeta.filetype,
                            "Content-Disposition": `attachment; filename="file"; filename*=UTF-8''${encodeURIComponent(filename)}`,
                            "Content-Length": String(result.value.byteLength || 0),
                            "Cache-Control": "no-store"
                        }
                    });
                }

            }

            return handleForwardRequest(request, result, forwardPathname);
        }
    }

    return jsonError("shareCode Expires", 404);
}

async function handleForward(pathname, forwardPathname, request, env, { crypt, q }) {
    const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
    if (!result?.value) return jsonError(`Forward config not found`, 404);
    return handleForwardRequest(request, result, forwardPathname);

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
            shareLink: meta.shareLink || "",
            code: meta.code || "",
            expiresSec: meta.expiresSec ?? "",
            shareActivateStamp: meta.shareActivateStamp || "",
            encrypted: meta.crypt ? "yes" : "no",
            note: meta.note || ""
        });
    }

    if (searchParams.has("json_response")) {
        return jsonOK(items);
    } else {
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
            "Content-Disposition": `attachment; filename="file"; filename*=UTF-8''${encodeURIComponent(filename)}`,
            "Content-Length": String(value.byteLength || 0),
            "Cache-Control": "no-store"
        }
    });
}

async function handleStore(pathname, request, env, { sParam, q, crypt, encbase64, isJson }) {
    const { searchParams } = new URL(request.url);
    const contentType = request.headers.get("content-type") || "";
    let filename = searchParams.get("filename") || pathname.split("/").pop() || "file";
    filename = filename.trim();

    // RENAME
    if (searchParams.has("rename_to")) {
        const newPath = searchParams.get("rename_to").trim();

        if (!newPath || !newPath.startsWith("/")) {
            return jsonError("New path must start with /", 400);
        }
        if (newPath === pathname) {
            return jsonError("New path is same as current", 400);
        }

        const destExists = await env.JSONBIN.get(newPath);
        if (destExists && !searchParams.has("force")) {
            return jsonError("Destination already exists. Use ?force=true to overwrite.", 409);
        }

        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError("Source item not found", 404);

        let newMeta = result.metadata || {};
        newMeta.filename = filename;
        newMeta.code = null;
        newMeta.shareLink = null;
        newMeta.shareActivateStamp = null;
        newMeta.expiresSec = null;

        await env.JSONBIN.put(newPath, result.value, { metadata: newMeta });
        await env.JSONBIN.delete(pathname);

        return jsonOK({ renamed: true, from: pathname, to: newPath });
    }

    // SET TYPE
    if (searchParams.has("set_type")) {
        const newType = searchParams.get("set_type");
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError("Item not found", 404);

        const meta = result.metadata || {};
        meta.filetype = newType;

        await env.JSONBIN.put(pathname, result.value, { metadata: meta });
        return jsonOK({ ok: true, type: newType, message: "Type updated" });
    }

    // SET NAME
    if (searchParams.has("set_name")) {
        const newName = searchParams.get("set_name");
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError("Item not found", 404);

        const meta = result.metadata || {};
        meta.filename = newName;

        await env.JSONBIN.put(pathname, result.value, { metadata: meta });
        return jsonOK({ ok: true, name: newName, message: "Name updated" });
    }

    // UPDATE METADATA (including note)
    if (searchParams.has("update_meta")) {
        const body = await request.text();
        const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
        if (!result || !result.value) return jsonError("Item not found", 404);

        const meta = result.metadata || {};
        meta.note = body;

        await env.JSONBIN.put(pathname, result.value, { metadata: meta });
        return jsonOK({ ok: true, message: "Metadata updated" });
    }

    // STANDARD STORE
    let storetype = sParam;
    if (!storetype) {
        storetype = (q || isJson || contentType.includes("json")) ? "json" : "raw";
    }

    if (storetype === "json") {
        let existing = {};
        let existing_meta = {};

        const result = await env.JSONBIN.getWithMetadata(pathname);

        if (result?.value) {
            const meta = result.metadata || {};
            let val = result.value;
            if (meta.crypt && crypt) {
                try { val = await decryptData(val, crypt); } catch (e) { }
            }
            try {
                existing = JSON.parse(val);
                existing_meta = meta;

            } catch (e) { }
        }

        let bodyText = await request.text();
        if (encbase64) bodyText = utf8ToBase64(bodyText);

        if (q) existing[q] = bodyText;
        else {
            try { existing = JSON.parse(bodyText); } catch (e) { return jsonError("Invalid JSON", 400); }
        }

        let dataToStore = JSON.stringify(existing);
        let metaToStore = existing_meta;

        if (crypt) dataToStore = await encryptData(dataToStore, crypt);
        metaToStore.crypt = !!crypt;
        metaToStore.filename = filename;
        metaToStore.filetype = "application/json";

        await env.JSONBIN.put(pathname, dataToStore, { metadata: metaToStore });
        return jsonOK({ ok: true, type: "json", encrypted: !!crypt });
    }

    if (storetype === "raw") {
        let existing_meta = {};

        const result = await env.JSONBIN.getWithMetadata(pathname);

        if (result?.metadata) {
            const meta = result.metadata || {};

            try {
                existing_meta = meta;
            } catch (e) { }
        }


        const buffer = await request.arrayBuffer();
        let toStore = buffer;

        if (crypt) {
            const encrypted = await encryptBinary(buffer, crypt);
            toStore = new TextEncoder().encode(encrypted).buffer;
        }
        let metaToStore = existing_meta;
        metaToStore.filename = filename;
        metaToStore.filetype = contentType || "application/octet-stream";
        metaToStore.crypt = !!crypt;
        metaToStore.size = toStore.byteLength;


        await env.JSONBIN.put(pathname, toStore, {
            metadata: metaToStore
        });
        return jsonOK({ stored: filename, type: "raw", size: toStore.byteLength, encrypted: !!crypt });
    }

    return jsonError("Unsupported store type", 400);
}

// ============================================================
// DOWNLOAD TOKEN
// ============================================================

async function createDownloadToken(pathname, filetype, searchParams, env, crypt, filename = null) {
    const filenameForToken = sanitizeFilename(filename || pathname.split("/").pop() || "data");

    const code = searchParams.get("code") || "";
    const expiresSec = parseInt(searchParams.get("expires") || "0", 10) || 0;

    const result = await env.JSONBIN.getWithMetadata(pathname, "arrayBuffer");
    if (!result || !result.value) return jsonError("Source item not found", 404);
    const newMeta = result.metadata || {};

    const link = `/_s${encodeURIComponent(pathname)}`;
    var shareLink = `/_download/${encodeURIComponent(await encryptData(link, code))}`;
    if (code) {
        shareLink += `/share=${code}`;
    }

    newMeta.code = code;
    newMeta.shareActivateStamp = Date.now();
    newMeta.expiresSec = expiresSec;
    newMeta.shareLink = shareLink;


    await env.JSONBIN.put(pathname, result.value, { metadata: newMeta });

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
