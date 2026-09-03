// Helper functions extracted from jsonbin.js

// --- internal binary ↔ base64 helpers ---

function bytesToBinaryString(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < u8.length; i++) {
    binary += String.fromCharCode(u8[i]);
  }
  return binary;
}

// Legacy fixed salt, kept only so data encrypted before the per-item random
// salt was introduced can still be decrypted.
const LEGACY_SALT = "salt";

async function deriveAESKey(key, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: typeof salt === "string" ? encoder.encode(salt) : salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// --- encryption helpers ---

// Ciphertext format: "<saltB64>:<ivB64>:<encB64>". A random salt per
// encryption prevents precomputed (rainbow-table) attacks against the
// PBKDF2 derivation, which a single fixed salt does not.
export async function encryptData(data, key) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveAESKey(key, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoder.encode(data)
  );

  const saltB64 = btoa(bytesToBinaryString(salt));
  const ivB64 = btoa(bytesToBinaryString(iv));
  const encB64 = btoa(bytesToBinaryString(new Uint8Array(encrypted)));

  return saltB64 + ":" + ivB64 + ":" + encB64;
}

export async function decryptData(ciphertext, key) {
  const parts = ciphertext.split(":");

  let salt, ivB64, encB64;
  if (parts.length === 3) {
    [ , ivB64, encB64] = parts;
    salt = base64ToUint8Array(parts[0]);
  } else {
    // Legacy two-part format ("iv:enc") produced with the fixed salt.
    [ivB64, encB64] = parts;
    salt = LEGACY_SALT;
  }

  const iv = base64ToUint8Array(ivB64);
  const data = base64ToUint8Array(encB64);
  const aesKey = await deriveAESKey(key, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    data
  );

  return new TextDecoder().decode(decrypted);
}

// --- binary helpers ---

export function arrayBufferToBase64(buffer) {
  return btoa(bytesToBinaryString(buffer));
}

export function base64ToUint8Array(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    arr[i] = bin.charCodeAt(i);
  }
  return arr;
}

// --- UTF8 <-> base64 helpers (safe for Unicode) ---

export function utf8ToBase64(str) {
  const buf = new TextEncoder().encode(str).buffer;
  return arrayBufferToBase64(buf);
}

export function base64ToUtf8(b64) {
  const arr = base64ToUint8Array(b64);
  return new TextDecoder().decode(arr);
}

// --- encryption wrappers for binary ---

export async function encryptBinary(buffer, key) {
  const b64 = arrayBufferToBase64(buffer);
  return await encryptData(b64, key);
}

export async function decryptBinary(ciphertext, key) {
  const b64 = await decryptData(ciphertext, key);
  return base64ToUint8Array(b64).buffer;
}

// --- utility helpers ---

export function sanitizeFilename(name) {
  name = name.split("/").pop() || name;
  name = name.replace(/[^a-zA-Z0-9._()\[\] \-]+/g, "");
  return name || "file";
}

export function generateToken(len = 18) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Constant-time string comparison to avoid leaking API key/share-code
// contents through response-time differences.
export function timingSafeEqual(a, b) {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(String(a ?? ""));
  const bufB = encoder.encode(String(b ?? ""));

  // Compare against a fixed-length view so the loop time doesn't depend on
  // the length of either input, then fold in a length check.
  const len = Math.max(bufA.length, bufB.length, 1);
  let diff = bufA.length ^ bufB.length;
  for (let i = 0; i < len; i++) {
    diff |= (bufA[i] || 0) ^ (bufB[i] || 0);
  }
  return diff === 0;
}

export function jsonOK(obj) {
  return new Response(JSON.stringify(obj, null, 2), {
    headers: { "Content-Type": "application/json" },
  });
}

export function jsonError(msg, status) {
  return new Response(JSON.stringify({ ok: false, error: msg }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// --- request processing ---

export async function processRequest(request, config) {
  const url = new URL(request.url);
  const targetUrl = new URL(
    config.forwardPathname + url.search,
    config.targetUrl
  );
  console.log(
    `processRequest: method:${request.method}, targetUrl:${targetUrl}`
  );

  const headers = new Headers(request.headers);

  const headersToRemove = [
    "host",
    "cf-connecting-ip",
    "cf-ray",
    "cf-visitor",
    "cf-ipcountry",
    "cdn-loop",
    "x-forwarded-proto",
  ];
  headersToRemove.forEach((header) => headers.delete(header));

  // Rewrite Destination header for WebDAV MOVE/COPY
  if (["MOVE", "COPY"].includes(request.method)) {
    const destination = headers.get("Destination");
    if (destination) {
      try {
        const destUrl = new URL(destination);
        const destPath = destUrl.pathname;
        const urlsplitIndex = destPath.indexOf("/urlsplit/");

        if (urlsplitIndex > -1) {
          const destForwardPath = destPath.slice(
            urlsplitIndex + "/urlsplit/".length
          );
          const newDestination = new URL(
            destForwardPath,
            config.targetUrl
          ).toString();
          headers.set("Destination", newDestination);
          console.log(
            `Rewritten Destination: ${destination} -> ${newDestination}`
          );
        } else {
          const newDestination = new URL(
            destUrl.pathname,
            config.targetUrl
          ).toString();
          headers.set("Destination", newDestination);
          console.log(
            `Rewritten Destination (fallback): ${destination} -> ${newDestination}`
          );
        }
      } catch (e) {
        console.error("Failed to rewrite Destination header:", e);
      }
    }
  }

  const requestInit = {
    method: request.method,
    headers,
  };

  const methodsWithBody = [
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "LOCK",
  ];

  if (methodsWithBody.includes(request.method)) {
    const contentLength = request.headers.get("content-length");

    if (contentLength && parseInt(contentLength) > 0) {
      if (parseInt(contentLength) < 10 * 1024 * 1024) {
        requestInit.body = await request.arrayBuffer();
      } else {
        requestInit.body = request.body;
        requestInit.duplex = "half";
      }
    } else {
      try {
        const cloned = request.clone();
        const bodyBuffer = await cloned.arrayBuffer();
        if (bodyBuffer.byteLength > 0) {
          requestInit.body = bodyBuffer;
        }
      } catch (_e) {
        console.log("No body to forward");
      }
    }
  }

  return new Request(targetUrl.toString(), requestInit);
}

export async function forwardRequest(request, config) {
  const isWebSocket = request.headers.get("Upgrade") === "websocket";

  if (isWebSocket) {
    try {
      const response = await fetch(request);
      if (response.status === 101) {
        return response;
      }
      return new Response(response.body, response);
    } catch (error) {
      throw error;
    }
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeout);

  try {
    const response = await fetch(request, { signal: controller.signal });
    clearTimeout(timeoutId);
    return new Response(response.body, response);
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === "AbortError") {
      throw new Error(`Request timeout after ${config.timeout}ms`);
    }
    throw error;
  }
}

// --- CORS helpers ---

export function addCORSHeaders(response, request, config) {
  if (response.status === 101 || response.status < 200 || response.status > 599) {
    return response;
  }

  const newHeaders = new Headers(response.headers);
  const corsHeaders = getCORSHeaders(request, config.allowedOrigins);

  Object.entries(corsHeaders).forEach(([key, value]) => {
    newHeaders.set(key, value);
  });

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}

export function handleCORS(request, env) {
  const allowedOrigins = env.ALLOWED_ORIGINS?.split(",") || ["*"];

  return new Response(null, {
    status: 204,
    headers: {
      ...getCORSHeaders(request, allowedOrigins),
      "Access-Control-Max-Age": "86400",
    },
  });
}

export function getCORSHeaders(request, allowedOrigins) {
  const origin = request.headers.get("Origin");
  let allowOrigin = "*";

  if (!allowedOrigins.includes("*") && origin) {
    allowOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];
  } else if (origin) {
    allowOrigin = origin;
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With, Accept, Origin",
    "Access-Control-Allow-Credentials": "true",
    Vary: "Origin",
  };
}

export function isOriginAllowed(request, allowedOrigins) {
  if (allowedOrigins.includes("*")) return true;
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  return allowedOrigins.includes(origin);
}

// --- buffer / decode helpers ---

export function bufferToText(value) {
  if (value instanceof ArrayBuffer) {
    return new TextDecoder().decode(new Uint8Array(value));
  }
  if (value instanceof Uint8Array) {
    return new TextDecoder().decode(value);
  }
  return String(value);
}

export async function decryptAndDecode(ciphertext, key) {
  const decrypted = await decryptData(ciphertext, key);

  try {
    JSON.parse(decrypted);
    return decrypted;
  } catch {
    try {
      const bytes = base64ToUint8Array(decrypted);
      return new TextDecoder().decode(bytes);
    } catch {
      return decrypted;
    }
  }
}