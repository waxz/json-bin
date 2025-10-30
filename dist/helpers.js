// Helper functions extracted from jsonbin.js

// --- encryption helpers ---
export async function encryptData(data, key) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: encoder.encode("salt"), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoder.encode(data));
  // Convert iv and encrypted bytes to binary strings safely (avoid spread on large arrays)
  let ivStr;
  let encStr;
  try {
    const td = new TextDecoder('latin1');
    ivStr = td.decode(iv);
    encStr = td.decode(new Uint8Array(encrypted));
  } catch (e) {
    // Fallback: build strings byte-by-byte
    ivStr = String.fromCharCode(...iv);
    const encBytes = new Uint8Array(encrypted);
    let s = "";
    for (let i = 0; i < encBytes.length; i++) s += String.fromCharCode(encBytes[i]);
    encStr = s;
  }
  return btoa(ivStr) + ":" + btoa(encStr);
}

export async function decryptData(ciphertext, key) {
  const [ivStr, encStr] = ciphertext.split(":");
  const iv = Uint8Array.from(atob(ivStr), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(encStr), c => c.charCodeAt(0));
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: encoder.encode("salt"), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, data);
  return new TextDecoder().decode(decrypted);
}

// --- binary helpers ---
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  try {
    // Use latin1 text decoder to produce a binary string from bytes (avoids large apply/spread)
    const td = new TextDecoder('latin1');
    const binary = td.decode(bytes);
    return btoa(binary);
  } catch (e) {
    // Fallback: build string one char at a time
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
}

export function base64ToUint8Array(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
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

export function sanitizeFilename(name) {
  name = name.split("/").pop() || name;
  name = name.replace(/[^a-zA-Z0-9._()\[\] \-]+/g, "");
  return name || "file";
}

export function generateToken(len = 18) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
