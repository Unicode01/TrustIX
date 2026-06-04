import type { Bootstrap } from "./types";

const ADMIN_PROOF_SESSION_KEY = "trustix.adminProof.v1";

export type AdminProofState = {
  certDERBase64: string;
  key: CryptoKey | null;
  ready: boolean;
  message: string;
  certName: string;
  keyName: string;
};

type StoredAdminProof = {
  certPEM: string;
  keyPEM: string;
  certName?: string;
  keyName?: string;
};

export function emptyAdminProof(): AdminProofState {
  return {
    certDERBase64: "",
    key: null,
    ready: false,
    message: "",
    certName: "",
    keyName: "",
  };
}

export function requiresAdminProof(bootstrap: Bootstrap): boolean {
  return bootstrap.require_admin_proof === true || bootstrap.admin_read_auth_enabled === true;
}

export async function loadAdminProofMaterial(certPEM: string, keyPEM: string, certName = "", keyName = ""): Promise<AdminProofState> {
  if (!window.crypto?.subtle) {
    throw new Error("Browser crypto is unavailable");
  }
  const certBytes = pemToBytes(certPEM, "CERTIFICATE");
  const keyBytes = pemToBytes(keyPEM, "PRIVATE KEY");
  const key = await crypto.subtle.importKey(
    "pkcs8",
    bufferSource(keyBytes),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  return {
    certDERBase64: bytesToBase64(certBytes),
    key,
    ready: true,
    message: "",
    certName,
    keyName,
  };
}

export function hasStoredAdminProof(): boolean {
	return readStoredAdminProof() !== null;
}

export function readStoredAdminProof(): StoredAdminProof | null {
	return readAdminProofFromStorage(storage("sessionStorage"), ADMIN_PROOF_SESSION_KEY);
}

export function rememberAdminProof(certPEM: string, keyPEM: string, certName: string, keyName: string): void {
	const payload = JSON.stringify({ certPEM, keyPEM, certName, keyName });
	try {
		sessionStorage.setItem(ADMIN_PROOF_SESSION_KEY, payload);
	} catch (_error) {
    // Session storage is a convenience only.
  }
}

export function forgetStoredAdminProof(): void {
	try {
		sessionStorage.removeItem(ADMIN_PROOF_SESSION_KEY);
	} catch (_error) {
    // Ignore storage cleanup failures.
  }
}

export async function attachAdminProof(url: string, options: RequestInit, proof: AdminProofState): Promise<void> {
  if (!proof.ready || !proof.key) {
    return;
  }
  const method = String(options.method || "GET").toUpperCase();
  const bodyBytes = requestBodyBytes(options.body);
  const timestamp = new Date().toISOString();
  const bodyHash = await sha256Hex(bodyBytes);
  const requestURI = requestURIForSignature(url);
  const signingPayload = ["TRUSTIX-ADMIN-V1", method, requestURI, timestamp, bodyHash].join("\n");
  const rawSignature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    proof.key,
    new TextEncoder().encode(signingPayload),
  ));
  const headers = new Headers(options.headers || {});
  headers.set("X-TrustIX-Admin-Cert", proof.certDERBase64);
  headers.set("X-TrustIX-Admin-Timestamp", timestamp);
  headers.set("X-TrustIX-Admin-Signature", bytesToBase64(ecdsaSignatureToDER(rawSignature)));
	options.headers = headers;
}

function storage(name: "localStorage" | "sessionStorage"): Storage | null {
	try {
		return window[name];
  } catch (_error) {
    return null;
  }
}

function readAdminProofFromStorage(storage: Storage | null, key: string): StoredAdminProof | null {
  if (!storage) {
    return null;
  }
  try {
    const raw = storage.getItem(key);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as Partial<StoredAdminProof>;
    if (typeof parsed.certPEM !== "string" || typeof parsed.keyPEM !== "string") {
      return null;
    }
    return {
      certPEM: parsed.certPEM,
      keyPEM: parsed.keyPEM,
      certName: typeof parsed.certName === "string" ? parsed.certName : "",
      keyName: typeof parsed.keyName === "string" ? parsed.keyName : "",
    };
  } catch (_error) {
    return null;
  }
}

function requestURIForSignature(url: string): string {
  const parsed = new URL(url, window.location.origin);
  return `${parsed.pathname}${parsed.search}`;
}

function requestBodyBytes(body: BodyInit | null | undefined): Uint8Array {
  if (body == null) {
    return new Uint8Array();
  }
  if (typeof body === "string") {
    return new TextEncoder().encode(body);
  }
  if (body instanceof Uint8Array) {
    return body;
  }
  if (body instanceof ArrayBuffer) {
    return new Uint8Array(body);
  }
  if (body instanceof URLSearchParams) {
    return new TextEncoder().encode(body.toString());
  }
  return new TextEncoder().encode(String(body));
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bufferSource(bytes)));
  return Array.from(digest).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function pemToBytes(pem: string, label: string): Uint8Array {
  const pattern = new RegExp(`-----BEGIN ${label}-----([\\s\\S]+?)-----END ${label}-----`);
  const match = String(pem || "").match(pattern);
  if (!match) {
    throw new Error(`${label} PEM block is required`);
  }
  const base64 = match[1].replace(/\s+/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    const chunk = bytes.subarray(offset, offset + 0x8000);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function bufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function ecdsaSignatureToDER(signature: Uint8Array): Uint8Array {
  if (signature[0] === 0x30) {
    return signature;
  }
  const half = signature.length / 2;
  const r = derInteger(signature.slice(0, half));
  const s = derInteger(signature.slice(half));
  const length = 2 + r.length + 2 + s.length;
  return new Uint8Array([0x30, length, 0x02, r.length, ...r, 0x02, s.length, ...s]);
}

function derInteger(bytes: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset < bytes.length - 1 && bytes[offset] === 0) {
    offset += 1;
  }
  let value = bytes.slice(offset);
  if (value[0] & 0x80) {
    const prefixed = new Uint8Array(value.length + 1);
    prefixed.set(value, 1);
    value = prefixed;
  }
  return value;
}
