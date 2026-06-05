import { attachAdminProof, type AdminProofState } from "./auth";

export type DownloadResponse = {
  blob: Blob;
  filename: string;
};

export class APIClient {
  private readonly base: string;
  private readonly getProof: () => AdminProofState;

  constructor(base: string, getProof: () => AdminProofState) {
    this.base = base;
    this.getProof = getProof;
  }

  path(path: string): string {
    const suffix = String(path || "");
    return `${this.base}${suffix.startsWith("/") ? suffix : `/${suffix}`}`;
  }

  async getJSON<T>(path: string): Promise<T> {
    return this.requestJSON<T>(this.path(path), { method: "GET", cache: "no-cache" });
  }

  async postJSON<T>(path: string, body: string, contentType = "application/json; charset=utf-8"): Promise<T> {
    return this.requestJSON<T>(this.path(path), {
      method: "POST",
      cache: "no-cache",
      headers: { "Content-Type": contentType },
      body,
    });
  }

  async postBlob(path: string, body: string, contentType = "application/json; charset=utf-8"): Promise<DownloadResponse> {
    const url = this.path(path);
    const requestOptions: RequestInit = {
      method: "POST",
      cache: "no-cache",
      headers: new Headers({ "Content-Type": contentType }),
      body,
    };
    await attachAdminProof(url, requestOptions, this.getProof());
    const response = await fetch(url, requestOptions);
    if (!response.ok) {
      const text = await response.text();
      let message = text || response.statusText;
      try {
        const payload = JSON.parse(text) as { error?: unknown };
        message = String(payload.error || message);
      } catch (_error) {
        // Leave non-JSON error bodies as-is.
      }
      throw new Error(message || `HTTP ${response.status}`);
    }
    return {
      blob: await response.blob(),
      filename: contentDispositionFilename(response.headers.get("Content-Disposition")) || "trustix-config-export.tar.gz",
    };
  }

  async postBinaryJSON<T>(path: string, body: Uint8Array, contentType: string): Promise<T> {
    const upload = new ArrayBuffer(body.byteLength);
    new Uint8Array(upload).set(body);
    return this.requestJSON<T>(this.path(path), {
      method: "POST",
      cache: "no-cache",
      headers: { "Content-Type": contentType },
      body: upload,
    });
  }

  async requestJSON<T>(url: string, options: RequestInit): Promise<T> {
    const requestOptions: RequestInit = { ...options, headers: new Headers(options.headers || {}) };
    await attachAdminProof(url, requestOptions, this.getProof());
    const response = await fetch(url, requestOptions);
    const text = await response.text();
    let payload: unknown = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch (_error) {
        payload = text;
      }
    }
    if (!response.ok) {
      const message = payload && typeof payload === "object" && "error" in payload
        ? String((payload as { error?: unknown }).error || "")
        : typeof payload === "string"
          ? payload
          : response.statusText;
      throw new Error(message || `HTTP ${response.status}`);
    }
    return payload as T;
  }
}

function contentDispositionFilename(value: string | null): string {
  const header = String(value || "").trim();
  if (!header) {
    return "";
  }
  const match = /filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i.exec(header);
  const raw = match?.[1] || match?.[2] || "";
  if (!raw) {
    return "";
  }
  try {
    return decodeURIComponent(raw).replace(/[\\/]/g, "_");
  } catch (_error) {
    return raw.replace(/[\\/]/g, "_");
  }
}
