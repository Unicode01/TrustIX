import { attachAdminProof, type AdminProofState } from "./auth";

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
