export type Role = "owner" | "admin" | "dispatcher" | "viewer";

let csrfToken: string | null = null;

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (method !== "GET" && method !== "HEAD") {
    headers.set("Content-Type", "application/json");
    if (!csrfToken) csrfToken = (await request<{ csrf_token: string }>("/api/v1/auth/csrf")).csrf_token;
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, { ...init, headers, credentials: "include" });
  const body = await response.json().catch(() => ({}));
  const replacement = response.headers.get("X-CSRF-Token");
  if (replacement) csrfToken = replacement;
  if (!response.ok) throw new ApiError(response.status, body.detail ?? "Request rejected");
  return body as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body: JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) => request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  put: <T>(path: string, body: unknown) => request<T>(path, { method: "PUT", body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  setCsrf: (value: string) => { csrfToken = value; }
};

export function readAndClearFragmentToken(): string {
  const token = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
  window.history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
  return decodeURIComponent(token);
}
