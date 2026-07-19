// Client-side API helper. This UI carries no server-side session: it logs in
// through /auth/login and calls the JSON API with the resulting device token,
// exactly like the old single-file admin.html did.

const TOKEN_KEY = "apicorex_admin_token";
const CORE_URL_KEY = "apicorex_core_url";

// Core's gateway base URL. Same-origin by default (this page is served through
// Core's proxy); override by opening ?core=http://localhost:8080. The chosen
// value is remembered in localStorage so it survives navigation/reloads.
export function coreURL(): string {
  if (typeof window === "undefined") return "";
  const params = new URLSearchParams(window.location.search);
  const fromParam = params.get("core");
  if (fromParam) {
    localStorage.setItem(CORE_URL_KEY, fromParam);
    return fromParam;
  }
  return localStorage.getItem(CORE_URL_KEY) || "";
}

export function token(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(TOKEN_KEY) || "";
}
export function setToken(t: string): void {
  localStorage.setItem(TOKEN_KEY, t);
}
export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export interface ApiOptions extends Omit<RequestInit, "headers"> {
  headers?: Record<string, string>;
}

export async function api<T = any>(path: string, opts: ApiOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  const t = token();
  if (t) headers["Authorization"] = "Bearer " + t;

  const res = await fetch(coreURL() + path, { ...opts, headers });
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    /* no body */
  }
  if (!res.ok) {
    const msg = body && body.error ? body.error : `request failed (${res.status})`;
    throw new Error(msg);
  }
  return body as T;
}

// download fetches a binary/text endpoint with auth and saves it as a file.
// Used for DB backups, which stream a .sql attachment and can't go through a
// plain <a href> (they need the Authorization header).
export async function download(path: string): Promise<void> {
  const headers: Record<string, string> = {};
  const t = token();
  if (t) headers["Authorization"] = "Bearer " + t;

  const res = await fetch(coreURL() + path, { headers });
  if (!res.ok) {
    let msg = `request failed (${res.status})`;
    try {
      const b = await res.json();
      if (b && b.error) msg = b.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(msg);
  }
  // A streamed dump can still fail mid-flight; the server signals that via a
  // trailer-ish response header instead of the body.
  const backupErr = res.headers.get("X-Backup-Error");
  if (backupErr) throw new Error(backupErr);

  const cd = res.headers.get("Content-Disposition") || "";
  const match = cd.match(/filename="([^"]+)"/);
  const filename = match ? match[1] : "backup.sql";

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// upload POSTs a File as multipart form field "file" with auth. Used to restore
// a DB dump.
export async function upload<T = any>(path: string, file: File): Promise<T> {
  const headers: Record<string, string> = {};
  const t = token();
  if (t) headers["Authorization"] = "Bearer " + t;

  const form = new FormData();
  form.append("file", file);

  const res = await fetch(coreURL() + path, {
    method: "POST",
    headers, // don't set Content-Type — the browser adds the multipart boundary
    body: form,
  });
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    /* no body */
  }
  if (!res.ok) {
    const msg = body && body.error ? body.error : `request failed (${res.status})`;
    throw new Error(msg);
  }
  return body as T;
}
