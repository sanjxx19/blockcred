export class ApiError extends Error {
  constructor(status, body) {
    super(body?.message || body?.error || `Request failed (HTTP ${status})`);
    this.status = status;
    this.code = body?.error;
  }
}

/** Same-origin JSON client. The session lives in an HttpOnly cookie. */
export async function api(path, { method = 'GET', body, raw = false, headers = {} } = {}) {
  const init = { method, headers: { ...headers }, credentials: 'same-origin' };
  if (body !== undefined) {
    if (raw) init.body = body;
    else {
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
  }
  const res = await fetch(`/api${path}`, init);
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { message: text };
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}
