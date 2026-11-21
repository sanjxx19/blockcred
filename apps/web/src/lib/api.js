export class ApiError extends Error {
  constructor(status, body) {
    super(body?.message || body?.error || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

/** fetch wrapper: JSON in/out, bearer auth, useful errors. */
export async function api(base, path, { method = 'GET', body, apiKey, headers = {}, raw = false } = {}) {
  const init = { method, headers: { ...headers } };
  if (apiKey) init.headers.authorization = `Bearer ${apiKey}`;
  if (body !== undefined) {
    if (raw) {
      init.body = body;
    } else {
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
  }
  const res = await fetch(`${base}${path}`, init);
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { message: text };
  }
  if (!res.ok && !(res.status === 422 && data?.verdict)) throw new ApiError(res.status, data);
  return data;
}
