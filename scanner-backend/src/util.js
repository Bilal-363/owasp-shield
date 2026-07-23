const USER_AGENT =
  'OWASP-Shield-Desk-Scanner/1.0 (+https://github.com/owasp-shield-desk; authorized-testing-only)';

/**
 * fetch() with a hard timeout and sane defaults for scanning.
 * Never throws on HTTP status codes — only on network/timeout errors.
 */
export async function httpRequest(url, { method = 'GET', timeout = 10000, redirect = 'follow', headers = {} } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      method,
      redirect,
      signal: controller.signal,
      headers: { 'User-Agent': USER_AGENT, ...headers },
    });
    return res;
  } finally {
    clearTimeout(t);
  }
}

/** Read a bounded amount of a response body (avoids huge downloads). */
export async function readBodyCapped(res, maxBytes = 512 * 1024) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    try {
      return (await res.text()).slice(0, maxBytes);
    } catch {
      return '';
    }
  }
  const chunks = [];
  let total = 0;
  const decoder = new TextDecoder();
  let out = '';
  while (total < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    out += decoder.decode(value, { stream: true });
  }
  try {
    await reader.cancel();
  } catch {
    /* ignore */
  }
  return out;
}

/** Run async tasks with a concurrency cap. */
export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      try {
        results[idx] = await fn(items[idx], idx);
      } catch (e) {
        results[idx] = { error: e };
      }
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

export const SEVERITY = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};
