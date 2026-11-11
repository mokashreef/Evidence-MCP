export interface HttpPostOptions {
  url: string;
  body: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export interface HttpPostResult {
  ok: boolean;
  statusCode?: number;
  statusText?: string;
  responseBody?: string;
  durationMs: number;
  error?: string;
}

/**
 * Validates that a target endpoint uses strict http: or https: protocol.
 */
export function validateHttpUrl(rawUrl: string): URL {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`URL must use http: or https: protocol (received "${parsed.protocol}").`);
  }
  return parsed;
}

/**
 * Dispatches an HTTP POST request with JSON payload and strict AbortController timeout bounds.
 */
export async function postJsonWithTimeout(options: HttpPostOptions): Promise<HttpPostResult> {
  const { url, body, headers = {}, timeoutMs = 10000 } = options;
  const startTime = Date.now();

  try {
    validateHttpUrl(url);
  } catch (err: unknown) {
    return {
      ok: false,
      durationMs: Date.now() - startTime,
      error: `Invalid URL: ${(err as Error).message}`,
    };
  }

  const controller = new AbortController();
  const timeoutTimer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Evidence-MCP/1.3.0',
        ...headers,
      },
      body,
      signal: controller.signal,
    });

    clearTimeout(timeoutTimer);
    const durationMs = Date.now() - startTime;
    const responseBody = await response.text();

    return {
      ok: response.ok,
      statusCode: response.status,
      statusText: response.statusText,
      responseBody,
      durationMs,
      error: response.ok ? undefined : `HTTP error: ${response.status} ${response.statusText}`,
    };
  } catch (err: unknown) {
    clearTimeout(timeoutTimer);
    const durationMs = Date.now() - startTime;
    const isAbort = (err as Error).name === 'AbortError';
    return {
      ok: false,
      durationMs,
      error: isAbort
        ? `Request timed out after ${timeoutMs}ms.`
        : `Network error: ${(err as Error).message}`,
    };
  }
}
