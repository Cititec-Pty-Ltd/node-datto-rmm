/**
 * HttpClient response-handling tests.
 *
 * Regression: connectwise-automate-mcp#54 — every API-backed tool returned an
 * empty object (200 with a non-JSON body was swallowed as `{}`), and repeat
 * calls threw "Body is unusable: Body has already been read" (the error path
 * consumed the body with response.json() and then re-read it with
 * response.text() in the catch). The body must be read exactly once.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HttpClient, parseRetryAfterMs } from '../../src/http.js';
import { AuthManager } from '../../src/auth.js';
import { RateLimiter } from '../../src/rate-limiter.js';
import {
  DattoRmmError,
  DattoRmmForbiddenError,
  DattoRmmIpBlockedError,
  DattoRmmRateLimitError,
  DattoRmmNotFoundError,
  DattoRmmServerError,
} from '../../src/errors.js';
import { DEFAULT_RATE_LIMIT_CONFIG, type ResolvedConfig } from '../../src/config.js';

const config: ResolvedConfig = {
  apiUrl: 'https://merlot-api.centrastage.net',
  apiKey: 'test-api-key',
  apiSecretKey: 'test-api-secret',
  timestamps: 'date',
  rateLimit: { ...DEFAULT_RATE_LIMIT_CONFIG },
};

function makeClient(): HttpClient {
  const auth = {
    getToken: vi.fn().mockResolvedValue('test-token'),
    refreshToken: vi.fn().mockResolvedValue('test-token'),
  } as unknown as AuthManager;
  const limiter = new RateLimiter(config.rateLimit);
  return new HttpClient(config, auth, limiter);
}

/** A real Response so body semantics (one-shot stream) are exercised. */
function realResponse(body: string, init: ResponseInit = {}): Response {
  return new Response(body, {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

describe('HttpClient response handling', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('parses a JSON 200 response', async () => {
    vi.mocked(fetch).mockResolvedValue(realResponse('[{"uid":"abc"}]'));
    const result = await makeClient().request('/account/sites');
    expect(result).toEqual([{ uid: 'abc' }]);
  });

  it('parses JSON even when the content-type header is wrong', async () => {
    vi.mocked(fetch).mockResolvedValue(
      realResponse('{"uid":"abc"}', { headers: { 'content-type': 'text/plain' } })
    );
    const result = await makeClient().request('/site/abc');
    expect(result).toEqual({ uid: 'abc' });
  });

  it('returns {} for a genuinely empty 200/204 body', async () => {
    vi.mocked(fetch).mockResolvedValue(
      realResponse('', { status: 200, headers: { 'content-type': 'text/plain' } })
    );
    const result = await makeClient().request('/device/abc/quickjob', { method: 'PUT' });
    expect(result).toEqual({});
  });

  it('throws a descriptive error (not {}) for a 200 with a non-JSON body', async () => {
    vi.mocked(fetch).mockResolvedValue(
      realResponse('<html>WAF challenge page</html>', {
        headers: { 'content-type': 'text/html' },
      })
    );
    await expect(makeClient().request('/account/sites')).rejects.toThrow(
      /Expected JSON .* text\/html.*WAF challenge page/
    );
  });

  it('reads a non-JSON error body exactly once — no "Body is unusable"', async () => {
    vi.mocked(fetch).mockResolvedValue(
      realResponse('<html>gateway error</html>', {
        status: 404,
        headers: { 'content-type': 'text/html' },
      })
    );
    // Before the fix this threw TypeError "Body is unusable: Body has already
    // been read" instead of the typed not-found error carrying the real body.
    const err = await makeClient()
      .request('/site/missing')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DattoRmmNotFoundError);
    expect((err as DattoRmmNotFoundError).response).toContain('gateway error');
  });

  it('passes a parsed JSON error body to the typed error', async () => {
    // 5xx retries once, then throws — both responses must be fresh.
    vi.mocked(fetch).mockResolvedValueOnce(realResponse('{"message":"boom"}', { status: 503 }));
    vi.mocked(fetch).mockResolvedValueOnce(realResponse('{"message":"boom"}', { status: 503 }));
    const err = await makeClient()
      .request('/account/sites')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DattoRmmServerError);
    expect((err as DattoRmmServerError).response).toEqual({ message: 'boom' });
  }, 15000);

  it('generic non-2xx statuses raise DattoRmmError with the raw body', async () => {
    vi.mocked(fetch).mockResolvedValue(
      realResponse('teapot', { status: 418, headers: { 'content-type': 'text/plain' } })
    );
    const err = await makeClient()
      .request('/account/sites')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DattoRmmError);
    expect((err as DattoRmmError).response).toBe('teapot');
  });

  describe('403 detail surfacing (regression: Zinfandel-platform investigation)', () => {
    // A bare "Access forbidden" — the pre-fix message — hid whether Datto
    // returned a permission-denied, wrong-platform, or account-suspended
    // reason. Callers that only read `.message` (not the typed error's
    // `.response`) need Datto's real reason inline.

    it('embeds the JSON body\'s `message` field in the thrown error message', async () => {
      vi.mocked(fetch).mockResolvedValue(
        realResponse(JSON.stringify({ message: 'Account is suspended' }), { status: 403 })
      );
      const err = await makeClient()
        .request('/account/sites')
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DattoRmmForbiddenError);
      expect((err as DattoRmmForbiddenError).message).toContain('Account is suspended');
      expect((err as DattoRmmForbiddenError).message).toContain('403');
    });

    it('falls back to a JSON dump when the body has no message/error/detail field', async () => {
      vi.mocked(fetch).mockResolvedValue(
        realResponse(JSON.stringify({ code: 'PLATFORM_MISMATCH' }), { status: 403 })
      );
      const err = await makeClient()
        .request('/account/sites')
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DattoRmmForbiddenError);
      expect((err as DattoRmmForbiddenError).message).toContain('PLATFORM_MISMATCH');
    });

    it('embeds a non-JSON error body verbatim (truncated)', async () => {
      vi.mocked(fetch).mockResolvedValue(
        realResponse('Forbidden by upstream WAF', {
          status: 403,
          headers: { 'content-type': 'text/plain' },
        })
      );
      const err = await makeClient()
        .request('/account/sites')
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(DattoRmmForbiddenError);
      expect((err as DattoRmmForbiddenError).message).toContain('Forbidden by upstream WAF');
    });

    it('still classifies an IP-block 403 as DattoRmmIpBlockedError, not ForbiddenError', async () => {
      vi.mocked(fetch).mockResolvedValue(
        realResponse(JSON.stringify({ message: 'Your IP has been blocked due to rate limits' }), {
          status: 403,
        })
      );
      const err = await makeClient()
        .request('/account/sites')
        .catch((e: unknown) => e);
      expect(err).not.toBeInstanceOf(DattoRmmForbiddenError);
      expect((err as { name: string }).name).toBe('DattoRmmIpBlockedError');
    });
  });
});

describe('HttpClient rate-limit handling (429 is never retried)', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function limited(retryAfter?: string): Response {
    return realResponse(JSON.stringify({ message: 'Too Many Requests' }), {
      status: 429,
      headers: { 'content-type': 'application/json', ...(retryAfter ? { 'retry-after': retryAfter } : {}) },
    });
  }

  it('does not retry a 429 and reports HTTP 429 with Retry-After', async () => {
    vi.mocked(fetch).mockResolvedValue(limited('42'));
    const err = await makeClient()
      .request('/account/sites')
      .catch((e: unknown) => e);

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(err).toBeInstanceOf(DattoRmmRateLimitError);
    expect((err as DattoRmmRateLimitError).message).toMatch(/HTTP 429.*Try again in 42 s\./);
    expect((err as DattoRmmRateLimitError).retryAfter).toBe(42_000);
  });

  it('reports 60 s when the 429 has no Retry-After', async () => {
    vi.mocked(fetch).mockResolvedValue(limited());
    const err = await makeClient()
      .request('/account/sites')
      .catch((e: unknown) => e);

    expect(fetch).toHaveBeenCalledTimes(1);
    expect((err as Error).message).toMatch(/HTTP 429.*Try again in 60 s\./);
  });

  it('reads a 403 after a 429 as an IP block, then refuses locally', async () => {
    const client = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(limited('5'));
    await client.request('/account/sites').catch(() => undefined);

    vi.mocked(fetch).mockResolvedValueOnce(
      realResponse(JSON.stringify({ message: 'Forbidden' }), { status: 403 })
    );
    const blocked = await client.request('/account/sites').catch((e: unknown) => e);
    expect(blocked).toBeInstanceOf(DattoRmmIpBlockedError);
    expect((blocked as Error).message).toMatch(/HTTP 403.*Try again in 300 s\./);

    const refused = await client.request('/account/sites').catch((e: unknown) => e);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(refused).toBeInstanceOf(DattoRmmIpBlockedError);
    expect((refused as Error).message).toMatch(/HTTP 403.*not sent.*Try again in \d+ s\./);
  });

  it('does not treat a rejected 2xx (HTML challenge) after a 429 as recovery', async () => {
    const client = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(limited('5'));
    await client.request('/account/sites').catch(() => undefined);

    vi.mocked(fetch).mockResolvedValueOnce(
      new Response('<html>challenge</html>', { status: 200, headers: { 'content-type': 'text/html' } })
    );
    const challenge = await client.request('/account/sites').catch((e: unknown) => e);
    expect(challenge).toBeInstanceOf(DattoRmmError);

    vi.mocked(fetch).mockResolvedValueOnce(
      realResponse(JSON.stringify({ message: 'Forbidden' }), { status: 403 })
    );
    const blocked = await client.request('/account/sites').catch((e: unknown) => e);
    expect(blocked).toBeInstanceOf(DattoRmmIpBlockedError);
  });

  it('does not let an older request that succeeds late clear a newer 429', async () => {
    const client = makeClient();
    let finishOlder: (res: Response) => void = () => undefined;
    vi.mocked(fetch).mockImplementationOnce(
      () => new Promise<Response>((resolve) => (finishOlder = resolve))
    );
    const older = client.request('/account/sites');
    // Let the older request reach fetch() before the newer one is answered.
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));

    vi.mocked(fetch).mockResolvedValueOnce(limited('5'));
    await client.request('/account/devices').catch(() => undefined);

    finishOlder(realResponse('[]'));
    await expect(older).resolves.toEqual([]);

    vi.mocked(fetch).mockResolvedValueOnce(
      realResponse(JSON.stringify({ message: 'Forbidden' }), { status: 403 })
    );
    const blocked = await client.request('/account/sites').catch((e: unknown) => e);
    expect(blocked).toBeInstanceOf(DattoRmmIpBlockedError);
  });

  it('treats a 403 after 429 then 200 as a plain permission error, not an IP block', async () => {
    const client = makeClient();
    vi.mocked(fetch).mockResolvedValueOnce(limited('5'));
    await client.request('/account/sites').catch(() => undefined);

    vi.mocked(fetch).mockResolvedValueOnce(realResponse('[]'));
    await expect(client.request('/account/sites')).resolves.toEqual([]);

    vi.mocked(fetch).mockResolvedValueOnce(
      realResponse(JSON.stringify({ message: 'No access to this site' }), { status: 403 })
    );
    const err = await client.request('/account/sites').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DattoRmmForbiddenError);

    // No local block: the next request is sent.
    vi.mocked(fetch).mockResolvedValueOnce(realResponse('[]'));
    await expect(client.request('/account/sites')).resolves.toEqual([]);
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it('keeps a plain 403 without a recent 429 as DattoRmmForbiddenError', async () => {
    vi.mocked(fetch).mockResolvedValue(realResponse(JSON.stringify({ message: 'No access' }), { status: 403 }));
    const err = await makeClient()
      .request('/account/sites')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DattoRmmForbiddenError);
  });
});

describe('parseRetryAfterMs', () => {
  it('reads seconds and HTTP dates, ignores junk', () => {
    const now = Date.parse('2026-01-01T00:00:00Z');
    expect(parseRetryAfterMs('5', now)).toBe(5000);
    expect(parseRetryAfterMs('Thu, 01 Jan 2026 00:00:07 GMT', now)).toBe(7000);
    expect(parseRetryAfterMs(null, now)).toBeUndefined();
    expect(parseRetryAfterMs('soon', now)).toBeUndefined();
    expect(parseRetryAfterMs('-3', now)).toBeUndefined();
  });
});
