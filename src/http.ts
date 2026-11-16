/**
 * HTTP layer for the Datto RMM API
 */

import type { ResolvedConfig } from './config.js';
import type { AuthManager } from './auth.js';
import type { RateLimiter } from './rate-limiter.js';
import { summarizeErrorBody } from './error-detail.js';
import {
  DattoRmmError,
  DattoRmmAuthenticationError,
  DattoRmmNotFoundError,
  DattoRmmRateLimitError,
  DattoRmmIpBlockedError,
  DattoRmmForbiddenError,
  DattoRmmServerError,
} from './errors.js';

/** Wait reported for a 429 without Retry-After: Datto counts requests over a rolling 60 s window. */
const DEFAULT_RATE_LIMIT_WAIT_MS = 60_000;

/** Parses a Retry-After header (seconds or HTTP date) into milliseconds; undefined if absent or invalid. */
export function parseRetryAfterMs(value: string | null, now: number = Date.now()): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();
  if (/^\d+(\.\d+)?$/.test(trimmed)) return Math.ceil(Number(trimmed) * 1000);
  if (!/[a-z]/i.test(trimmed)) return undefined;
  const date = Date.parse(trimmed);
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}

/**
 * HTTP request options
 */
export interface RequestOptions {
  /** HTTP method */
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Request body (will be JSON stringified) */
  body?: unknown;
  /** URL query parameters */
  params?: Record<string, string | number | boolean | undefined>;
  /** Skip authentication (for token endpoint) */
  skipAuth?: boolean;
}

/**
 * HTTP client for making authenticated requests to the Datto RMM API
 */
export class HttpClient {
  private readonly config: ResolvedConfig;
  private readonly authManager: AuthManager;
  private readonly rateLimiter: RateLimiter;

  constructor(config: ResolvedConfig, authManager: AuthManager, rateLimiter: RateLimiter) {
    this.config = config;
    this.authManager = authManager;
    this.rateLimiter = rateLimiter;
  }

  /**
   * Make an authenticated request to the API
   */
  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const { method = 'GET', body, params, skipAuth = false } = options;

    // Build the URL
    let url = `${this.config.apiUrl}/api/v2${path}`;
    if (params) {
      const searchParams = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined) {
          searchParams.append(key, String(value));
        }
      }
      const queryString = searchParams.toString();
      if (queryString) {
        url += `?${queryString}`;
      }
    }

    return this.executeRequest<T>(url, method, body, skipAuth);
  }

  /**
   * Make a request to a full URL (for pagination)
   */
  async requestUrl<T>(url: string): Promise<T> {
    return this.executeRequest<T>(url, 'GET', undefined, false);
  }

  /**
   * Execute the request with retry logic
   */
  private async executeRequest<T>(
    url: string,
    method: string,
    body: unknown,
    skipAuth: boolean,
    retryCount: number = 0,
    isRetryAfter401: boolean = false
  ): Promise<T> {
    // Wait for a rate limit slot
    await this.rateLimiter.waitForSlot();

    // Get the auth token
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (!skipAuth) {
      const token = await this.authManager.getToken();
      headers['Authorization'] = `Bearer ${token}`;
    }

    // Record the request
    this.rateLimiter.recordRequest();
    // A success only clears the recent-429 marker if no 429 arrived after
    // this request was sent.
    const rateLimitGeneration = this.rateLimiter.currentRateLimitGeneration();

    // Make the request
    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    // Handle the response
    return this.handleResponse<T>(
      response,
      url,
      method,
      body,
      skipAuth,
      retryCount,
      isRetryAfter401,
      rateLimitGeneration
    );
  }

  /**
   * Handle the response and errors
   */
  private async handleResponse<T>(
    response: Response,
    url: string,
    method: string,
    body: unknown,
    skipAuth: boolean,
    retryCount: number,
    isRetryAfter401: boolean,
    rateLimitGeneration: number
  ): Promise<T> {
    // Read the body EXACTLY once, as text, for every path. A fetch Response
    // body is a one-shot stream: response.json() followed by response.text()
    // in a catch throws "Body is unusable: Body has already been read",
    // which masked the real (often non-JSON, e.g. WAF/proxy HTML) response
    // (connectwise-automate-mcp#54).
    const rawBody = await response.text();
    let parsedBody: unknown;
    let bodyIsJson = false;
    try {
      parsedBody = JSON.parse(rawBody);
      bodyIsJson = true;
    } catch {
      parsedBody = rawBody;
    }

    if (response.ok) {
      // Only a response we accept marks recovery from a 429. A 2xx that is
      // rejected below (an HTML challenge or login page) does not.
      if (bodyIsJson) {
        this.rateLimiter.handleSuccess(rateLimitGeneration);
        return parsedBody as T;
      }
      if (rawBody.trim() === '') {
        // Genuinely empty 200/204 — preserve the historical empty-object shape.
        this.rateLimiter.handleSuccess(rateLimitGeneration);
        return {} as T;
      }
      // A 200 whose body isn't JSON is not a success we can use (login pages,
      // WAF challenges, proxy errors). Surfacing it beats returning {} and
      // letting the caller believe the API answered.
      throw new DattoRmmError(
        `Expected JSON from ${method} ${url} but got ${
          response.headers.get('content-type') ?? 'no content-type'
        }: ${rawBody.slice(0, 200)}`,
        response.status,
        rawBody.slice(0, 2000)
      );
    }

    const responseBody: unknown = parsedBody;
    const detail = summarizeErrorBody(responseBody);

    switch (response.status) {
      case 400:
        throw new DattoRmmAuthenticationError(
          `Bad request (400) - invalid credentials or parameters: ${detail}`,
          400,
          responseBody
        );

      case 401:
        // If this is already a retry after 401, don't retry again
        if (isRetryAfter401) {
          throw new DattoRmmAuthenticationError(
            `Authentication failed after token refresh (401): ${detail}`,
            401,
            responseBody
          );
        }
        // Try to refresh the token and retry once
        await this.authManager.refreshToken();
        return this.executeRequest<T>(url, method, body, skipAuth, retryCount, true);

      case 403:
        // Distinguish between IP block (rate limit) and permission denied.
        // Datto blocks the source IP with a 403 when calls continue after a
        // 429, so a 403 shortly after a 429 is treated as that block too.
        if (this.isIpBlockResponse(responseBody) || this.rateLimiter.wasRecentlyRateLimited()) {
          this.rateLimiter.handleIpBlock();
          const cooldownMs = this.config.rateLimit.ipBlockCooldownMs;
          throw new DattoRmmIpBlockedError(
            `Datto RMM blocked this IP after rate-limit violations (HTTP 403 Forbidden). ` +
              `Try again in ${Math.ceil(cooldownMs / 1000)} s. Detail: ${detail}`,
            cooldownMs,
            responseBody
          );
        }
        // Datto's own reason (wrong platform/region, missing scope, suspended
        // account, ...) lives in `detail` — a bare "Access forbidden" hides
        // exactly the information needed to tell those causes apart (the gap
        // that stalled the Zinfandel-platform investigation, msg-1788213394271).
        throw new DattoRmmForbiddenError(`Access forbidden (403): ${detail}`, responseBody);

      case 404:
        throw new DattoRmmNotFoundError(`Resource not found (404): ${detail}`, responseBody);

      case 429: {
        // Never retried. Datto blocks the source IP (403, about 5 minutes)
        // when requests continue after a 429, so the only safe move is to
        // stop and report how long to wait.
        this.rateLimiter.handleRateLimitError(retryCount);
        const retryAfterMs = parseRetryAfterMs(response.headers.get('retry-after')) ?? DEFAULT_RATE_LIMIT_WAIT_MS;
        throw new DattoRmmRateLimitError(
          `Datto RMM rate-limited the request (HTTP 429 Too Many Requests). Not retried: continuing after a 429 ` +
            `gets this IP blocked (HTTP 403). Try again in ${Math.max(1, Math.ceil(retryAfterMs / 1000))} s. ` +
            `Detail: ${detail}`,
          retryAfterMs,
          responseBody
        );
      }

      default:
        if (response.status >= 500) {
          // Server error - retry once
          if (retryCount === 0) {
            await this.sleep(1000);
            return this.executeRequest<T>(url, method, body, skipAuth, 1, isRetryAfter401);
          }
          throw new DattoRmmServerError(
            `Server error: ${response.status} ${response.statusText}: ${detail}`,
            response.status,
            responseBody
          );
        }
        throw new DattoRmmError(
          `Request failed: ${response.status} ${response.statusText}: ${detail}`,
          response.status,
          responseBody
        );
    }
  }

  /**
   * Check if a 403 response indicates an IP block
   */
  private isIpBlockResponse(responseBody: unknown): boolean {
    // Datto RMM typically returns specific error messages for IP blocks
    // This is a heuristic check
    if (typeof responseBody === 'object' && responseBody !== null) {
      const body = responseBody as Record<string, unknown>;
      const message = body['message'] ?? body['error'] ?? '';
      if (typeof message === 'string') {
        return message.toLowerCase().includes('rate') || message.toLowerCase().includes('blocked');
      }
    }
    return false;
  }

  /**
   * Sleep for a given duration
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
