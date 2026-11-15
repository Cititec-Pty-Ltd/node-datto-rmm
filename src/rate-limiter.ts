/**
 * Rate limiting logic for the Datto RMM API
 *
 * Datto RMM enforces:
 * - 600 requests per 60-second rolling window
 * - At 540 requests (90%), API adds 1-second delays
 * - At 600+ requests, returns 429
 * - Persistent 429 violations result in 403 + 5-minute IP block
 */

import type { RateLimitConfig } from './config.js';
import { DattoRmmIpBlockedError } from './errors.js';

/**
 * Manages rate limiting for API requests
 */
export class RateLimiter {
  private readonly config: RateLimitConfig;
  private requestTimestamps: number[] = [];
  private ipBlockedUntil: number | null = null;
  private lastRateLimitedAt: number | null = null;

  constructor(config: RateLimitConfig) {
    this.config = config;
  }

  /**
   * Wait until it's safe to make a request
   * Throws if IP is currently blocked
   */
  async waitForSlot(): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    // Check if IP is currently blocked
    if (this.ipBlockedUntil !== null) {
      const now = Date.now();
      if (now < this.ipBlockedUntil) {
        const remainingMs = this.ipBlockedUntil - now;
        throw new DattoRmmIpBlockedError(
          `Datto RMM blocked this IP after rate-limit violations (HTTP 403 Forbidden); this request was not sent. ` +
            `Try again in ${Math.ceil(remainingMs / 1000)} s.`,
          remainingMs
        );
      }
      // Block has expired
      this.ipBlockedUntil = null;
    }

    // Clean up old timestamps
    this.pruneOldTimestamps();

    // Calculate current rate
    const currentRate = this.requestTimestamps.length / this.config.maxRequests;

    // If we're above the throttle threshold, add a delay
    if (currentRate >= this.config.throttleThreshold) {
      // Calculate delay based on how close we are to the limit
      const delayMs = Math.min(
        1000 * (currentRate - this.config.throttleThreshold + 0.1) * 10,
        5000
      );
      await this.sleep(delayMs);
    }

    // If we're at the limit, wait until the oldest request falls out of the window
    if (this.requestTimestamps.length >= this.config.maxRequests) {
      const oldestTimestamp = this.requestTimestamps[0];
      if (oldestTimestamp !== undefined) {
        const waitUntil = oldestTimestamp + this.config.windowMs;
        const waitTime = waitUntil - Date.now();
        if (waitTime > 0) {
          await this.sleep(waitTime);
        }
      }
    }
  }

  /**
   * Record that a request was made
   */
  recordRequest(): void {
    if (!this.config.enabled) {
      return;
    }
    this.requestTimestamps.push(Date.now());
  }

  /**
   * Handle a rate limit error (429)
   */
  handleRateLimitError(_retryCount: number): void {
    // Remembered so a 403 that follows soon after is read as an IP block.
    this.lastRateLimitedAt = Date.now();
  }

  /**
   * True when a 429 was seen within the IP-block cooldown. Datto answers 403
   * (IP blocked) when calls continue after a 429.
   */
  wasRecentlyRateLimited(): boolean {
    return this.lastRateLimitedAt !== null && Date.now() - this.lastRateLimitedAt < this.config.ipBlockCooldownMs;
  }

  /**
   * Forget the last 429 once a request succeeds: the API is answering again,
   * so a later 403 is an ordinary permission error, not proof of an IP block.
   */
  handleSuccess(): void {
    this.lastRateLimitedAt = null;
  }

  /**
   * Handle an IP block error (403)
   */
  handleIpBlock(): void {
    this.ipBlockedUntil = Date.now() + this.config.ipBlockCooldownMs;
  }

  /**
   * Get the current request rate as a fraction of the limit
   */
  getCurrentRate(): number {
    this.pruneOldTimestamps();
    return this.requestTimestamps.length / this.config.maxRequests;
  }

  /**
   * Get the number of requests remaining in the current window
   */
  getRemainingRequests(): number {
    this.pruneOldTimestamps();
    return Math.max(0, this.config.maxRequests - this.requestTimestamps.length);
  }

  /**
   * Check if the IP is currently blocked
   */
  isIpBlocked(): boolean {
    if (this.ipBlockedUntil === null) {
      return false;
    }
    if (Date.now() >= this.ipBlockedUntil) {
      this.ipBlockedUntil = null;
      return false;
    }
    return true;
  }

  /**
   * Calculate retry delay with exponential backoff
   */
  calculateRetryDelay(retryCount: number): number {
    return Math.min(
      this.config.retryAfterMs * Math.pow(2, retryCount),
      30000 // Max 30 seconds
    );
  }

  /**
   * Check if we should retry after a rate limit error.
   * HttpClient no longer retries a 429 (Datto blocks the IP when calls
   * continue after one); kept for API compatibility.
   */
  shouldRetry(retryCount: number): boolean {
    return retryCount < this.config.maxRetries;
  }

  /**
   * Remove timestamps older than the window
   */
  private pruneOldTimestamps(): void {
    const cutoff = Date.now() - this.config.windowMs;
    this.requestTimestamps = this.requestTimestamps.filter(ts => ts > cutoff);
  }

  /**
   * Sleep for a given duration
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
