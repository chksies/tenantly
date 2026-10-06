import { randomUUID } from 'node:crypto';
import { Redis } from 'ioredis';

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  /** Requests left in the current window after this one (0 when denied). */
  remaining: number;
  /** Milliseconds until the oldest counted request leaves the window, i.e. until a slot frees up. */
  resetMs: number;
}

/** Anything that can answer "may this key make another request?" atomically. */
export interface RateLimitStore {
  hit(key: string, limit: number, windowMs: number): Promise<RateLimitDecision>;
}

/**
 * The braces are a Redis Cluster hash tag: every key for one tenant lands in the same slot, so this
 * (and any future per-tenant key, e.g. a second limiter for expensive endpoints) stays single-slot.
 */
export const rateLimitKey = (tenantId: string) => `rl:{${tenantId}}:requests`;

/**
 * Sliding-window LOG. Each allowed request is a member of a sorted set scored by its timestamp, so
 * "how many requests in the last W ms" is exact: there is no fixed-window boundary burst where a
 * client gets 2x the limit by straddling the reset.
 *
 * It runs as one Lua script because the read-check-write must be atomic: with separate commands two
 * app servers could both see count = limit - 1 and both admit a request. Redis runs scripts
 * single-threaded, so the check and the insert cannot interleave with another client.
 *
 * Details that matter:
 * - The clock is Redis's own (TIME), not the app server's, so skewed app servers can't disagree
 *   about where the window starts. (TIME followed by a write inside a script needs Redis >= 5.)
 * - Denied requests are NOT recorded. Memory per tenant is bounded by the limit, and a client that
 *   keeps hammering while throttled doesn't extend its own penalty: it recovers as soon as its
 *   oldest allowed request ages out.
 * - Every key gets a PEXPIRE of one window, so idle tenants cost nothing.
 * - The member is unique per request (the caller supplies a UUID); two requests in the same
 *   millisecond must not collapse into one sorted-set entry.
 *
 * Returns { allowed, remaining, resetMs }.
 */
export const SLIDING_WINDOW_LUA = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local member = ARGV[3]

local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)

local allowed = 0
if count < limit then
  redis.call('ZADD', key, now, member)
  redis.call('PEXPIRE', key, window)
  count = count + 1
  allowed = 1
end

local reset = window
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
if oldest[2] then
  reset = tonumber(oldest[2]) + window - now
end
if reset < 0 then reset = 0 end

return { allowed, limit - count, reset }
`;

type SlidingWindowClient = Redis & {
  slidingWindow(key: string, limit: number, windowMs: number, member: string): Promise<[number, number, number]>;
};

export class RedisSlidingWindowStore implements RateLimitStore {
  private readonly redis: SlidingWindowClient;

  constructor(redis: Redis) {
    // defineCommand sends EVALSHA and transparently falls back to EVAL (loading the script) on NOSCRIPT.
    redis.defineCommand('slidingWindow', { numberOfKeys: 1, lua: SLIDING_WINDOW_LUA });
    this.redis = redis as SlidingWindowClient;
  }

  async hit(key: string, limit: number, windowMs: number): Promise<RateLimitDecision> {
    const [allowed, remaining, resetMs] = await this.redis.slidingWindow(key, limit, windowMs, randomUUID());
    return { allowed: allowed === 1, limit, remaining, resetMs };
  }
}

export interface RedisOptions {
  url: string;
  /** Per-command deadline. Past it the limiter fails open instead of stalling the request. */
  timeoutMs: number;
  onError: (err: Error) => void;
}

/**
 * A Redis client tuned for a dependency that must never take the API down with it: commands fail
 * immediately while disconnected (no offline queue) or after a short timeout, and reconnection
 * backs off in the background.
 */
export function createRedis({ url, timeoutMs, onError }: RedisOptions): Redis {
  const redis = new Redis(url, {
    lazyConnect: true,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
    commandTimeout: timeoutMs,
    connectTimeout: 2_000,
    retryStrategy: (attempt) => Math.min(attempt * 200, 2_000),
  });
  redis.on('error', onError); // without a listener, ioredis would raise an unhandled 'error' event
  return redis;
}
