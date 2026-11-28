import { Request, Response, NextFunction } from 'express';
import { createHash } from 'node:crypto';

export interface ThreatCheckResult {
  configured: boolean;
  checked?: boolean;
  isThreat?: boolean;
  threatTypes?: string[];
  cacheDuration?: string;
  evaluatedAt?: string;
  status?: string;
  message?: string;
  error?: string;
}

export interface UrlValidationResult {
  valid: boolean;
  sanitizedUrl?: string;
  error?: string;
  status?: number;
}

/**
 * Validates a user-provided URL string:
 * - Must be a non-empty string
 * - Maximum length: 2048 characters
 * - Protocol must be http or https
 * - Strips any embedded username/password before sending upstream
 */
export function validateThreatCheckUrl(rawInput: unknown): UrlValidationResult {
  if (rawInput === undefined || rawInput === null || typeof rawInput !== 'string') {
    return {
      valid: false,
      error: 'URL is required and must be a valid string.',
      status: 400,
    };
  }

  const trimmed = rawInput.trim();
  if (trimmed.length === 0) {
    return {
      valid: false,
      error: 'URL cannot be empty.',
      status: 400,
    };
  }

  if (trimmed.length > 2048) {
    return {
      valid: false,
      error: 'URL exceeds maximum permitted length of 2048 characters.',
      status: 400,
    };
  }

  try {
    const parsed = new URL(trimmed);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        valid: false,
        error: `Unsupported protocol scheme "${parsed.protocol}". Only HTTP and HTTPS are permitted.`,
        status: 400,
      };
    }

    if (!parsed.hostname || parsed.hostname.length === 0) {
      return {
        valid: false,
        error: 'URL must contain a valid hostname.',
        status: 400,
      };
    }

    // Sanitize by removing embedded user credentials to prevent leaking auth info upstream
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }

    return {
      valid: true,
      sanitizedUrl: parsed.href,
    };
  } catch {
    return {
      valid: false,
      error: 'Invalid URL format.',
      status: 400,
    };
  }
}

/**
 * Rate limit requests by client IP. Production requires a shared Upstash Redis
 * REST store so limits remain consistent across serverless instances. Development
 * uses a bounded in-memory fallback.
 */
export function createRateLimiter(maxRequests = 60, windowMs = 60000) {
  const clients = new Map<string, { count: number; resetTime: number }>();
  const redisUrlValue = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  let redisUrl: URL | undefined;

  try {
    if (redisUrlValue && redisToken) {
      redisUrl = new URL(redisUrlValue);
      if (redisUrl.protocol !== 'https:') redisUrl = undefined;
    }
  } catch {
    redisUrl = undefined;
  }

  const redisConfigIncomplete = Boolean(redisUrlValue || redisToken) && !redisUrl;
  const productionWithoutRedis = process.env.NODE_ENV === 'production' && !redisUrl;
  const script = "local count=redis.call('INCR',KEYS[1]); if count==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return {count,redis.call('PTTL',KEYS[1])}";

  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of clients.entries()) {
      if (now > record.resetTime) clients.delete(ip);
    }
  }, Math.max(windowMs, 30000));
  cleanupTimer.unref();

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

    if (redisConfigIncomplete || productionWithoutRedis) {
      res.status(503).json({
        error: 'Shared rate limiting is not configured. Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.',
      });
      return;
    }

    if (redisUrl && redisToken) {
      try {
        const ipDigest = createHash('sha256').update(clientIp).digest('hex');
        const key = `fraud-link-detector:rate:${maxRequests}:${ipDigest}`;
        const redisResponse = await fetch(`${redisUrl.origin}/`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${redisToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(['EVAL', script, '1', key, String(windowMs)]),
          signal: AbortSignal.timeout(2000),
        });
        if (!redisResponse.ok) throw new Error(`Redis returned HTTP ${redisResponse.status}`);
        const payload = await redisResponse.json() as { result?: unknown };
        const result = payload.result;
        if (!Array.isArray(result) || typeof result[0] !== 'number' || typeof result[1] !== 'number') {
          throw new Error('Redis returned an invalid rate-limit result');
        }

        const [count, ttl] = result;
        if (count > maxRequests) {
          res.setHeader('Retry-After', String(Math.max(1, Math.ceil(ttl / 1000))));
          res.status(429).json({ error: 'Too many requests. Please try again later.' });
          return;
        }
        next();
        return;
      } catch {
        res.status(503).json({ error: 'Rate limiting is temporarily unavailable. Please try again later.' });
        return;
      }
    }

    const now = Date.now();
    const clientRecord = clients.get(clientIp);
    if (!clientRecord || now > clientRecord.resetTime) {
      if (clients.size >= 10000) {
        for (const [ip, record] of clients.entries()) {
          if (now > record.resetTime || record.count < maxRequests) clients.delete(ip);
          if (clients.size < 9000) break;
        }
      }
      clients.set(clientIp, { count: 1, resetTime: now + windowMs });
      next();
      return;
    }

    if (clientRecord.count >= maxRequests) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((clientRecord.resetTime - now) / 1000))));
      res.status(429).json({ error: 'Too many requests. Please try again later.' });
      return;
    }

    clientRecord.count += 1;
    next();
  };
}

/**
 * Queries the official Google Safe Browsing v5 urls:search API.
 * Method: GET https://safebrowsing.googleapis.com/v5/urls:search?urls[]=...&key=...
 * Never logs or exposes the API key or sensitive parameters.
 */
export async function querySafeBrowsing(
  sanitizedUrl: string,
  apiKey?: string,
  fetchFn: typeof fetch = fetch
): Promise<{ status: number; body: ThreatCheckResult }> {
  // If key is not configured, return an unconfigured fallback without erroring or inventing data
  if (!apiKey || !apiKey.trim()) {
    return {
      status: 200,
      body: {
        configured: false,
        status: 'unconfigured',
        message: 'Threat intelligence service is not configured on this server.',
      },
    };
  }

  const endpointUrl = new URL('https://safebrowsing.googleapis.com/v5/urls:search');
  endpointUrl.searchParams.append('urls[]', sanitizedUrl);
  endpointUrl.searchParams.append('key', apiKey.trim());
  const endpoint = endpointUrl.toString().replace(/urls%5B%5D/g, 'urls[]');

  try {
    const response = await fetchFn(endpoint, {
      method: 'GET',
      signal: AbortSignal.timeout(5000), // 5-second timeout
    });

    if (!response.ok) {
      let errorCategory = 'UPSTREAM_ERROR';
      let errorDetail = '';
      let errorCode = response.status;
      let errorStatus = '';
      let errorMessage = '';

      try {
        const text = await response.text();
        try {
          const errorJson = JSON.parse(text) as {
            error?: { code?: number; message?: string; status?: string };
          };
          if (errorJson?.error) {
            errorCode = errorJson.error.code || response.status;
            errorStatus = errorJson.error.status || '';
            errorMessage = errorJson.error.message || '';

            const lowerMsg = errorMessage.toLowerCase();
            const lowerStatus = errorStatus.toLowerCase();
            const hasReason = (reason: string) =>
              lowerMsg.includes(reason.toLowerCase()) ||
              lowerStatus.includes(reason.toLowerCase());

            if (hasReason('SERVICE_DISABLED') || lowerMsg.includes('not enabled') || lowerStatus === 'service_disabled') {
              errorCategory = 'API_NOT_ENABLED';
            } else if (
              hasReason('API_KEY_INVALID') ||
              hasReason('INVALID_API_KEY') ||
              lowerMsg.includes('api key not valid') ||
              lowerMsg.includes('api_key_invalid')
            ) {
              errorCategory = 'API_KEY_INVALID';
            } else if (
              hasReason('KEY_RESTRICTIONS') ||
              hasReason('API_KEY_RESTRICTED') ||
              lowerMsg.includes('restricted') ||
              lowerMsg.includes('restriction')
            ) {
              errorCategory = 'KEY_RESTRICTIONS';
            } else if (errorCode === 429 || hasReason('RESOURCE_EXHAUSTED') || lowerMsg.includes('quota') || lowerStatus === 'resource_exhausted') {
              errorCategory = 'QUOTA_EXCEEDED';
            } else if (errorCode === 400 || hasReason('INVALID_ARGUMENT') || lowerMsg.includes('invalid argument') || lowerStatus === 'invalid_argument') {
              errorCategory = 'INVALID_ARGUMENT';
            } else if (errorCode === 403 || hasReason('PERMISSION_DENIED') || lowerStatus === 'permission_denied') {
              errorCategory = 'PERMISSION_DENIED';
            }

            // Sanitize errorMessage in errorDetail to guarantee no API keys or URLs in logs
            const sanitizedMsg = errorMessage
              .replace(/key=[^&\s]+/gi, 'key=[REDACTED]')
              .replace(/https?:\/\/[^\s]+/gi, '[URL_REDACTED]');
            errorDetail = ` (${errorStatus || errorCode}: ${sanitizedMsg})`;
          }
        } catch {
          // Non-JSON response body (e.g. HTML 502/503 from proxy or gateway)
          const sanitizedText = text
            .slice(0, 100)
            .replace(/key=[^&\s]+/gi, 'key=[REDACTED]')
            .replace(/https?:\/\/[^\s]+/gi, '[URL_REDACTED]')
            .trim();
          if (sanitizedText) {
            errorDetail = ` (Non-JSON: ${sanitizedText})`;
          }
        }
      } catch {
        // Fallback if response body reading fails
      }

      // Log structured diagnostics safely - NEVER log API key, submitted URL, or complete request URL
      console.error(`Google Safe Browsing diagnostic classification [${errorCategory}]: HTTP ${response.status}${errorDetail}`);

      return {
        status: 502,
        body: {
          configured: true,
          checked: false,
          error: 'Threat intelligence service is temporarily unavailable.',
        },
      };
    }

    const data = (await response.json()) as {
      threats?: Array<{ url?: string; threatTypes?: string[] }>;
      cacheDuration?: string;
    };

    const threats = Array.isArray(data.threats) ? data.threats : [];
    const isThreat = threats.length > 0;
    const threatTypes: string[] = Array.from(
      new Set(
        threats
          .flatMap((t) => (Array.isArray(t.threatTypes) ? t.threatTypes : []))
          .filter(Boolean)
      )
    );

    return {
      status: 200,
      body: {
        configured: true,
        checked: true,
        isThreat,
        threatTypes,
        cacheDuration: data.cacheDuration,
        evaluatedAt: new Date().toISOString(),
      },
    };
  } catch (err: unknown) {
    const isTimeout =
      err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
    const errorCategory = isTimeout ? 'TIMEOUT' : 'NETWORK_ERROR';
    console.error(`Google Safe Browsing diagnostic classification [${errorCategory}]:`, err instanceof Error ? err.message : 'Unknown error');

    return {
      status: isTimeout ? 504 : 502,
      body: {
        configured: true,
        checked: false,
        error: isTimeout
          ? 'Threat intelligence request timed out.'
          : 'Threat intelligence service is temporarily unavailable.',
      },
    };
  }
}
