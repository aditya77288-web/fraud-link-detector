import { Request, Response, NextFunction } from 'express';

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
 * Simple in-memory rate limiter to prevent abuse and quota exhaustion.
 * Default: 60 requests per minute per IP address.
 */
export function createRateLimiter(maxRequests = 60, windowMs = 60000) {
  const clients = new Map<string, { count: number; resetTime: number }>();

  // Cleanup expired entries periodically
  setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of clients.entries()) {
      if (now > record.resetTime) {
        clients.delete(ip);
      }
    }
  }, Math.max(windowMs, 30000)).unref();

  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const clientRecord = clients.get(clientIp);

    if (!clientRecord || now > clientRecord.resetTime) {
      if (clients.size >= 10000) {
        // 1. Purge expired client records first
        for (const [ip, record] of clients.entries()) {
          if (now > record.resetTime) {
            clients.delete(ip);
          }
        }
        // 2. If still at capacity, evict unblocked entries (count < maxRequests) to protect active rate-limit bans
        if (clients.size >= 10000) {
          for (const [ip, record] of clients.entries()) {
            if (record.count < maxRequests) {
              clients.delete(ip);
              if (clients.size < 9000) break;
            }
          }
        }
        // 3. Strict bound fallback: evict oldest entry to prevent unbounded memory growth
        while (clients.size >= 10000) {
          const oldestKey = clients.keys().next().value;
          if (!oldestKey) break;
          clients.delete(oldestKey);
        }
      }
      clients.set(clientIp, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (clientRecord.count >= maxRequests) {
      res.status(429).json({
        error: 'Too many threat check requests. Please try again later.',
      });
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

  const endpoint = `https://safebrowsing.googleapis.com/v5/urls:search?urls[]=${encodeURIComponent(sanitizedUrl)}&key=${encodeURIComponent(apiKey.trim())}`;

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
        const errorJson = (await response.json()) as {
          error?: { code?: number; message?: string; status?: string };
        };
        if (errorJson?.error) {
          errorCode = errorJson.error.code || response.status;
          errorStatus = errorJson.error.status || '';
          errorMessage = errorJson.error.message || '';
          errorDetail = ` (${errorStatus || errorCode}: ${errorMessage})`;

          const lowerMsg = errorMessage.toLowerCase();
          if (errorCode === 403 || lowerMsg.includes('api key') || lowerMsg.includes('api_key_invalid')) {
            errorCategory = 'API_KEY_INVALID';
          } else if (lowerMsg.includes('not enabled') || lowerMsg.includes('service_disabled')) {
            errorCategory = 'API_NOT_ENABLED';
          } else if (errorCode === 400 || errorStatus === 'INVALID_ARGUMENT' || lowerMsg.includes('invalid argument')) {
            errorCategory = 'INVALID_ARGUMENT';
          } else if (errorCode === 429 || lowerMsg.includes('quota') || lowerMsg.includes('resource_exhausted')) {
            errorCategory = 'QUOTA_EXCEEDED';
          }
        }
      } catch {
        // Fallback if error body is not JSON
      }

      // Log structured diagnostics safely - NEVER log API key or user URL
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
    console.error('Threat check request failed:', isTimeout ? 'Request timed out' : 'Network error');

    return {
      status: isTimeout ? 504 : 502,
      body: {
        configured: true,
        checked: false,
        error: isTimeout
          ? 'Threat intelligence request timed out.'
          : 'Unable to reach threat intelligence service.',
      },
    };
  }
}
