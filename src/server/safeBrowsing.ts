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
 * Queries the official Google Safe Browsing v4 threatMatches:find API.
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

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey.trim())}`;

  const payload = {
    client: {
      clientId: 'fraud-link-detector',
      clientVersion: '1.0.0',
    },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: sanitizedUrl }],
    },
  };

  try {
    const response = await fetchFn(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000), // 5-second timeout
    });

    if (!response.ok) {
      // Log status only, NEVER the endpoint or query string with API key
      console.error('Google Safe Browsing upstream error status:', response.status);
      return {
        status: 502,
        body: {
          configured: true,
          checked: false,
          error: 'Threat intelligence upstream service error.',
        },
      };
    }

    const data = await response.json();
    const matches = Array.isArray(data.matches) ? data.matches : [];
    const isThreat = matches.length > 0;
    const threatTypes: string[] = Array.from(
      new Set(matches.map((m: { threatType?: string }) => m.threatType).filter(Boolean))
    );

    return {
      status: 200,
      body: {
        configured: true,
        checked: true,
        isThreat,
        threatTypes,
        cacheDuration: matches[0]?.cacheDuration,
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
