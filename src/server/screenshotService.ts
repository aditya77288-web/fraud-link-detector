import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import {
  isSpecialUseHostname,
  isSpecialUseIpv4,
  isSpecialUseIpv6,
} from './dnsRecon.js';
import { validateThreatCheckUrl } from './safeBrowsing.js';
import { ScreenshotResult } from '../types/screenshot.js';

export const SCREENSHOT_TIMEOUT_MS = 8000;
export const MAX_IMAGE_BUFFER_BYTES = 2 * 1024 * 1024; // 2 MB ceiling
export const MAX_PROVIDER_JSON_BYTES = 64 * 1024; // Provider metadata should remain small

export interface FetchFunction {
  (input: string | URL | Request, init?: RequestInit): Promise<Response>;
}

export type ScreenshotHostResolver = (hostname: string) => Promise<string[]>;

const defaultScreenshotHostResolver: ScreenshotHostResolver = async (hostname) => {
  const records = await lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
};

const DNS_LOOKUP_TIMEOUT_MS = 3000;

/**
 * Fail closed unless every resolved address is a public IP. This is a pre-flight
 * check only: Microlink performs the target render on its own infrastructure, so
 * this application cannot pin the provider's eventual target socket.
 */
async function isPublicScreenshotHost(
  hostname: string,
  resolver: ScreenshotHostResolver
): Promise<boolean> {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isSpecialUseHostname(normalized)) return false;

  if (isIP(normalized)) {
    return !isSpecialUseIpv4(normalized) && !isSpecialUseIpv6(normalized);
  }

  let timer: NodeJS.Timeout | undefined;
  try {
    const addresses = await Promise.race([
      resolver(normalized),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('DNS lookup timed out')), DNS_LOOKUP_TIMEOUT_MS);
      }),
    ]);
    return addresses.length > 0 && addresses.every((address) =>
      isIP(address) !== 0 &&
      !isSpecialUseIpv4(address) &&
      !isSpecialUseIpv6(address)
    );
  } catch {
    return false;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Validates magic numbers of a buffer to ensure it is genuinely a JPEG, PNG, or WebP raster image.
 * Explicitly rejects SVG, HTML, executable binaries, and text scripts.
 */
export function validateImageBuffer(
  buffer: Buffer,
  declaredMimeType: string
): { valid: boolean; mimeType: string; error?: string } {
  if (buffer.length < 4) {
    return {
      valid: false,
      mimeType: '',
      error: 'Downloaded payload is too small to be a valid image.',
    };
  }

  // JPEG: 0xFF, 0xD8, 0xFF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { valid: true, mimeType: 'image/jpeg' };
  }

  // PNG: \x89PNG\r\n\x1a\n (0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
  if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return { valid: true, mimeType: 'image/png' };
  }

  // WebP: RIFF (bytes 0-3) and WEBP (bytes 8-11)
  if (
    buffer.length >= 12 &&
    buffer[0] === 0x52 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x46 &&
    buffer[8] === 0x57 &&
    buffer[9] === 0x45 &&
    buffer[10] === 0x42 &&
    buffer[11] === 0x50
  ) {
    return { valid: true, mimeType: 'image/webp' };
  }

  return {
    valid: false,
    mimeType: '',
    error: `Untrusted or unsafe image payload (declared: ${declaredMimeType || 'unknown'}). Only JPEG, PNG, and WebP raster images are accepted.`,
  };
}

/**
 * Reads a response body incrementally and aborts immediately if the streamed bytes
 * exceed maxBytes, preventing memory exhaustion from oversized responses.
 */
export async function readLimitedBuffer(
  response: Response,
  maxBytes: number = MAX_IMAGE_BUFFER_BYTES
): Promise<Buffer> {
  const contentLength = response.headers.get('content-length');
  if (contentLength && Number(contentLength) > maxBytes) {
    try { await response.body?.cancel('Content-Length exceeded limit'); } catch {}
    throw new Error(`Response exceeds maximum size limit of ${maxBytes} bytes.`);
  }

  // If response stream is not available, fallback to arrayBuffer check
  if (!response.body) {
    const arrayBuf = await response.arrayBuffer();
    if (arrayBuf.byteLength > maxBytes) {
      throw new Error(`Response exceeds maximum size limit of ${maxBytes} bytes.`);
    }
    return Buffer.from(arrayBuf);
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        totalBytes += value.byteLength;
        if (totalBytes > maxBytes) {
          await reader.cancel();
          throw new Error(`Response exceeded maximum allowed size of ${maxBytes} bytes.`);
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(chunks);
}

/**
 * Validates a target URL and fetches an ephemeral website screenshot via
 * an isolated external rendering sandbox.
 * Rejects all loopback, private, and internal addresses before contacting any external service,
 * enforces an overall 8-second timeout, streams image data with strict size limits,
 * and validates image magic bytes before encoding.
 */
export async function captureWebsiteScreenshot(
  rawUrl: string,
  apiKey?: string,
  fetchFn: FetchFunction = fetch,
  hostResolver: ScreenshotHostResolver = defaultScreenshotHostResolver
): Promise<{ status: number; body: ScreenshotResult }> {
  // 1. URL format & scheme validation (strictly http or https)
  const validation = validateThreatCheckUrl(rawUrl);
  if (!validation.valid || !validation.sanitizedUrl) {
    return {
      status: validation.status || 400,
      body: {
        status: 'error',
        error: validation.error || 'Invalid URL provided.',
      },
    };
  }

  const targetUrl = validation.sanitizedUrl;
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return {
      status: 400,
      body: {
        status: 'error',
        error: 'Malformed URL.',
      },
    };
  }

  // 2. Pre-flight SSRF Guard: reject local loopback, private RFC 1918, CGNAT, link-local, and cloud metadata addresses
  const host = parsed.hostname.toLowerCase();
  if (
    isSpecialUseHostname(host) ||
    isSpecialUseIpv4(host) ||
    isSpecialUseIpv6(host) ||
    !(await isPublicScreenshotHost(host, hostResolver))
  ) {
    return {
      status: 400,
      body: {
        status: 'blocked_special_use',
        error: 'Visual preview is blocked: destination does not resolve exclusively to public IP addresses.',
      },
    };
  }

  // 3. Build Microlink provider URL
  const providerUrl = new URL('https://api.microlink.io');
  providerUrl.searchParams.set('url', targetUrl);
  providerUrl.searchParams.set('screenshot', 'true');
  providerUrl.searchParams.set('meta', 'false');
  providerUrl.searchParams.set('viewport.width', '1280');
  providerUrl.searchParams.set('viewport.height', '800');
  providerUrl.searchParams.set('screenshot.type', 'jpeg');
  providerUrl.searchParams.set('screenshot.quality', '75');

  const headers: Record<string, string> = {
    Accept: 'application/json, image/jpeg, image/png',
    'User-Agent': 'FraudLinkDetector/1.0',
  };

  if (apiKey) {
    headers['x-api-key'] = apiKey;
  }

  // Global abort controller covering the entire operation within 8 seconds
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SCREENSHOT_TIMEOUT_MS);

  try {
    const response = await fetchFn(providerUrl.toString(), {
      method: 'GET',
      headers,
      signal: controller.signal,
    });

    if (!response.ok) {
      clearTimeout(timeoutId);
      if (response.status === 429) {
        return {
          status: 429,
          body: {
            status: 'error',
            error: 'Screenshot provider rate limit reached. Please try again in a few moments.',
          },
        };
      }

      return {
        status: 502,
        body: {
          status: 'error',
          error: `Screenshot provider returned HTTP ${response.status}. The target website may be blocking automated page capture.`,
        },
      };
    }

    const contentType = response.headers.get('content-type') || '';
    let imageBuffer: Buffer;
    let declaredMime = contentType;

    // A. If provider returned JSON with image CDN URL
    if (contentType.includes('application/json')) {
      let json: { data?: { screenshot?: { url?: unknown } } };
      try {
        const providerBody = await readLimitedBuffer(response, MAX_PROVIDER_JSON_BYTES);
        json = JSON.parse(providerBody.toString('utf8')) as typeof json;
      } catch {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: { status: 'error', error: 'Screenshot provider returned an invalid or oversized JSON response.' },
        };
      }
      const imageUrl = json?.data?.screenshot?.url;

      if (!imageUrl || typeof imageUrl !== 'string') {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: {
            status: 'error',
            error: 'Could not extract visual preview URL from screenshot response.',
          },
        };
      }

      // Security Check: Validate CDN image URL protocol & SSRF target before fetching
      let parsedImgUrl: URL;
      try {
        parsedImgUrl = new URL(imageUrl);
      } catch {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: {
            status: 'error',
            error: 'Screenshot provider returned a malformed image URL.',
          },
        };
      }

      if (parsedImgUrl.protocol !== 'https:') {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: {
            status: 'error',
            error: 'Insecure non-HTTPS image URL returned by provider.',
          },
        };
      }

      const imgHost = parsedImgUrl.hostname.toLowerCase();
      if (
        isSpecialUseHostname(imgHost) ||
        isSpecialUseIpv4(imgHost) ||
        isSpecialUseIpv6(imgHost) ||
        !(await isPublicScreenshotHost(imgHost, hostResolver))
      ) {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: {
            status: 'error',
            error: 'Screenshot provider returned an image host that does not resolve exclusively to public IP addresses.',
          },
        };
      }

      // Do not follow provider-controlled redirects: the redirect destination
      // would otherwise bypass the hostname and DNS checks above.
      const imgRes = await fetchFn(imageUrl, {
        signal: controller.signal,
        redirect: 'error',
      });

      if (!imgRes.ok) {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: {
            status: 'error',
            error: `Failed to retrieve rendered image buffer (HTTP ${imgRes.status}).`,
          },
        };
      }

      declaredMime = imgRes.headers.get('content-type') || 'image/jpeg';
      try {
        imageBuffer = await readLimitedBuffer(imgRes, MAX_IMAGE_BUFFER_BYTES);
      } catch (streamErr: unknown) {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: {
            status: 'error',
            error: (streamErr as Error).message || 'Rendered screenshot exceeds maximum allowed size (2MB).',
          },
        };
      }
    } else {
      // B. Direct binary image returned by provider
      try {
        imageBuffer = await readLimitedBuffer(response, MAX_IMAGE_BUFFER_BYTES);
      } catch (streamErr: unknown) {
        clearTimeout(timeoutId);
        return {
          status: 502,
          body: {
            status: 'error',
            error: (streamErr as Error).message || 'Rendered screenshot exceeds maximum allowed size (2MB).',
          },
        };
      }
    }

    clearTimeout(timeoutId);

    // Validate magic bytes to verify this is genuinely a safe raster image
    const validationResult = validateImageBuffer(imageBuffer, declaredMime);
    if (!validationResult.valid) {
      return {
        status: 502,
        body: {
          status: 'error',
          error: validationResult.error || 'Invalid or unsafe image data received.',
        },
      };
    }

    const base64 = imageBuffer.toString('base64');
    return {
      status: 200,
      body: {
        status: 'success',
        imageDataUri: `data:${validationResult.mimeType};base64,${base64}`,
        capturedAt: new Date().toISOString(),
        viewport: { width: 1280, height: 800 },
      },
    };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const error = err as Error;
    if (error.name === 'AbortError') {
      return {
        status: 504,
        body: {
          status: 'timeout',
          error: 'Website preview timed out within 8 seconds. The site may be offline, blocking automated page rendering, or taking too long to respond.',
        },
      };
    }

    return {
      status: 500,
      body: {
        status: 'error',
        error: error.message || 'An unexpected error occurred while capturing preview.',
      },
    };
  }
}
