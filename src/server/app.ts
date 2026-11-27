import express, { Request, Response, NextFunction } from 'express';
import {
  validateThreatCheckUrl,
  createRateLimiter,
  querySafeBrowsing,
} from './safeBrowsing.js';
import { performFullRecon } from './dnsRecon.js';
import { inspectRedirectChain } from './redirectInspector.js';
import { captureWebsiteScreenshot } from './screenshotService.js';

export function createApiRouter(): express.Router {
  const router = express.Router();

  // Rate limiter for reconnaissance and threat checks: max 60 requests per minute per IP
  const threatCheckRateLimiter = createRateLimiter(60, 60000);

  // Dedicated rate limiter for visual previews: max 15 requests per minute per IP
  const screenshotRateLimiter = createRateLimiter(15, 60000);

  // Unconditional no-store cache control for all API endpoints
  router.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  // 0. GET /: Service index / endpoint discovery
  router.get('/', (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).json({
      status: 'ok',
      service: 'fraud-link-detector-api',
      endpoints: [
        '/api/health',
        '/api/threat-check',
        '/api/recon',
        '/api/redirect-chain',
        '/api/screenshot',
      ],
    });
  });

  // 1. GET /health: Service status endpoint
  router.get('/health', (_req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).json({
      status: 'ok',
      service: 'fraud-link-detector-api',
    });
  });

  // 2. POST /threat-check: Google Safe Browsing integration endpoint
  router.post(
    '/threat-check',
    threatCheckRateLimiter,
    async (req: Request, res: Response, next: NextFunction) => {
      res.setHeader('Cache-Control', 'no-store');
      try {
        const validation = validateThreatCheckUrl(req.body?.url);
        if (!validation.valid || !validation.sanitizedUrl) {
          res.status(validation.status || 400).json({
            error: validation.error || 'Invalid URL provided.',
          });
          return;
        }

        // Read API key exclusively from server-side environment variable
        const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

        const result = await querySafeBrowsing(validation.sanitizedUrl, apiKey);
        res.status(result.status).json(result.body);
      } catch (err) {
        next(err);
      }
    }
  );

  // 3. POST /recon: DNS and RDAP Domain Reconnaissance endpoint
  router.post(
    '/recon',
    threatCheckRateLimiter,
    async (req: Request, res: Response, next: NextFunction) => {
      res.setHeader('Cache-Control', 'no-store');
      try {
        const validation = validateThreatCheckUrl(req.body?.url);
        if (!validation.valid || !validation.sanitizedUrl) {
          res.status(validation.status || 400).json({
            error: validation.error || 'Invalid URL provided.',
          });
          return;
        }

        const parsed = new URL(validation.sanitizedUrl);
        const reconResult = await performFullRecon(parsed.hostname);
        res.status(200).json(reconResult);
      } catch (err) {
        next(err);
      }
    }
  );

  // 4. POST /redirect-chain: Hop-by-hop secure redirect inspection endpoint
  router.post(
    '/redirect-chain',
    threatCheckRateLimiter,
    async (req: Request, res: Response, next: NextFunction) => {
      res.setHeader('Cache-Control', 'no-store');
      try {
        const validation = validateThreatCheckUrl(req.body?.url);
        if (!validation.valid || !validation.sanitizedUrl) {
          res.status(validation.status || 400).json({
            error: validation.error || 'Invalid URL provided.',
          });
          return;
        }

        const chainResult = await inspectRedirectChain(validation.sanitizedUrl);
        res.status(200).json(chainResult);
      } catch (err) {
        next(err);
      }
    }
  );

  // 5. POST /screenshot: Ephemeral isolated website screenshot preview endpoint
  router.post(
    '/screenshot',
    screenshotRateLimiter,
    async (req: Request, res: Response, next: NextFunction) => {
      res.setHeader('Cache-Control', 'no-store');
      try {
        const apiKey = process.env.SCREENSHOT_API_KEY;
        const result = await captureWebsiteScreenshot(req.body?.url, apiKey);
        res.status(result.status).json(result.body);
      } catch (err) {
        next(err);
      }
    }
  );

  return router;
}

export function createApp(): express.Express {
  const app = express();

  // Configure reverse proxy trust: configurable via TRUST_PROXY env var
  // Defaults to 1 (standard for Vercel, Cloud Run, or single reverse proxy)
  const trustProxyEnv = process.env.TRUST_PROXY ?? '1';
  if (trustProxyEnv === 'false' || trustProxyEnv === '0') {
    app.set('trust proxy', false);
  } else if (trustProxyEnv === 'true') {
    app.set('trust proxy', true);
  } else if (!isNaN(Number(trustProxyEnv))) {
    app.set('trust proxy', Number(trustProxyEnv));
  } else {
    app.set('trust proxy', trustProxyEnv);
  }

  // Global security headers
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Basic JSON body parsing with strict size limit
  app.use(express.json({ limit: '100kb' }));

  // Routing & URL normalization middleware:
  // 1. Natural routing: Under Vercel catch-all (api/[...route].ts) and standalone Node.js,
  //    Express naturally receives full pathnames like '/api/health', '/api/threat-check', etc.
  // 2. Prefix normalization: If a proxy or orchestrator stripped the '/api' prefix (e.g. delivering
  //    '/health' instead of '/api/health'), normalize req.url to start with '/api'.
  // 3. Defensive fallback: If an upstream reverse proxy collapsed req.url to '/api' or '/api/',
  //    defensively check if 'x-vercel-original-url' or 'x-matched-path' provides the subpath.
  const knownEndpoints = ['/health', '/threat-check', '/recon', '/redirect-chain', '/screenshot'];
  app.use((req: Request, _res: Response, next: NextFunction) => {
    // 1. Natural path preservation: If req.url is already an /api/ path, preserve as-is
    if (req.url.startsWith('/api/')) {
      return next();
    }

    // 2. Prefix normalization: If path is a known endpoint without /api prefix, normalize
    if (knownEndpoints.some((ep) => req.url === ep || req.url.startsWith(`${ep}?`))) {
      req.url = `/api${req.url}`;
      return next();
    }

    // 3. Defensive fallback: If an upstream proxy collapsed req.url to /api or /api/, recover subpath
    if (req.url === '/api' || req.url === '/api/') {
      const originalUrl =
        (req.headers['x-vercel-original-url'] as string | undefined) ||
        (req.headers['x-matched-path'] as string | undefined);

      if (originalUrl && originalUrl.startsWith('/api/')) {
        req.url = originalUrl;
      }
    }

    next();
  });

  // Mount API router strictly once at '/api'
  const apiRouter = createApiRouter();
  app.use('/api', apiRouter);

  // Centralized safe error handler (prevents leaking internal stack traces or secrets)
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error('Unhandled server error:', err.message);
    res.setHeader('Cache-Control', 'no-store');
    res.status(500).json({
      error: 'Internal Server Error',
    });
  });

  return app;
}

export const app = createApp();
