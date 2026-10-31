import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  validateThreatCheckUrl,
  createRateLimiter,
  querySafeBrowsing,
} from './src/server/safeBrowsing';
import { performFullRecon } from './src/server/dnsRecon';
import { inspectRedirectChain } from './src/server/redirectInspector';
import { captureWebsiteScreenshot } from './src/server/screenshotService';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Enable trust proxy: configurable via TRUST_PROXY env var, defaulting to 1 (standard for Cloud Run / single reverse proxy)
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

// Unconditional no-store cache control for all /api endpoints (including validation errors, 429s, and 500s)
app.use('/api', (_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// Basic JSON body parsing with strict size limit
app.use(express.json({ limit: '100kb' }));

// Rate limiter for reconnaissance and threat checks: max 60 requests per minute per IP
const threatCheckRateLimiter = createRateLimiter(60, 60000);

// 1. API Routes
// GET /api/health: Service status endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json({
    status: 'ok',
    service: 'fraud-link-detector-api',
  });
});

// POST /api/threat-check: Google Safe Browsing integration endpoint
app.post(
  '/api/threat-check',
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

// POST /api/recon: DNS and RDAP Domain Reconnaissance endpoint
app.post(
  '/api/recon',
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

// POST /api/redirect-chain: Hop-by-hop secure redirect inspection endpoint
app.post(
  '/api/redirect-chain',
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

// Dedicated rate limiter for visual previews: max 15 requests per minute per IP
const screenshotRateLimiter = createRateLimiter(15, 60000);

// POST /api/screenshot: Ephemeral isolated website screenshot preview endpoint
app.post(
  '/api/screenshot',
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

// 2. Vite Middleware or Static Production Serving
async function setupFrontend() {
  if (!isProduction) {
    // Development mode: Attach Vite as middleware for instant compilation
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Production mode: Serve pre-built static assets from dist
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  // 3. Centralized safe error handler (prevents leaking internal details or env vars)
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    // Log error message internally on server side
    console.error('Unhandled server error:', err.message);
    res.setHeader('Cache-Control', 'no-store');
    res.status(500).json({
      error: 'Internal Server Error',
    });
  });
}

// Start server if not running in test mode
if (process.env.NODE_ENV !== 'test') {
  setupFrontend()
    .then(() => {
      app.listen(PORT, '0.0.0.0', () => {
        console.log(`Fraud Link Detector backend running at http://0.0.0.0:${PORT}`);
      });
    })
    .catch((err) => {
      console.error('Failed to initialize server:', err);
      process.exit(1);
    });
}
