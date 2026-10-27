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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Basic JSON body parsing with strict size limit
app.use(express.json({ limit: '100kb' }));

// Rate limiter for reconnaissance and threat checks: max 60 requests per minute per IP
const threatCheckRateLimiter = createRateLimiter(60, 60000);

// 1. API Routes
// GET /api/health: Service status endpoint
app.get('/api/health', (_req: Request, res: Response) => {
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
