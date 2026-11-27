import 'dotenv/config';
import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { app } from './src/server/app.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Vite Middleware or Static Production Serving for standalone/local execution
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
}

// Start standalone server for local dev (npm run dev) or production (npm start)
// Do not call listen() in test environments or when running as a Vercel serverless function
if (process.env.NODE_ENV !== 'test' && !process.env.VERCEL) {
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

export { app };
