import type { Request, Response } from 'express';
import { app } from '../src/server/app.js';

export default function handler(req: Request, res: Response) {
  return app(req, res);
}

export { app };
