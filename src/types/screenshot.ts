export type ScreenshotStatus =
  | 'idle'
  | 'loading'
  | 'success'
  | 'error'
  | 'timeout'
  | 'blocked_special_use'
  | 'unconfigured';

export interface ScreenshotResult {
  status: ScreenshotStatus;
  imageDataUri?: string;
  capturedAt?: string;
  viewport?: { width: number; height: number };
  message?: string;
  error?: string;
}

export interface ScreenshotClientState {
  status: ScreenshotStatus;
  data: ScreenshotResult | null;
  errorMessage?: string;
}
