import { useState } from 'react';
import {
  Camera,
  RotateCw,
  AlertTriangle,
  CheckCircle2,
  Maximize2,
  X,
  ShieldAlert,
} from 'lucide-react';
import { ScreenshotClientState } from '../types/screenshot';

interface ScreenshotPreviewCardProps {
  targetUrl: string;
}

export function ScreenshotPreviewCard({ targetUrl }: ScreenshotPreviewCardProps) {
  const [state, setState] = useState<ScreenshotClientState>({
    status: 'idle',
    data: null,
  });
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handleCapture = async () => {
    setState({ status: 'loading', data: null });

    try {
      const response = await fetch('/api/screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });

      const body = await response.json();

      if (response.ok && body.status === 'success') {
        setState({ status: 'success', data: body });
      } else {
        setState({
          status: body.status || 'error',
          data: body,
          errorMessage: body.error || 'Failed to capture visual preview.',
        });
      }
    } catch (_err) {
      setState({
        status: 'error',
        data: null,
        errorMessage: 'Unable to connect to visual preview service.',
      });
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xl shadow-slate-950/40 backdrop-blur-sm">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <Camera className="w-5 h-5 text-blue-400" aria-hidden="true" />
          <h3 className="text-base sm:text-lg font-bold text-white">
            Website Visual Preview
          </h3>
        </div>
        {state.status === 'success' && (
          <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/60 border border-emerald-800/80 px-2.5 py-1 rounded-full font-medium">
            <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
            Snapshot Rendered
          </span>
        )}
      </div>

      {/* Security Disclaimer & Privacy Disclosure */}
      <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 flex items-start gap-2.5 text-xs text-slate-300 mb-4">
        <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
        <div className="space-y-1 leading-relaxed">
          <p>
            <strong className="text-amber-300 font-semibold">Isolated Sandbox Preview: </strong>
            Rendered on a remote cloud browser. An untrusted page cannot infect your device through an image. However, visual appearance does not prove safety—phishing websites frequently mimic authentic brand login screens.
          </p>
          <p className="text-slate-400 text-[11px]">
            Privacy Notice: Capturing a snapshot transmits this URL to an external rendering service (Microlink API), which may temporarily cache public page captures on its CDN.
          </p>
        </div>
      </div>

      {/* Idle State: Trigger Button */}
      {state.status === 'idle' && (
        <div className="text-center py-6 px-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
          <p className="text-xs sm:text-sm text-slate-400 mb-4 max-w-md mx-auto">
            Take an isolated snapshot of this webpage without executing scripts or opening links on your device.
          </p>
          <button
            type="button"
            onClick={handleCapture}
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-900/30 transition-all cursor-pointer active:scale-[0.99]"
          >
            <Camera className="w-4 h-4" aria-hidden="true" />
            <span>Capture Visual Preview</span>
          </button>
        </div>
      )}

      {/* Loading State */}
      {state.status === 'loading' && (
        <div className="py-10 text-center bg-slate-950/60 border border-slate-800/80 rounded-xl">
          <RotateCw className="w-6 h-6 text-blue-400 animate-spin mx-auto mb-3" aria-hidden="true" />
          <p className="text-sm font-medium text-slate-200">
            Rendering preview in isolated cloud sandbox...
          </p>
          <p className="text-xs text-slate-500 mt-1">
            Navigating and capturing full page view (up to 8s)
          </p>
        </div>
      )}

      {/* Success State: Image Preview */}
      {state.status === 'success' && state.data?.imageDataUri && (
        <div className="space-y-3">
          <div className="relative group rounded-xl overflow-hidden border border-slate-800 bg-slate-950 shadow-inner">
            <img
              src={state.data.imageDataUri}
              alt={`Visual preview of ${targetUrl}`}
              className="w-full max-h-[460px] object-cover object-top select-none"
              loading="lazy"
            />
            {/* Overlay expand button */}
            <button
              type="button"
              onClick={() => setIsModalOpen(true)}
              className="absolute bottom-3 right-3 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 text-xs text-slate-200 border border-slate-700 shadow-md backdrop-blur-sm transition-all cursor-pointer"
              title="Expand preview"
            >
              <Maximize2 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Expand</span>
            </button>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs text-slate-400 pt-1">
            <span>
              Viewport: {state.data.viewport?.width} × {state.data.viewport?.height} px · Captured {state.data.capturedAt ? new Date(state.data.capturedAt).toLocaleTimeString() : 'recently'}
            </span>
            <button
              type="button"
              onClick={handleCapture}
              className="inline-flex items-center gap-1 text-slate-300 hover:text-white transition-colors cursor-pointer"
            >
              <RotateCw className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Refresh Snapshot</span>
            </button>
          </div>
        </div>
      )}

      {/* Error or Blocked State */}
      {(state.status === 'error' || state.status === 'timeout' || state.status === 'blocked_special_use') && (
        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/40 text-center space-y-3">
          <div className="flex items-center justify-center gap-2 text-red-400 font-semibold text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span>
              {state.status === 'blocked_special_use'
                ? 'Destination Blocked'
                : state.status === 'timeout'
                ? 'Snapshot Request Timed Out'
                : 'Unable to Render Preview'}
            </span>
          </div>
          <p className="text-xs text-slate-300 max-w-md mx-auto leading-relaxed">
            {state.errorMessage || state.data?.error || 'The webpage could not be captured.'}
          </p>
          {state.status !== 'blocked_special_use' && (
            <button
              type="button"
              onClick={handleCapture}
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <RotateCw className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Try Again</span>
            </button>
          )}
        </div>
      )}

      {/* Expanded Modal */}
      {isModalOpen && state.data?.imageDataUri && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Expanded visual preview"
          className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4 sm:p-6"
        >
          <div className="relative max-w-5xl w-full max-h-[90vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-950/80">
              <div className="text-xs font-mono text-slate-300 truncate max-w-xl">
                {targetUrl}
              </div>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white transition-colors cursor-pointer"
                aria-label="Close modal"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4 bg-slate-950 flex justify-center items-start">
              <img
                src={state.data.imageDataUri}
                alt={`Expanded preview of ${targetUrl}`}
                className="max-w-full h-auto rounded-lg shadow-lg select-none"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
