import { Shield } from 'lucide-react';

export function Header() {
  return (
    <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="flex items-center justify-center w-11 h-11 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 shadow-sm shadow-blue-500/10">
              <Shield className="w-6 h-6 text-blue-400" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Fraud Link Detector
              </h1>
              <p className="text-xs sm:text-sm text-slate-400 font-normal">
                Check suspicious links before you click.
              </p>
            </div>
          </div>
          <div className="hidden sm:flex items-center text-xs text-slate-400 gap-2 border border-slate-800 bg-slate-950/60 px-3 py-1.5 rounded-lg">
            <span className="text-blue-400">Client-Side Only</span>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <span>Zero External Tracking</span>
          </div>
        </div>
      </div>
    </header>
  );
}
