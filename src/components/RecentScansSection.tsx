import { useState } from 'react';
import { History, Trash2, ShieldCheck, ShieldAlert, AlertTriangle, ArrowUpRight, Lock, AlertCircle } from 'lucide-react';
import { ScanHistoryItem } from '../utils/historyStorage';

interface RecentScansSectionProps {
  history: ScanHistoryItem[];
  onClearHistory: () => void;
  onSelectUrl: (url: string) => void;
}

export function RecentScansSection({
  history,
  onClearHistory,
  onSelectUrl,
}: RecentScansSectionProps) {
  const [showConfirmModal, setShowConfirmModal] = useState(false);

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'High':
        return {
          badge: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
          icon: ShieldAlert,
        };
      case 'Medium':
        return {
          badge: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
          icon: AlertTriangle,
        };
      default:
        return {
          badge: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
          icon: ShieldCheck,
        };
    }
  };

  const handleConfirmClear = () => {
    onClearHistory();
    setShowConfirmModal(false);
  };

  return (
    <section aria-labelledby="recent-scans-heading" className="w-full">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 sm:p-7 shadow-xl shadow-slate-950/40 backdrop-blur-sm">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div className="flex items-center gap-2.5">
            <History className="w-5 h-5 text-blue-400" aria-hidden="true" />
            <h2 id="recent-scans-heading" className="text-lg font-bold text-white tracking-tight">
              Recent Scans
            </h2>
            <span className="text-xs font-mono text-slate-400 bg-slate-950 border border-slate-800 px-2 py-0.5 rounded-full">
              {history.length} / 10 stored
            </span>
          </div>

          {history.length > 0 && (
            <button
              type="button"
              onClick={() => setShowConfirmModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg border border-slate-800 hover:border-rose-500/30 transition-colors cursor-pointer self-start sm:self-auto"
              aria-label="Clear scan history"
            >
              <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Clear History</span>
            </button>
          )}
        </div>

        {/* Content */}
        {history.length === 0 ? (
          <div className="py-10 text-center">
            <div className="w-10 h-10 rounded-full bg-slate-800/60 border border-slate-700/60 flex items-center justify-center mx-auto mb-3 text-slate-400">
              <History className="w-5 h-5 text-slate-400" aria-hidden="true" />
            </div>
            <p className="text-sm font-medium text-slate-300">
              No recent scans recorded yet.
            </p>
            <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
              Links you scan will be stored locally in your browser (up to 10 entries) with sensitive query tokens redacted.
            </p>
          </div>
        ) : (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
              <span>Saved locally in browser localStorage</span>
              <span className="flex items-center gap-1 text-[11px] text-slate-400">
                <Lock className="w-3 h-3 text-blue-400" />
                Sensitive tokens redacted
              </span>
            </div>

            <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-xl overflow-hidden bg-slate-950/60">
              {history.map((item) => {
                const style = getRiskBadge(item.level);
                const Icon = style.icon;

                return (
                  <div
                    key={item.id}
                    className="p-3.5 sm:p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-900/40 transition-colors"
                  >
                    {/* Left: URL & Hostname */}
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-semibold text-slate-200">
                          {item.hostname}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          {item.scannedAt}
                        </span>
                      </div>
                      <div
                        className="font-mono text-xs text-blue-300 truncate select-all"
                        title={item.displayUrl}
                      >
                        {item.displayUrl}
                      </div>
                    </div>

                    {/* Right: Risk Level, Score & Re-inspect Action */}
                    <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-md font-semibold border ${style.badge}`}
                        >
                          <Icon className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>{item.level}</span>
                        </span>
                        <span className="text-xs font-mono font-bold text-slate-300 bg-slate-900 px-2 py-1 rounded border border-slate-800">
                          {item.score} <span className="text-slate-500 font-normal">/ 100</span>
                        </span>
                      </div>

                      <button
                        type="button"
                        onClick={() => onSelectUrl(item.displayUrl)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 rounded-md transition-colors cursor-pointer"
                        title="Load into inspector without navigating"
                        aria-label={`Inspect ${item.hostname}`}
                      >
                        <span>Re-inspect</span>
                        <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Accessible Confirmation Modal Dialog */}
        {showConfirmModal && (
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="clear-history-title"
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-150"
          >
            <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 shadow-2xl shadow-black/80 space-y-4">
              <div className="flex items-start gap-3">
                <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 shrink-0">
                  <AlertCircle className="w-6 h-6" aria-hidden="true" />
                </div>
                <div>
                  <h3 id="clear-history-title" className="text-base font-bold text-white">
                    Clear Scan History?
                  </h3>
                  <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                    This will permanently delete all stored scan records from your browser's local storage. This action cannot be undone.
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowConfirmModal(false)}
                  className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-750 border border-slate-700 rounded-xl transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleConfirmClear}
                  className="px-4 py-2 text-xs font-medium text-white bg-rose-600 hover:bg-rose-500 border border-rose-500/30 rounded-xl transition-colors cursor-pointer shadow-md shadow-rose-950/40"
                >
                  Clear All History
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
