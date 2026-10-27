import { AlertTriangle, ShieldCheck } from 'lucide-react';

export function SafetyNotice() {
  return (
    <section aria-label="Security and Privacy Notices" className="w-full space-y-4">
      {/* Required Safety Notice */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 sm:p-5 flex items-start gap-3.5 shadow-lg shadow-slate-950/20">
        <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 shrink-0">
          <AlertTriangle className="w-5 h-5 text-amber-400" aria-hidden="true" />
        </div>
        <div>
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            Safety Notice
          </h2>
          <p className="text-sm font-medium text-slate-200 leading-relaxed">
            Security checks can identify suspicious indicators but cannot guarantee that a website is safe.
          </p>
          <p className="text-xs text-slate-400 mt-1">
            Always verify sender identity directly through trusted channels before providing credentials, making payments, or downloading attachments.
          </p>
        </div>
      </div>

      {/* Privacy Guarantee */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 sm:p-5 flex items-start gap-3.5 shadow-lg shadow-slate-950/20">
        <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 shrink-0">
          <ShieldCheck className="w-5 h-5 text-blue-400" aria-hidden="true" />
        </div>
        <div>
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            Privacy Guarantee
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            For this initial version, submitted URLs are processed locally in your browser. URLs are never transmitted to external services, logged on remote servers, or stored permanently.
          </p>
        </div>
      </div>
    </section>
  );
}
