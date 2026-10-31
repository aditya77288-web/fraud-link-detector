import {
  AlertTriangle,
  ShieldCheck,
  Cpu,
  Server,
  Database,
  Camera,
  HardDrive,
  Info,
} from 'lucide-react';

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

      {/* Accurate Privacy & URL Processing Architecture Disclosures */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-lg shadow-slate-950/20 space-y-4">
        <div className="flex items-start gap-3.5 pb-3 border-b border-slate-800">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 shrink-0">
            <ShieldCheck className="w-5 h-5 text-blue-400" aria-hidden="true" />
          </div>
          <div>
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Privacy Architecture & Data Handling
            </h2>
            <p className="text-sm text-slate-200 font-medium">
              Transparent disclosure of where and how links are processed across all application layers.
            </p>
          </div>
        </div>

        {/* 5 Distinct Architectural Layers */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 pt-1">
          {/* 1. Client-Side URL Structural Analysis */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-start gap-3">
            <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 shrink-0 mt-0.5">
              <Cpu className="w-4 h-4" aria-hidden="true" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white">Client-Side Structural Analysis</span>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 border border-emerald-800/80 px-1.5 py-0.2 rounded">
                  Local Browser Only
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Initial URL normalization, protocol parsing, credential extraction, punycode decoding, and the 10 heuristic risk scoring rules run 100% locally in your browser. This instant structural evaluation generates zero external network traffic.
              </p>
            </div>
          </div>

          {/* 2. Backend Application Requests */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-start gap-3">
            <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 shrink-0 mt-0.5">
              <Server className="w-4 h-4" aria-hidden="true" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white">Application Backend Requests</span>
                <span className="text-[10px] font-mono text-blue-400 bg-blue-950/80 border border-blue-800/80 px-1.5 py-0.2 rounded">
                  Internal Server
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                When a valid link is scanned, the browser contacts our Express backend to perform DNS resolution, RDAP domain registration age queries, and hop-by-hop HTTP redirect inspection (headers-only, max 5 hops) with strict server-side SSRF blocks. All API endpoints enforce <code className="text-blue-300 font-mono">Cache-Control: no-store</code> and never persist links to server databases.
              </p>
            </div>
          </div>

          {/* 3. Optional External Threat-Intelligence Checks */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-start gap-3">
            <div className="p-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 shrink-0 mt-0.5">
              <Database className="w-4 h-4" aria-hidden="true" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white">External Threat Intelligence</span>
                <span className="text-[10px] font-mono text-indigo-300 bg-indigo-950/80 border border-indigo-800/80 px-1.5 py-0.2 rounded">
                  Optional Google Safe Browsing
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                If an administrator has configured a server-side <code className="text-indigo-300 font-mono">GOOGLE_SAFE_BROWSING_API_KEY</code>, the backend queries the Google Safe Browsing v4 API to identify known malware and deceptive threat records. If unconfigured, this external lookup is skipped entirely, operating in offline structural heuristic mode.
              </p>
            </div>
          </div>

          {/* 4. External Screenshot Rendering */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-start gap-3">
            <div className="p-1.5 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 shrink-0 mt-0.5">
              <Camera className="w-4 h-4" aria-hidden="true" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white">Visual Screenshot Rendering</span>
                <span className="text-[10px] font-mono text-purple-300 bg-purple-950/80 border border-purple-800/80 px-1.5 py-0.2 rounded">
                  Explicit User Click Only
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Website screenshot previews are strictly on-demand. An external rendering service (Microlink API) is contacted <em>only</em> when you explicitly click &ldquo;Capture Visual Preview&rdquo;. Rendered image buffers are streamed ephemerally to your browser without being saved to server disk. The external provider may temporarily cache public page captures on its CDN.
              </p>
            </div>
          </div>
        </div>

        {/* 5. Local Browser History Storage */}
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-start gap-3">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0 mt-0.5">
            <HardDrive className="w-4 h-4" aria-hidden="true" />
          </div>
          <div className="space-y-1 w-full">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="text-xs font-bold text-white">Local Browser History Storage</span>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/80 border border-cyan-800/80 px-1.5 py-0.2 rounded">
                localStorage · Zero Cloud Storage
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Your recent scan history (capped at 10 items) is retained exclusively on your device inside browser <code className="text-cyan-300 font-mono">localStorage</code>. Sensitive URL query parameters (such as tokens, session keys, and passwords) are automatically redacted before storage. Scan history is never transmitted to or synchronized with remote servers, and can be permanently deleted at any moment via the &ldquo;Clear History&rdquo; button.
            </p>
          </div>
        </div>

        {/* Summary Transparency Note */}
        <div className="pt-2 border-t border-slate-800/80 flex items-center gap-2 text-[11px] text-slate-400">
          <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" aria-hidden="true" />
          <span>
            We do not sell data, track user identities, or store submitted URLs on remote databases. All remote lookups are purpose-specific, ephemeral, and protected by SSRF controls.
          </span>
        </div>
      </div>
    </section>
  );
}
