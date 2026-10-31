import {
  Globe,
  Lock,
  Unlock,
  Hash,
  Terminal,
  AlertCircle,
  CheckCircle2,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Loader2,
  Database,
  Network,
  Calendar,
  Mail,
  Server,
  GitCommit,
  ArrowRight,
  CornerDownRight,
  ChevronDown,
} from 'lucide-react';
import { useState } from 'react';
import { ParsedUrlDetails } from '../utils/urlParser';
import { assessUrlRisk, RiskAssessment } from '../utils/riskEngine';
import { ThreatIntelligenceState } from '../types/threat';
import { ReconClientState } from '../types/recon';
import { RedirectClientState } from '../types/redirect';
import { ScreenshotPreviewCard } from './ScreenshotPreviewCard';
import { generateScamAwarenessReport } from '../utils/warningEngine';
import { ScamAwarenessReport, WarningSeverity } from '../types/warning';

interface ScanResultsSectionProps {
  scannedResult: ParsedUrlDetails | null;
  threatState?: ThreatIntelligenceState;
  reconState?: ReconClientState;
  redirectState?: RedirectClientState;
}

export function ScanResultsSection({
  scannedResult,
  threatState = { status: 'idle' },
  reconState = { status: 'idle', data: null },
  redirectState = { status: 'idle', data: null },
}: ScanResultsSectionProps) {
  const [copied, setCopied] = useState(false);
  const [copiedHopIndex, setCopiedHopIndex] = useState<number | null>(null);
  const [expandedWarnings, setExpandedWarnings] = useState<Record<string, boolean>>({});

  const toggleWarningExpanded = (warnId: string, defaultOpen: boolean) => {
    setExpandedWarnings((prev) => ({
      ...prev,
      [warnId]: prev[warnId] !== undefined ? !prev[warnId] : !defaultOpen,
    }));
  };

  const handleCopyUrl = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCopyHopUrl = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedHopIndex(index);
    setTimeout(() => setCopiedHopIndex(null), 2000);
  };

  const assessment: RiskAssessment | null = scannedResult?.isValid
    ? assessUrlRisk(scannedResult)
    : null;

  const scamReport: ScamAwarenessReport | null = scannedResult?.isValid
    ? generateScamAwarenessReport({
        parsedUrl: scannedResult,
        assessment,
        threatState,
        reconState,
        redirectState,
      })
    : null;

  const getRiskLevelStyles = (level: string) => {
    switch (level) {
      case 'High':
        return {
          badge: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
          bar: 'bg-rose-500',
          text: 'text-rose-400',
          border: 'border-rose-500/20',
          icon: ShieldAlert,
        };
      case 'Medium':
        return {
          badge: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
          bar: 'bg-amber-500',
          text: 'text-amber-400',
          border: 'border-amber-500/20',
          icon: AlertTriangle,
        };
      default:
        return {
          badge: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
          bar: 'bg-emerald-500',
          text: 'text-emerald-400',
          border: 'border-emerald-500/20',
          icon: ShieldCheck,
        };
    }
  };

  const getWarningSeverityStyles = (severity: WarningSeverity) => {
    switch (severity) {
      case 'critical':
        return {
          badge: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
          card: 'bg-rose-950/20 border-rose-500/30',
          text: 'text-rose-400',
          label: 'CRITICAL THREAT',
          icon: ShieldAlert,
        };
      case 'high':
        return {
          badge: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
          card: 'bg-rose-950/15 border-rose-500/25',
          text: 'text-rose-400',
          label: 'HIGH RISK',
          icon: AlertTriangle,
        };
      case 'medium':
        return {
          badge: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
          card: 'bg-amber-950/15 border-amber-500/25',
          text: 'text-amber-400',
          label: 'MEDIUM RISK',
          icon: AlertCircle,
        };
      case 'low':
        return {
          badge: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
          card: 'bg-emerald-950/15 border-emerald-500/25',
          text: 'text-emerald-400',
          label: 'LOW RISK',
          icon: ShieldCheck,
        };
      default: // info
        return {
          badge: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
          card: 'bg-slate-900/60 border-slate-800',
          text: 'text-cyan-400',
          label: 'INCONCLUSIVE / INFO',
          icon: Info,
        };
    }
  };

  const getConfidenceBadge = (confidence: string) => {
    switch (confidence) {
      case 'confirmed':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      case 'suspicious':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'inconclusive':
        return 'bg-slate-800 text-slate-300 border-slate-700';
      default:
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    }
  };

  const riskStyles = assessment ? getRiskLevelStyles(assessment.level) : null;
  const RiskIcon = riskStyles?.icon || Info;

  return (
    <section aria-labelledby="scan-results-heading" className="w-full">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 sm:p-7 shadow-xl shadow-slate-950/40 backdrop-blur-sm">
        {/* Title */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-5 h-5 text-blue-400" aria-hidden="true" />
            <h2 id="scan-results-heading" className="text-lg font-bold text-white tracking-tight">
              Scan Results
            </h2>
          </div>
          {scannedResult && (
            <div className="text-xs text-slate-400 font-mono tabular-nums">
              Processed: {scannedResult.scannedAt}
            </div>
          )}
        </div>

        {/* Content */}
        {!scannedResult ? (
          /* Initial Empty State */
          <div className="py-12 sm:py-16 text-center">
            <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700/60 flex items-center justify-center mx-auto mb-4 text-slate-400">
              <Globe className="w-6 h-6 text-slate-400" aria-hidden="true" />
            </div>
            <p className="text-base sm:text-lg text-slate-300 font-medium max-w-md mx-auto">
              Paste a URL above to begin your security check.
            </p>
            <p className="text-xs sm:text-sm text-slate-500 mt-2 max-w-sm mx-auto">
              Inspect link structure, protocols, and subdomains safely without opening or navigating to the link.
            </p>
          </div>
        ) : !scannedResult.isValid ? (
          /* Invalid URL State - Strict validation message, no misleading risk score */
          <div className="py-8">
            <div className="flex items-start gap-3 p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-200">
              <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-sm">Validation Notice: Unable to parse URL</p>
                <p className="text-xs text-amber-300/80 mt-1">
                  The provided text does not appear to be a valid web URL. Please verify the URL structure or paste a complete web address.
                </p>
                <div className="mt-2 text-xs font-mono bg-slate-950/70 p-2 rounded text-slate-300 break-all">
                  {scannedResult.rawInput}
                </div>
              </div>
            </div>
          </div>
        ) : assessment ? (
          /* Scanned Result with Client-Side Risk Assessment Engine */
          <div className="pt-5 space-y-6">
            {/* 1. Transparent Risk Assessment Scorecard */}
            <div className={`bg-slate-950/90 border ${riskStyles?.border || 'border-slate-800'} rounded-xl p-5 shadow-lg`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
                <div className="flex items-start gap-3">
                  <div className={`p-2.5 rounded-xl border ${riskStyles?.badge}`}>
                    <RiskIcon className="w-6 h-6" aria-hidden="true" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                        Client-Side Risk Assessment
                      </span>
                      <span
                        className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${riskStyles?.badge}`}
                      >
                        {assessment.level} Risk
                      </span>
                    </div>
                    <h3 className="text-base sm:text-lg font-bold text-white mt-0.5">
                      {assessment.summaryMessage}
                    </h3>
                  </div>
                </div>

                {/* Numerical Score Gauge */}
                <div className="sm:text-right shrink-0 bg-slate-900/80 border border-slate-800 px-4 py-2.5 rounded-xl">
                  <div className="text-[11px] text-slate-400 uppercase font-semibold">
                    Heuristic Risk Score
                  </div>
                  <div className="text-2xl font-extrabold font-mono tabular-nums text-white flex items-baseline sm:justify-end gap-1">
                    <span className={riskStyles?.text}>{assessment.score}</span>
                    <span className="text-xs text-slate-500 font-normal">/ 100</span>
                  </div>
                </div>
              </div>

              {/* Visual Score Meter Bar */}
              <div className="mt-3">
                <div className="w-full h-2 bg-slate-800/80 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${riskStyles?.bar}`}
                    style={{ width: `${Math.max(4, assessment.score)}%` }}
                  />
                </div>
                <div className="flex justify-between text-[11px] text-slate-500 font-mono mt-1">
                  <span>0 (No patterns)</span>
                  <span>30 (Medium threshold)</span>
                  <span>60 (High threshold)</span>
                  <span>100</span>
                </div>
              </div>

              {/* Detected Heuristic Indicators */}
              <div className="mt-5">
                <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2.5">
                  Detected Heuristic Indicators ({assessment.indicators.length})
                </div>

                {assessment.indicators.length === 0 ? (
                  <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start gap-3">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-semibold text-emerald-400">
                        No obvious suspicious patterns detected
                      </p>
                      <p className="text-xs text-slate-400 mt-0.5">
                        None of the 10 structural risk rules were triggered. However, please note that the absence of obvious patterns does not guarantee that a link or website is safe or trustworthy.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {assessment.indicators.map((indicator) => (
                      <div
                        key={indicator.id}
                        className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/80 flex items-start justify-between gap-3"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-bold text-slate-200">
                              Rule {indicator.ruleNumber}: {indicator.name}
                            </span>
                            {indicator.evidence && (
                              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-blue-300">
                                {indicator.evidence}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">
                            {indicator.explanation}
                          </p>
                        </div>
                        <span className="shrink-0 text-xs font-mono font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-1 rounded">
                          +{indicator.points} pts
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Heuristic Disclaimer */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-start gap-2 text-xs text-slate-400">
                <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                <p>
                  <strong className="text-slate-300">Heuristic Engine Notice:</strong> {assessment.disclaimer}
                </p>
              </div>
            </div>

            {/* FEATURE: Evidence-Based Scam Awareness Warning Engine */}
            {scamReport && (
              <div
                className="bg-slate-950/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4 transition-all"
                aria-labelledby="scam-warnings-heading"
              >
                {/* Section Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3.5 border-b border-slate-800/80">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
                      <ShieldAlert className="w-5 h-5" aria-hidden="true" />
                    </div>
                    <div>
                      <h3
                        id="scam-warnings-heading"
                        className="text-base font-bold text-white tracking-tight flex items-center gap-2"
                      >
                        Scam Awareness Warning Engine
                        <span className="text-xs font-mono font-normal px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                          {scamReport.warnings.length} finding(s)
                        </span>
                      </h3>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Evidence-based safety guidance, scam scenarios, and practical next steps
                      </p>
                    </div>
                  </div>

                  {/* Summary Guidance Badge */}
                  <div className="self-start sm:self-auto">
                    {scamReport.hasConfirmedThreat ? (
                      <span className="text-xs font-semibold px-3 py-1 rounded-full border text-rose-400 bg-rose-500/10 border-rose-500/30">
                        Confirmed Threat Match
                      </span>
                    ) : scamReport.overallRiskLevel === 'High' ? (
                      <span className="text-xs font-semibold px-3 py-1 rounded-full border text-rose-400 bg-rose-500/10 border-rose-500/30">
                        High Concern Indicators
                      </span>
                    ) : scamReport.overallRiskLevel === 'Medium' ? (
                      <span className="text-xs font-semibold px-3 py-1 rounded-full border text-amber-400 bg-amber-500/10 border-amber-500/30">
                        Suspicious Indicators
                      </span>
                    ) : (
                      <span className="text-xs font-semibold px-3 py-1 rounded-full border text-emerald-400 bg-emerald-500/10 border-emerald-500/30">
                        Standard Web Structure
                      </span>
                    )}
                  </div>
                </div>

                {/* Primary Guidance Banner */}
                <div
                  className={`p-3.5 rounded-xl border text-xs sm:text-sm font-medium flex items-start gap-3 ${
                    scamReport.hasConfirmedThreat || scamReport.overallRiskLevel === 'High'
                      ? 'bg-rose-950/25 border-rose-500/30 text-rose-200'
                      : scamReport.overallRiskLevel === 'Medium'
                      ? 'bg-amber-950/20 border-amber-500/30 text-amber-200'
                      : 'bg-blue-950/20 border-blue-500/30 text-slate-200'
                  }`}
                >
                  <AlertCircle className="w-5 h-5 shrink-0 mt-0.5 text-current" aria-hidden="true" />
                  <div className="space-y-1">
                    <p className="font-semibold">{scamReport.summaryGuidance}</p>
                  </div>
                </div>

                {/* Warning Cards List */}
                <div className="space-y-3 pt-1">
                  {scamReport.warnings.map((warn) => {
                    const styles = getWarningSeverityStyles(warn.severity);
                    const WarnIcon = styles.icon;
                    const confidenceBadgeClass = getConfidenceBadge(warn.confidence);
                    const isDefaultOpen = warn.severity === 'critical';
                    const isOpen =
                      expandedWarnings[warn.id] !== undefined
                        ? expandedWarnings[warn.id]
                        : isDefaultOpen;

                    return (
                      <div
                        key={warn.id}
                        className={`p-4 rounded-xl border ${styles.card} transition-all space-y-3`}
                      >
                        {/* Warning Header */}
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <WarnIcon className={`w-4 h-4 ${styles.text} shrink-0`} aria-hidden="true" />
                            <span className="text-sm font-bold text-white">{warn.title}</span>
                          </div>

                          <div className="flex items-center gap-1.5 flex-wrap">
                            {/* Accessible severity badge with explicit text */}
                            <span
                              className={`text-[11px] font-semibold px-2.5 py-0.5 rounded-full border ${styles.badge}`}
                            >
                              {styles.label}
                            </span>
                            {/* Confidence / Status label */}
                            <span
                              className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded-full border ${confidenceBadgeClass}`}
                            >
                              {warn.confidence}
                            </span>
                          </div>
                        </div>

                        {/* Observed Evidence Chips - Primary evidence immediately visible */}
                        {warn.evidence && warn.evidence.length > 0 && (
                          <div className="space-y-1.5 bg-slate-950/70 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                              Observed Evidence ({warn.evidence.length})
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {warn.evidence.map((ev, i) => (
                                <span
                                  key={i}
                                  className="text-xs font-mono bg-slate-900 border border-slate-700/80 text-blue-300 px-2 py-1 rounded"
                                >
                                  {ev}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Practical Recommendation - Primary action immediately visible */}
                        <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-200 flex items-start gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
                          <div>
                            <span className="font-semibold text-white block mb-0.5">
                              Recommended Action:
                            </span>
                            <span className="text-slate-300 leading-relaxed">
                              {warn.recommendedAction}
                            </span>
                          </div>
                        </div>

                        {/* Secondary Technical Explanations & Scenario - Accessible Expandable Section */}
                        {(warn.explanation || warn.potentialScamScenario) && (
                          <div className="rounded-lg bg-slate-950/60 border border-slate-800/80 overflow-hidden">
                            <button
                              type="button"
                              onClick={() => toggleWarningExpanded(warn.id, isDefaultOpen)}
                              aria-expanded={isOpen}
                              aria-controls={`warning-details-${warn.id}`}
                              className="w-full flex items-center justify-between gap-2 px-3 py-2 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 transition-colors cursor-pointer select-none focus:outline-none focus:ring-1 focus:ring-blue-500/50"
                            >
                              <span className="font-semibold text-[11px] uppercase tracking-wider flex items-center gap-1.5 text-slate-400">
                                <Info className="w-3.5 h-3.5 text-blue-400" aria-hidden="true" />
                                Technical Breakdown & Threat Analysis
                              </span>
                              <span className="flex items-center gap-1 text-[11px] text-slate-400">
                                <span>{isOpen ? 'Hide technical details' : 'Show technical details'}</span>
                                <ChevronDown
                                  className={`w-3.5 h-3.5 transition-transform duration-200 ${
                                    isOpen ? 'rotate-180' : ''
                                  }`}
                                  aria-hidden="true"
                                />
                              </span>
                            </button>

                            {isOpen && (
                              <div
                                id={`warning-details-${warn.id}`}
                                className="p-3 pt-2.5 space-y-2.5 border-t border-slate-800/60 bg-slate-950/80 text-xs"
                              >
                                {warn.explanation && (
                                  <div>
                                    <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block mb-0.5">
                                      Why this matters / Technical Context:
                                    </span>
                                    <p className="text-xs text-slate-300 leading-relaxed">
                                      {warn.explanation}
                                    </p>
                                  </div>
                                )}

                                {warn.potentialScamScenario && (
                                  <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-200 flex items-start gap-2.5">
                                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
                                    <div>
                                      <span className="font-semibold text-amber-300 block mb-0.5">
                                        Possible Scam Scenario:
                                      </span>
                                      <span className="text-amber-200/90 leading-relaxed">
                                        {warn.potentialScamScenario}
                                      </span>
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* Bottom Disclaimer */}
                <div className="pt-2 border-t border-slate-800/80 flex items-start gap-2 text-[11px] text-slate-400">
                  <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                  <p>
                    <strong className="text-slate-300">Warning Engine Notice:</strong> {scamReport.disclaimer}
                  </p>
                </div>
              </div>
            )}

            {/* 2. Threat Intelligence Feed: Google Safe Browsing */}
            {threatState && threatState.status !== 'idle' && (
              <div
                className={`rounded-xl border p-4 sm:p-5 transition-all shadow-md ${
                  threatState.status === 'threat_detected'
                    ? 'bg-rose-950/20 border-rose-500/30 text-rose-200'
                    : threatState.status === 'clean'
                    ? 'bg-blue-950/20 border-blue-500/30 text-slate-200'
                    : threatState.status === 'checking'
                    ? 'bg-slate-950/70 border-slate-800 text-slate-300'
                    : threatState.status === 'unavailable'
                    ? 'bg-amber-500/10 border-amber-500/20 text-amber-200'
                    : 'bg-slate-950/60 border-slate-800 text-slate-300'
                }`}
              >
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-blue-400" aria-hidden="true" />
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      External Threat Intelligence · Google Safe Browsing
                    </span>
                  </div>

                  {threatState.status === 'checking' && (
                    <span className="inline-flex items-center gap-1.5 text-xs text-blue-400 font-mono">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      Checking...
                    </span>
                  )}
                  {threatState.status === 'threat_detected' && (
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      Threat Detected
                    </span>
                  )}
                  {threatState.status === 'clean' && (
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      Clean Record
                    </span>
                  )}
                  {threatState.status === 'unconfigured' && (
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                      Unconfigured
                    </span>
                  )}
                  {threatState.status === 'unavailable' && (
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                      Unavailable
                    </span>
                  )}
                </div>

                {/* State: Checking */}
                {threatState.status === 'checking' && (
                  <div className="flex items-center gap-3 py-1 text-xs text-slate-400">
                    <p>Querying Google Safe Browsing v4 threatMatches database via server proxy...</p>
                  </div>
                )}

                {/* State: Threat Detected */}
                {threatState.status === 'threat_detected' && (
                  <div className="space-y-2">
                    <div className="flex items-start gap-2.5 text-rose-300 font-semibold text-sm">
                      <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                      <div>
                        <p>High-Concern Threat Record Detected by Google Safe Browsing</p>
                        {threatState.threatTypes && threatState.threatTypes.length > 0 && (
                          <p className="text-xs font-mono text-rose-400 mt-1">
                            Flagged Threat Category: {threatState.threatTypes.join(', ')}
                          </p>
                        )}
                      </div>
                    </div>
                    <p className="text-xs text-rose-200/90 leading-relaxed">
                      This destination address is explicitly cataloged as an active threat in Google Safe Browsing feeds. Do not navigate to this site, download files, or submit login credentials.
                    </p>
                  </div>
                )}

                {/* State: Clean Record */}
                {threatState.status === 'clean' && (
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                      <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>No threat records found in Google Safe Browsing. This does not guarantee the URL is safe.</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Zero matches were returned by the Safe Browsing list at this time. However, newly registered phishing campaigns and evasive domains may not yet be cataloged in public threat lists. Always verify sender identity directly.
                    </p>
                  </div>
                )}

                {/* State: Unconfigured */}
                {threatState.status === 'unconfigured' && (
                  <div className="space-y-1 text-xs text-slate-400">
                    <div className="flex items-center gap-2 text-slate-300 font-medium">
                      <Info className="w-4 h-4 text-blue-400 shrink-0" />
                      <span>Threat intelligence is not configured on this server. Running offline structural heuristic mode only.</span>
                    </div>
                    <p className="text-slate-500">
                      Local heuristic risk analysis, port checks, credential detection, and structural decomposition above remain 100% active and functional.
                    </p>
                  </div>
                )}

                {/* State: Temporarily Unavailable */}
                {threatState.status === 'unavailable' && (
                  <div className="space-y-1 text-xs text-amber-300">
                    <div className="flex items-center gap-2 font-medium">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>Threat intelligence service is temporarily unavailable. Local heuristic analysis remains active.</span>
                    </div>
                    <p className="text-xs text-amber-200/80">
                      The server-side threat check could not be completed at this time. Please rely on the client-side structural analysis and exercise caution.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* 3. Domain & DNS Reconnaissance Panel */}
            {reconState && reconState.status !== 'idle' && (
              <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 sm:p-5 shadow-md space-y-4">
                {/* Header */}
                <div className="flex items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <Network className="w-4 h-4 text-blue-400" aria-hidden="true" />
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      Domain & DNS Reconnaissance · Host Infrastructure Analysis
                    </span>
                  </div>

                  {reconState.status === 'checking' && (
                    <span className="inline-flex items-center gap-1.5 text-xs text-blue-400 font-mono">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      Resolving...
                    </span>
                  )}
                  {reconState.status === 'completed' && (
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      Recon Complete
                    </span>
                  )}
                  {reconState.status === 'error' && (
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      Recon Unavailable
                    </span>
                  )}
                </div>

                {/* Body: Checking */}
                {reconState.status === 'checking' && (
                  <div className="flex items-center gap-3 py-2 text-xs text-slate-400">
                    <p>
                      Querying authoritative DNS records (A, AAAA, MX) and RDAP domain registration database...
                    </p>
                  </div>
                )}

                {/* Body: Error / Unavailable */}
                {reconState.status === 'error' && (
                  <div className="flex items-start gap-2.5 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-200">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <p className="font-semibold">Reconnaissance Service Unavailable</p>
                      <p className="text-amber-300/80 mt-0.5">
                        {reconState.errorMessage ||
                          'Unable to query DNS or domain registration records at this time. Local heuristic analysis remains active above.'}
                      </p>
                    </div>
                  </div>
                )}

                {/* Body: Completed Data */}
                {reconState.status === 'completed' && reconState.data && (
                  <div className="space-y-4">
                    {/* 3 Infrastructure Summary Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      {/* 1. Domain Registration Age (RDAP) */}
                      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                            <span className="flex items-center gap-1.5">
                              <Calendar className="w-3.5 h-3.5 text-blue-400" />
                              Domain Age (RDAP)
                            </span>
                            {reconState.data.rdap.status === 'available' &&
                            typeof reconState.data.rdap.domainAgeDays === 'number' ? (
                              reconState.data.rdap.domainAgeDays <= 30 ? (
                                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">
                                  Newly Registered
                                </span>
                              ) : (
                                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                  Established
                                </span>
                              )
                            ) : null}
                          </div>

                          <div className="text-base font-bold font-mono text-white mt-1">
                            {reconState.data.rdap.status === 'available' &&
                            typeof reconState.data.rdap.domainAgeDays === 'number'
                              ? `${reconState.data.rdap.domainAgeDays.toLocaleString()} days`
                              : reconState.data.rdap.status === 'redacted'
                              ? 'Date Redacted'
                              : reconState.data.rdap.status === 'unsupported'
                              ? 'TLD Unsupported'
                              : reconState.data.isIpAddress
                              ? 'Direct IP'
                              : 'Unavailable'}
                          </div>
                        </div>

                        <p className="text-xs text-slate-400 mt-2">
                          {reconState.data.rdap.registrationDate
                            ? `Registered on ${new Date(reconState.data.rdap.registrationDate).toLocaleDateString()}`
                            : reconState.data.rdap.registrar
                            ? `Registrar: ${reconState.data.rdap.registrar}`
                            : 'Withheld under privacy policy or not disclosed by registry.'}
                        </p>
                      </div>

                      {/* 2. DNS IP Resolution (A & AAAA) */}
                      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                            <span className="flex items-center gap-1.5">
                              <Server className="w-3.5 h-3.5 text-blue-400" />
                              DNS Endpoints
                            </span>
                            <span
                              className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                                reconState.data.dns.status === 'resolved'
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : reconState.data.dns.status === 'nxdomain'
                                  ? 'bg-slate-800 text-slate-400 border border-slate-700'
                                  : 'bg-slate-800 text-slate-400'
                              }`}
                            >
                              {reconState.data.dns.status === 'resolved'
                                ? 'Resolved'
                                : reconState.data.dns.status === 'nxdomain'
                                ? 'NXDOMAIN'
                                : reconState.data.isIpAddress
                                ? 'Direct IP'
                                : reconState.data.dns.status}
                            </span>
                          </div>

                          <div className="text-base font-bold font-mono text-white mt-1">
                            {reconState.data.dns.status === 'resolved'
                              ? `${reconState.data.dns.aCount} IPv4 · ${reconState.data.dns.aaaaCount} IPv6`
                              : reconState.data.dns.status === 'nxdomain'
                              ? 'No DNS Records'
                              : reconState.data.isIpAddress
                              ? 'IP Host'
                              : reconState.data.dns.status}
                          </div>
                        </div>

                        <p className="text-xs text-slate-400 font-mono truncate mt-2">
                          {reconState.data.dns.aRecords.length > 0
                            ? `IP: ${reconState.data.dns.aRecords.slice(0, 2).join(', ')}`
                            : reconState.data.dns.message || 'No active IP endpoints resolved.'}
                        </p>
                      </div>

                      {/* 3. Mail Exchange (MX) */}
                      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
                        <div>
                          <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                            <span className="flex items-center gap-1.5">
                              <Mail className="w-3.5 h-3.5 text-blue-400" />
                              Mail Exchange (MX)
                            </span>
                            <span
                              className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                                reconState.data.dns.hasMailExchange
                                  ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                  : 'bg-slate-800 text-slate-400 border border-slate-700'
                              }`}
                            >
                              {reconState.data.dns.hasMailExchange ? 'Configured' : 'No MX'}
                            </span>
                          </div>

                          <div className="text-base font-bold font-mono text-white mt-1">
                            {reconState.data.dns.mxCount > 0
                              ? `${reconState.data.dns.mxCount} Mail Server(s)`
                              : 'No MX Records'}
                          </div>
                        </div>

                        <p className="text-xs text-slate-400 font-mono truncate mt-2">
                          {reconState.data.dns.mxRecords.length > 0
                            ? reconState.data.dns.mxRecords[0]?.exchange
                            : 'No email servers configured (common for web-only services).'}
                        </p>
                      </div>
                    </div>

                    {/* Reconnaissance Findings List */}
                    {reconState.data.findings.length > 0 && (
                      <div className="space-y-2 pt-1">
                        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                          Reconnaissance Observations ({reconState.data.findings.length})
                        </div>
                        <div className="space-y-2">
                          {reconState.data.findings.map((finding) => (
                            <div
                              key={finding.id}
                              className={`p-3 rounded-lg border text-xs leading-relaxed flex items-start gap-2.5 ${
                                finding.severity === 'warning'
                                  ? 'bg-rose-950/20 border-rose-500/30 text-rose-200'
                                  : finding.severity === 'info'
                                  ? 'bg-blue-950/20 border-blue-500/30 text-blue-200'
                                  : 'bg-slate-900/60 border-slate-800 text-slate-300'
                              }`}
                            >
                              {finding.severity === 'warning' ? (
                                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                              ) : finding.severity === 'info' ? (
                                <CheckCircle2 className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                              ) : (
                                <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                              )}
                              <div>
                                <span className="font-bold text-white block mb-0.5">
                                  {finding.title}
                                </span>
                                {finding.explanation}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Disclaimer */}
                    <div className="pt-2 border-t border-slate-800/80 flex items-start gap-2 text-[11px] text-slate-400">
                      <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                      <p>
                        <strong className="text-slate-300">Reconnaissance Notice:</strong> DNS records and domain age provide infrastructure context, not definitive proof of malicious activity or absolute safety. Missing MX records or unlisted registration dates do not alter the baseline heuristic risk score.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* FEATURE: HTTP Redirect Chain Inspection */}
            {redirectState.status !== 'idle' && (
              <div
                className="bg-slate-950/90 border border-slate-800 rounded-xl p-4 sm:p-5 transition-all"
                aria-labelledby="redirect-inspection-heading"
              >
                {/* Header */}
                <div className="flex flex-wrap items-center justify-between gap-2.5 pb-3.5 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <GitCommit className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                    <h3
                      id="redirect-inspection-heading"
                      className="text-sm font-semibold text-white tracking-wide"
                    >
                      HTTP Redirect Chain Inspection
                    </h3>
                  </div>

                  {/* Status Badge */}
                  {redirectState.status === 'checking' && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Tracing hops...
                    </span>
                  )}
                  {redirectState.status === 'unavailable' && (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                      Unavailable
                    </span>
                  )}
                  {redirectState.status === 'completed' && redirectState.data && (
                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                        redirectState.data.status === 'BLOCKED_SPECIAL_USE_IP'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                          : redirectState.data.status === 'REDIRECT_LOOP' || redirectState.data.status === 'MAX_HOPS_EXCEEDED'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          : redirectState.data.totalRedirects === 0
                          ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {redirectState.data.status === 'BLOCKED_SPECIAL_USE_IP'
                        ? 'Blocked Destination'
                        : redirectState.data.status === 'REDIRECT_LOOP'
                        ? 'Redirect Loop'
                        : redirectState.data.status === 'MAX_HOPS_EXCEEDED'
                        ? 'Max Hops Exceeded'
                        : redirectState.data.totalRedirects === 0
                        ? 'Direct (0 Redirects)'
                        : `${redirectState.data.totalRedirects} Redirect(s)`}
                    </span>
                  )}
                </div>

                {/* Body Content */}
                {redirectState.status === 'checking' && (
                  <div className="py-6 flex items-center justify-center gap-3 text-slate-400 text-xs">
                    <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                    <span>Analyzing HTTP redirect headers safely (max 5 hops, SSRF guards active)...</span>
                  </div>
                )}

                {redirectState.status === 'unavailable' && (
                  <div className="py-4 text-xs text-slate-400 flex items-start gap-2">
                    <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                    <span>
                      {redirectState.errorMessage || 'Redirect inspection service is temporarily offline. Local heuristic analysis remains active.'}
                    </span>
                  </div>
                )}

                {redirectState.status === 'completed' && redirectState.data && (
                  <div className="mt-4 space-y-4">
                    {/* Status Message */}
                    <div className="text-xs text-slate-300 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                      <span className="font-semibold text-white">Inspection Result: </span>
                      {redirectState.data.statusMessage}
                    </div>

                    {/* Timeline Hop Cards */}
                    <div className="relative pl-4 border-l-2 border-slate-800 space-y-4">
                      {redirectState.data.hops.map((hop, idx) => {
                        const isLast = idx === redirectState.data!.hops.length - 1;
                        const isRedirectStatus = [301, 302, 303, 307, 308].includes(hop.statusCode);
                        const isBlocked = hop.statusCode === 0;

                        return (
                          <div key={hop.hopIndex} className="relative group">
                            {/* Dot on line */}
                            <div
                              className={`absolute -left-[23px] top-3.5 w-3 h-3 rounded-full border-2 bg-slate-950 ${
                                isBlocked
                                  ? 'border-rose-500'
                                  : isRedirectStatus
                                  ? 'border-amber-400'
                                  : 'border-emerald-400'
                              }`}
                            />

                            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-2">
                              {/* Hop Header Meta */}
                              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                                <div className="flex items-center gap-2">
                                  <span className="font-bold text-white">Hop {hop.hopIndex}</span>
                                  {/* Status code badge */}
                                  <span
                                    className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${
                                      isBlocked
                                        ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                                        : isRedirectStatus
                                        ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                        : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                    }`}
                                  >
                                    {isBlocked ? 'Blocked' : `${hop.statusCode} ${hop.statusText}`}
                                  </span>

                                  {/* Protocol badge */}
                                  <span
                                    className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium ${
                                      hop.isHttps
                                        ? 'bg-emerald-500/10 text-emerald-400'
                                        : 'bg-amber-500/10 text-amber-400'
                                    }`}
                                  >
                                    {hop.isHttps ? (
                                      <>
                                        <Lock className="w-2.5 h-2.5" />
                                        HTTPS
                                      </>
                                    ) : (
                                      <>
                                        <Unlock className="w-2.5 h-2.5" />
                                        HTTP
                                      </>
                                    )}
                                  </span>
                                </div>

                                <div className="flex items-center gap-3 text-[11px] text-slate-400">
                                  {hop.resolvedIp && (
                                    <span className="font-mono text-slate-400">IP: {hop.resolvedIp}</span>
                                  )}
                                  {hop.durationMs > 0 && <span>{hop.durationMs}ms</span>}
                                </div>
                              </div>

                              {/* Hop URL Display with safe copy (selectable text, never clickable link) */}
                              <div className="flex items-center justify-between gap-2 bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80">
                                <span className="font-mono text-xs text-blue-300 break-all select-all">
                                  {hop.url}
                                </span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyHopUrl(hop.url, hop.hopIndex)}
                                  className="text-slate-400 hover:text-cyan-400 shrink-0 p-1 rounded transition-colors cursor-pointer"
                                  title="Copy URL"
                                  aria-label={`Copy URL for Hop ${hop.hopIndex}`}
                                >
                                  {copiedHopIndex === hop.hopIndex ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>
                              </div>

                              {/* Redirect Location pointer */}
                              {hop.locationHeader && !isLast && (
                                <div className="flex items-center gap-1.5 text-[11px] text-amber-400/90 pl-1">
                                  <CornerDownRight className="w-3.5 h-3.5 shrink-0" />
                                  <span className="truncate">Redirects to: <span className="font-mono">{hop.locationHeader}</span></span>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Findings */}
                    {redirectState.data.findings.length > 0 && (
                      <div className="space-y-2 pt-1">
                        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                          Chain Security Findings ({redirectState.data.findings.length})
                        </div>
                        <div className="space-y-2">
                          {redirectState.data.findings.map((f) => (
                            <div
                              key={f.id}
                              className={`p-3 rounded-lg border text-xs leading-relaxed flex items-start gap-2.5 ${
                                f.severity === 'critical'
                                  ? 'bg-rose-950/20 border-rose-500/30 text-rose-200'
                                  : f.severity === 'warning'
                                  ? 'bg-amber-950/20 border-amber-500/30 text-amber-200'
                                  : 'bg-blue-950/20 border-blue-500/30 text-blue-200'
                              }`}
                            >
                              {f.severity === 'critical' ? (
                                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                              ) : f.severity === 'warning' ? (
                                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                              ) : (
                                <CheckCircle2 className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                              )}
                              <div>
                                <span className="font-bold text-white block mb-0.5">{f.title}</span>
                                {f.description}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Disclaimer */}
                    <div className="pt-2 border-t border-slate-800/80 flex items-start gap-2 text-[11px] text-slate-400">
                      <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <p>
                        <strong className="text-slate-300">Headers-only inspection:</strong> Page scripts and response content were not retrieved or executed. Redirect analysis cannot guarantee that a destination is safe.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 4. Scanned URL Display with Safe Copy */}
            <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Target URL (Safe Display)
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyUrl(scannedResult.normalizedUrl)}
                  className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-blue-400 transition-colors cursor-pointer"
                  title="Copy URL"
                  aria-label="Copy inspected URL"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy link</span>
                    </>
                  )}
                </button>
              </div>
              <div className="font-mono text-sm text-blue-300 break-all select-all bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
                {scannedResult.normalizedUrl}
              </div>
              <p className="text-[11px] text-slate-400 mt-2">
                Note: This link is rendered safely as plain text and will not automatically execute or navigate.
              </p>
            </div>

            {/* 5. URL Structural Elements Grid */}
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                Client-Side Structural Analysis
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {/* Protocol Card */}
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                    <span>Protocol Scheme</span>
                    {scannedResult.isHttps ? (
                      <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Unlock className="w-3.5 h-3.5 text-amber-400" />
                    )}
                  </div>
                  <div className="text-sm font-semibold font-mono text-slate-200">
                    {scannedResult.protocol}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    {scannedResult.isHttps ? 'Encrypted TLS transport (note: does not alone guarantee safety)' : 'Unencrypted transport'}
                  </p>
                </div>

                {/* Hostname / Domain */}
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                    <span>Host / Domain</span>
                    <Globe className="w-3.5 h-3.5 text-blue-400" />
                  </div>
                  <div className="text-sm font-semibold font-mono text-slate-200 break-all">
                    {scannedResult.hostname}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    {scannedResult.isIpAddress ? 'Direct numeric IP address' : 'Standard domain name'}
                  </p>
                </div>

                {/* Subdomain depth */}
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                    <span>Subdomains</span>
                    <span className="font-mono tabular-nums text-slate-300">
                      {scannedResult.subdomainCount}
                    </span>
                  </div>
                  <div className="text-sm font-semibold font-mono text-slate-200">
                    {scannedResult.subdomainCount === 0 ? 'Root domain' : `${scannedResult.subdomainCount} subdomain level(s)`}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    Hierarchy within target host
                  </p>
                </div>

                {/* Pathname */}
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                    <span>Resource Path</span>
                    <span className="text-[11px] text-slate-400 font-mono">
                      {scannedResult.pathname.length} chars
                    </span>
                  </div>
                  <div className="text-sm font-semibold font-mono text-slate-200 break-all">
                    {scannedResult.pathname}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    Endpoint requested on host
                  </p>
                </div>

                {/* Query Parameters */}
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                    <span>Query Parameters</span>
                    <Hash className="w-3.5 h-3.5 text-blue-400" />
                  </div>
                  <div className="text-sm font-semibold font-mono text-slate-200">
                    {scannedResult.paramCount} parameter(s) detected
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    {scannedResult.paramCount > 0 ? 'URL carries tracking or session data' : 'No query parameters attached'}
                  </p>
                </div>

                {/* Port Configuration */}
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                    <span>Network Port</span>
                    <span className="text-[11px] text-slate-400 font-mono">
                      {scannedResult.port}
                    </span>
                  </div>
                  <div className="text-sm font-semibold font-mono text-slate-200">
                    Port {scannedResult.port}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    Destination network port
                  </p>
                </div>
              </div>
            </div>

            {/* Query parameters list breakdown (if any) */}
            {scannedResult.paramsList.length > 0 && (
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
                  Parameters List ({scannedResult.paramsList.length})
                </span>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 pr-4 font-medium">Parameter Name</th>
                        <th className="py-2 font-medium">Value</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {scannedResult.paramsList.map((param, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="py-2 pr-4 text-blue-400 font-semibold">{param.key}</td>
                          <td className="py-2 text-slate-300 break-all">{param.value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Structural Markers Identified */}
            <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <CheckCircle2 className="w-4 h-4 text-blue-400" />
                Structural Markers Identified
              </div>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                <li>
                  <span className="font-medium text-slate-200">Host Type:</span>{' '}
                  {scannedResult.isIpv4
                    ? `Direct IPv4 address (${scannedResult.hostname})`
                    : scannedResult.isIpv6
                    ? `Direct IPv6 address (${scannedResult.hostname})`
                    : `Registered domain name (${scannedResult.hostname})`}
                </li>
                <li>
                  <span className="font-medium text-slate-200">Transport:</span>{' '}
                  {scannedResult.isHttps
                    ? 'HTTPS protocol with TLS encryption.'
                    : 'Unencrypted HTTP protocol.'}
                </li>
                <li>
                  <span className="font-medium text-slate-200">Authority Credentials:</span>{' '}
                  {scannedResult.hasAuthorityCredentials
                    ? `Credentials embedded in authority ("${scannedResult.username}@"). True destination host is "${scannedResult.hostname}".`
                    : 'No embedded authority credentials.'}
                </li>
                <li>
                  <span className="font-medium text-slate-200">Network Port:</span>{' '}
                  {scannedResult.isNonStandardPort
                    ? `Non-standard port :${scannedResult.explicitPort} (${scannedResult.explicitPort === '8080' ? 'alternative/non-default HTTP port; ' : ''}standard defaults are 80 for HTTP and 443 for HTTPS; not proof of malicious activity).`
                    : `Standard default port (${scannedResult.port}).`}
                </li>
                <li>
                  <span className="font-medium text-slate-200">Character Encoding:</span>{' '}
                  {scannedResult.hasPunycode
                    ? 'Contains "xn--" Punycode label (internationalized domain name encoding).'
                    : 'Standard ASCII character domain.'}
                </li>
              </ul>
            </div>

            {/* 7. Website Visual Preview (Isolated Cloud Render) */}
            <ScreenshotPreviewCard targetUrl={scannedResult.normalizedUrl} />
          </div>
        ) : null}
      </div>
    </section>
  );
}
