import { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { UrlInputSection } from './components/UrlInputSection';
import { ScanResultsSection } from './components/ScanResultsSection';
import { RecentScansSection } from './components/RecentScansSection';
import { SafetyNotice } from './components/SafetyNotice';
import { PlatformTips } from './components/PlatformTips';
import { parseUrl, ParsedUrlDetails } from './utils/urlParser';
import { assessUrlRisk } from './utils/riskEngine';
import {
  loadScanHistory,
  addScanToHistory,
  clearScanHistory,
  ScanHistoryItem,
} from './utils/historyStorage';
import { ThreatIntelligenceState } from './types/threat';
import { ReconClientState } from './types/recon';
import { RedirectClientState } from './types/redirect';

export default function App() {
  const [inputUrl, setInputUrl] = useState('');
  const [scannedResult, setScannedResult] = useState<ParsedUrlDetails | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [threatState, setThreatState] = useState<ThreatIntelligenceState>({ status: 'idle' });
  const [reconState, setReconState] = useState<ReconClientState>({ status: 'idle', data: null });
  const [redirectState, setRedirectState] = useState<RedirectClientState>({ status: 'idle', data: null });

  // Load existing scan history from localStorage on initial render
  useEffect(() => {
    setHistory(loadScanHistory());
  }, []);

  const executeScan = (urlToScan: string) => {
    const trimmed = urlToScan.trim();
    if (!trimmed) return;

    setIsScanning(true);
    // Instant smooth client-side parsing without external calls
    setTimeout(() => {
      const details = parseUrl(trimmed);
      setScannedResult(details);

      // Only add to history and query network services if URL format is valid
      if (details && details.isValid) {
        const assessment = assessUrlRisk(details);
        const updatedHistory = addScanToHistory(details, assessment);
        setHistory(updatedHistory);

        // 1. Asynchronously check threat intelligence in background (non-blocking)
        setThreatState({ status: 'checking' });
        fetch('/api/threat-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: details.normalizedUrl }),
        })
          .then(async (res) => {
            if (!res.ok) {
              setThreatState({
                status: 'unavailable',
                message: 'Threat intelligence service is temporarily unavailable. Local heuristic analysis remains active.',
              });
              return;
            }

            const data = await res.json();
            if (!data.configured) {
              setThreatState({
                status: 'unconfigured',
                message: 'Threat intelligence is not configured on this server. Running offline structural heuristic mode only.',
              });
            } else if (data.isThreat) {
              setThreatState({
                status: 'threat_detected',
                threatTypes: data.threatTypes || [],
                cacheDuration: data.cacheDuration,
                evaluatedAt: data.evaluatedAt,
              });
            } else {
              setThreatState({
                status: 'clean',
                message: 'No threat records found in Google Safe Browsing. This does not guarantee the URL is safe.',
                evaluatedAt: data.evaluatedAt,
              });
            }
          })
          .catch(() => {
            setThreatState({
              status: 'unavailable',
              message: 'Threat intelligence service is temporarily unavailable. Local heuristic analysis remains active.',
            });
          });

        // 2. Asynchronously check DNS reconnaissance & RDAP in background (non-blocking)
        setReconState({ status: 'checking', data: null });
        fetch('/api/recon', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: details.normalizedUrl }),
        })
          .then(async (res) => {
            if (!res.ok) {
              setReconState({
                status: 'error',
                data: null,
                errorMessage: 'DNS and domain registration reconnaissance is temporarily unavailable.',
              });
              return;
            }

            const reconData = await res.json();
            setReconState({
              status: 'completed',
              data: reconData,
            });
          })
          .catch(() => {
            setReconState({
              status: 'error',
              data: null,
              errorMessage: 'Unable to connect to reconnaissance service.',
            });
          });

        // 3. Asynchronously inspect redirect chain in background (non-blocking)
        setRedirectState({ status: 'checking', data: null });
        fetch('/api/redirect-chain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: details.normalizedUrl }),
        })
          .then(async (res) => {
            if (!res.ok) {
              setRedirectState({
                status: 'unavailable',
                data: null,
                errorMessage: 'Redirect inspection service is temporarily unavailable.',
              });
              return;
            }

            const chainData = await res.json();
            setRedirectState({
              status: 'completed',
              data: chainData,
            });
          })
          .catch(() => {
            setRedirectState({
              status: 'unavailable',
              data: null,
              errorMessage: 'Unable to connect to redirect inspection service.',
            });
          });
      } else {
        setThreatState({ status: 'idle' });
        setReconState({ status: 'idle', data: null });
        setRedirectState({ status: 'idle', data: null });
      }

      setIsScanning(false);
    }, 150);
  };

  const handleScan = () => {
    executeScan(inputUrl);
  };

  const handleClear = () => {
    setInputUrl('');
    setScannedResult(null);
    setThreatState({ status: 'idle' });
    setReconState({ status: 'idle', data: null });
    setRedirectState({ status: 'idle', data: null });
    setIsScanning(false);
  };

  const handleSelectRecentUrl = (url: string) => {
    setInputUrl(url);
    executeScan(url);
    // Smooth scroll up to results
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleClearHistory = () => {
    clearScanHistory();
    setHistory([]);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0b1120] text-slate-100 selection:bg-blue-600/30">
      {/* 1. Header with Shield Icon & required text */}
      <Header />

      {/* Main Content Area */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-10 space-y-8">
        {/* Intro Banner */}
        <div className="text-center sm:text-left max-w-2xl">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Suspicious Link Inspection
          </h2>
          <p className="text-sm sm:text-base text-slate-400 mt-2 leading-relaxed">
            Safely examine suspicious links received on messaging platforms like WhatsApp, Telegram, SMS, or Email without triggering malicious payloads or sending data to third parties.
          </p>
        </div>

        {/* 2. URL Input Section (large input, Scan Link, Clear button, disabled when empty) */}
        <UrlInputSection
          inputUrl={inputUrl}
          setInputUrl={setInputUrl}
          onScan={handleScan}
          onClear={handleClear}
          isScanning={isScanning}
        />

        {/* 3. Results Section ("Scan Results", initially "Paste a URL above to begin your security check.") */}
        <ScanResultsSection
          scannedResult={scannedResult}
          threatState={threatState}
          reconState={reconState}
          redirectState={redirectState}
        />

        {/* FEATURE: Recent Scans Section (capped at 10 items, stored in localStorage, with Clear History) */}
        <RecentScansSection
          history={history}
          onClearHistory={handleClearHistory}
          onSelectUrl={handleSelectRecentUrl}
        />

        {/* 4. Safety Notice & 5. Privacy Notice */}
        <SafetyNotice />

        {/* Platform Guidance for WhatsApp, SMS, Telegram, Email */}
        <PlatformTips />
      </main>

      {/* Minimalistic, clean cybersecurity footer */}
      <footer className="border-t border-slate-900/80 bg-slate-950/60 py-6 text-center text-xs text-slate-500">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p>Fraud Link Detector · Client-Side Security Assessment</p>
          <p>URLs are never stored on external servers or transmitted.</p>
        </div>
      </footer>
    </div>
  );
}
