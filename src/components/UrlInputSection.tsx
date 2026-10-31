import React, { useRef, useState, useEffect } from 'react';
import {
  Search,
  RotateCcw,
  Link2,
  Sparkles,
  Clipboard,
  ClipboardCheck,
  AlertCircle,
  AlertTriangle,
  ShieldAlert,
  Share2,
  X,
} from 'lucide-react';
import { extractUrlsFromText, readClipboardSafely } from '../utils/clipboardUrl';

export interface DetectedCandidate {
  urls: string[];
  primaryUrl: string;
  source: 'button' | 'paste' | 'share';
}

interface UrlInputSectionProps {
  inputUrl: string;
  setInputUrl: (val: string) => void;
  onScan: (urlToScan?: string) => void;
  onClear: () => void;
  isScanning?: boolean;
  incomingCandidate?: DetectedCandidate | null;
  onDismissIncomingCandidate?: () => void;
}

interface NoticeState {
  type: 'info' | 'denied';
  text: string;
}

const SAMPLE_URLS = [
  {
    label: 'Clean HTTPS (about-us)',
    url: 'https://www.example.com/about-us',
  },
  {
    label: 'IP & Port 8080',
    url: 'http://192.0.2.1:8080/login',
  },
  {
    label: 'Authority @ Credentials',
    url: 'https://example.com@192.0.2.1/login',
  },
  {
    label: 'Punycode (xn--)',
    url: 'https://xn--e1afmkfd.example/login',
  },
  {
    label: 'URL shortener',
    url: 'https://bit.ly/3xSampleNotice',
  },
];

export function UrlInputSection({
  inputUrl,
  setInputUrl,
  onScan,
  onClear,
  isScanning = false,
  incomingCandidate = null,
  onDismissIncomingCandidate,
}: UrlInputSectionProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const isInputEmpty = !inputUrl.trim();

  // Clipboard & Share detection state
  const [isReadingClipboard, setIsReadingClipboard] = useState(false);
  const [detectedCandidate, setDetectedCandidate] = useState<DetectedCandidate | null>(null);
  const [selectedCandidateUrl, setSelectedCandidateUrl] = useState<string>('');
  const [noticeMessage, setNoticeMessage] = useState<NoticeState | null>(null);
  const [showMobileShareTip, setShowMobileShareTip] = useState(true);

  // Sync incomingCandidate from Web Share Target or external triggers
  useEffect(() => {
    if (incomingCandidate) {
      setDetectedCandidate(incomingCandidate);
      setSelectedCandidateUrl(incomingCandidate.primaryUrl);
    }
  }, [incomingCandidate]);

  // Sync selectedCandidateUrl whenever detectedCandidate changes
  useEffect(() => {
    if (detectedCandidate) {
      setSelectedCandidateUrl(detectedCandidate.primaryUrl);
    }
  }, [detectedCandidate]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isInputEmpty) {
      e.preventDefault();
      onScan();
    }
  };

  const handleClear = () => {
    onClear();
    setDetectedCandidate(null);
    setNoticeMessage(null);
    if (onDismissIncomingCandidate) {
      onDismissIncomingCandidate();
    }
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  const handleSelectSample = (sampleUrl: string) => {
    setInputUrl(sampleUrl);
    setDetectedCandidate(null);
    setNoticeMessage(null);
    if (onDismissIncomingCandidate) {
      onDismissIncomingCandidate();
    }
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  // Browser paste event handler on URL input
  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const pastedText = e.clipboardData?.getData('text') || '';
    if (!pastedText.trim()) return;

    // Check if the pasted text contains an embedded URL or multiple URLs within message text
    const extracted = extractUrlsFromText(pastedText);
    if (extracted.urls.length > 0 && extracted.primaryUrl) {
      e.preventDefault();
      // Pre-fill the input field with the primary URL
      setInputUrl(extracted.primaryUrl);
      // Trigger the immediate pre-scan safety confirmation
      setDetectedCandidate({
        urls: extracted.urls,
        primaryUrl: extracted.primaryUrl,
        source: 'paste',
      });
      setNoticeMessage(null);
    }
  };

  // Explicit user-triggered clipboard check button
  const handleCheckClipboard = async () => {
    setIsReadingClipboard(true);
    setNoticeMessage(null);
    try {
      const result = await readClipboardSafely();
      if (result.status === 'success' && result.primaryUrl) {
        setDetectedCandidate({
          urls: result.urls,
          primaryUrl: result.primaryUrl,
          source: 'button',
        });
      } else {
        setNoticeMessage({
          type: result.status === 'denied' ? 'denied' : 'info',
          text: result.message,
        });
      }
    } finally {
      setIsReadingClipboard(false);
    }
  };

  const handleConfirmScan = () => {
    if (!selectedCandidateUrl) return;
    setInputUrl(selectedCandidateUrl);
    onScan(selectedCandidateUrl);
    setDetectedCandidate(null);
    setNoticeMessage(null);
    if (onDismissIncomingCandidate) {
      onDismissIncomingCandidate();
    }
  };

  const handlePasteToInputOnly = () => {
    if (!selectedCandidateUrl) return;
    setInputUrl(selectedCandidateUrl);
    setDetectedCandidate(null);
    setNoticeMessage(null);
    if (onDismissIncomingCandidate) {
      onDismissIncomingCandidate();
    }
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  const handleDismissCandidate = () => {
    setDetectedCandidate(null);
    if (onDismissIncomingCandidate) {
      onDismissIncomingCandidate();
    }
  };

  return (
    <section aria-labelledby="url-inspector-heading" className="w-full">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 sm:p-7 shadow-xl shadow-slate-950/40 backdrop-blur-sm">
        <div className="flex items-center justify-between mb-3">
          <label
            htmlFor="url-input"
            id="url-inspector-heading"
            className="text-sm font-semibold text-slate-200 flex items-center gap-2"
          >
            <Link2 className="w-4 h-4 text-blue-400" aria-hidden="true" />
            Inspect Suspicious URL
          </label>
          <span className="text-xs text-slate-400 hidden sm:inline">
            WhatsApp · SMS · Telegram · Email
          </span>
        </div>

        {/* Large Input Field */}
        <div className="relative mb-4">
          <input
            id="url-input"
            ref={inputRef}
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            onPaste={handlePaste}
            placeholder="Paste a suspicious URL here..."
            className="w-full text-base sm:text-lg bg-slate-950/90 border border-slate-700/80 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-slate-100 placeholder:text-slate-500 rounded-xl px-4 py-3.5 sm:py-4 transition-all duration-150 outline-none font-mono selection:bg-blue-600/30"
            aria-label="Paste a suspicious URL here"
            autoComplete="off"
            spellCheck="false"
          />
        </div>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Scan Link Button */}
            <button
              type="button"
              onClick={() => onScan()}
              disabled={isInputEmpty || isScanning}
              aria-label="Scan Link"
              className={`flex items-center justify-center gap-2 px-6 py-2.5 sm:py-3 rounded-xl font-medium text-sm transition-all duration-150 shadow-md ${
                isInputEmpty || isScanning
                  ? 'bg-slate-800/80 text-slate-500 cursor-not-allowed border border-slate-800'
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-900/30 border border-blue-500/30 active:scale-[0.99] cursor-pointer'
              }`}
            >
              <Search className="w-4 h-4" aria-hidden="true" />
              <span>{isScanning ? 'Processing...' : 'Scan Link'}</span>
            </button>

            {/* Check Clipboard Button */}
            <button
              type="button"
              onClick={handleCheckClipboard}
              disabled={isScanning || isReadingClipboard}
              aria-label="Check Clipboard for URL"
              className="flex items-center justify-center gap-2 px-4 py-2.5 sm:py-3 rounded-xl font-medium text-sm bg-slate-800/80 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 transition-all duration-150 cursor-pointer active:scale-[0.99] group shadow-sm"
            >
              <Clipboard className="w-4 h-4 text-blue-400 group-hover:text-blue-300 transition-colors" aria-hidden="true" />
              <span>{isReadingClipboard ? 'Checking...' : 'Check Clipboard'}</span>
            </button>

            {/* Clear Button */}
            <button
              type="button"
              onClick={handleClear}
              aria-label="Clear URL input"
              className="flex items-center justify-center gap-2 px-4 py-2.5 sm:py-3 rounded-xl font-medium text-sm bg-slate-800/70 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/70 transition-all duration-150 cursor-pointer active:scale-[0.99]"
            >
              <RotateCcw className="w-4 h-4 text-slate-400" aria-hidden="true" />
              <span>Clear</span>
            </button>
          </div>

          <div className="text-xs text-slate-400 flex items-center gap-1.5 self-center sm:self-auto">
            <span>Press <kbd className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[11px]">Enter</kbd> to scan</span>
          </div>
        </div>

        {/* User Confirmation Card for Detected Clipboard / Shared / Pasted URL */}
        {detectedCandidate && (
          <div className="mt-4 p-4 rounded-xl bg-blue-950/40 border border-blue-500/40 shadow-lg animate-in fade-in duration-200">
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
                {detectedCandidate.source === 'share' ? (
                  <Share2 className="w-4 h-4 text-blue-400" aria-hidden="true" />
                ) : detectedCandidate.source === 'button' ? (
                  <ClipboardCheck className="w-4 h-4 text-blue-400" aria-hidden="true" />
                ) : (
                  <ShieldAlert className="w-4 h-4 text-amber-400" aria-hidden="true" />
                )}
                <span>
                  {detectedCandidate.source === 'share'
                    ? 'Confirm Shared Mobile Link'
                    : detectedCandidate.source === 'button'
                    ? 'Confirm Clipboard Link Scan'
                    : 'Pre-Scan Safety Confirmation'}
                </span>
              </div>
              <button
                type="button"
                onClick={handleDismissCandidate}
                className="text-slate-400 hover:text-white p-1 rounded transition-colors cursor-pointer"
                aria-label="Dismiss confirmation"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Immediate pre-scan safety message */}
            <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-200 text-xs sm:text-sm font-medium mb-3 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
              <span>Don't open an unfamiliar link yet. Scan it first to check for potential security risks.</span>
            </div>

            <p className="text-xs text-slate-300 mb-3">
              {detectedCandidate.source === 'share'
                ? 'A web link was received via your mobile share sheet. Confirm below before starting a scan (links are never visited automatically):'
                : detectedCandidate.source === 'button'
                ? 'A web link was detected in your clipboard. Confirm below before starting a scan (links are never visited automatically):'
                : 'A web link was detected in your pasted input. Confirm below before starting a scan (links are never visited automatically):'}
            </p>

            {/* Multi-URL selector */}
            {detectedCandidate.urls.length > 1 && (
              <div className="mb-3">
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Found {detectedCandidate.urls.length} links. Select link to scan:
                </label>
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {detectedCandidate.urls.map((u, i) => (
                    <label
                      key={i}
                      className={`flex items-center gap-2 p-2 rounded-lg text-xs font-mono border cursor-pointer transition-colors ${
                        selectedCandidateUrl === u
                          ? 'bg-blue-600/20 border-blue-500 text-blue-200'
                          : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <input
                        type="radio"
                        name="selectedCandidateUrl"
                        checked={selectedCandidateUrl === u}
                        onChange={() => setSelectedCandidateUrl(u)}
                        className="text-blue-500 focus:ring-0"
                      />
                      <span className="truncate">{u}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* Single URL Display Box */}
            {detectedCandidate.urls.length === 1 && (
              <div className="p-2.5 bg-slate-950/90 rounded-lg border border-slate-800 font-mono text-xs sm:text-sm text-blue-300 break-all mb-3.5 select-all">
                {selectedCandidateUrl}
              </div>
            )}

            {/* Confirmation Action Buttons */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <button
                type="button"
                onClick={handleConfirmScan}
                aria-label="Scan This Link"
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg font-medium text-xs sm:text-sm bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-900/30 transition-all cursor-pointer"
              >
                <Search className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Scan This Link</span>
              </button>
              <button
                type="button"
                onClick={handlePasteToInputOnly}
                aria-label="Keep in Input"
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg font-medium text-xs sm:text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-all cursor-pointer"
              >
                <Link2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Keep in Input</span>
              </button>
              <button
                type="button"
                onClick={handleDismissCandidate}
                aria-label="Cancel"
                className="px-3.5 py-2 rounded-lg text-xs sm:text-sm text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Friendly Notification Banner (e.g., permission denied, empty clipboard, or no link found) */}
        {noticeMessage && (
          <div className="mt-3.5 p-3 rounded-xl bg-slate-950/90 border border-slate-800 flex items-start justify-between gap-3 animate-in fade-in duration-150">
            <div className="flex items-start gap-2 text-xs text-slate-300">
              <AlertCircle
                className={`w-4 h-4 shrink-0 mt-0.5 ${
                  noticeMessage.type === 'denied' ? 'text-amber-400' : 'text-blue-400'
                }`}
                aria-hidden="true"
              />
              <span>{noticeMessage.text}</span>
            </div>
            <button
              type="button"
              onClick={() => setNoticeMessage(null)}
              className="text-slate-500 hover:text-slate-300 p-0.5 rounded transition-colors cursor-pointer"
              aria-label="Dismiss notice"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Mobile Share Target Tip */}
        {showMobileShareTip && (
          <div className="mt-4 p-3 rounded-xl bg-slate-950/80 border border-slate-800/90 flex items-start justify-between gap-3 text-xs text-slate-400 animate-in fade-in duration-200">
            <div className="flex items-start gap-2">
              <Share2 className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <span className="font-semibold text-slate-300">Mobile Share Sheet Support: </span>
                <span>On Android browsers (Chrome, Edge), tap <span className="text-slate-200 font-medium">Install App</span> or <span className="text-slate-200 font-medium">Add to Home Screen</span> to share suspicious links directly from WhatsApp, SMS, or Telegram.</span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowMobileShareTip(false)}
              className="text-slate-500 hover:text-slate-300 p-0.5 rounded transition-colors cursor-pointer"
              aria-label="Dismiss mobile share tip"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Quick Test Samples */}
        <div className="mt-5 pt-4 border-t border-slate-800/80">
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
            <Sparkles className="w-3.5 h-3.5 text-blue-400" aria-hidden="true" />
            <span>Try sample URLs for testing:</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_URLS.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectSample(sample.url)}
                className="text-xs font-mono px-2.5 py-1.5 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-blue-500/50 hover:bg-slate-800/60 text-slate-300 transition-colors cursor-pointer text-left"
                title={`Click to load: ${sample.url}`}
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
