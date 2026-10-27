import React, { useRef } from 'react';
import { Search, RotateCcw, Link2, Sparkles } from 'lucide-react';

interface UrlInputSectionProps {
  inputUrl: string;
  setInputUrl: (val: string) => void;
  onScan: () => void;
  onClear: () => void;
  isScanning?: boolean;
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
}: UrlInputSectionProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const isInputEmpty = !inputUrl.trim();

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isInputEmpty) {
      e.preventDefault();
      onScan();
    }
  };

  const handleClear = () => {
    onClear();
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  const handleSelectSample = (sampleUrl: string) => {
    setInputUrl(sampleUrl);
    if (inputRef.current) {
      inputRef.current.focus();
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
            placeholder="Paste a suspicious URL here..."
            className="w-full text-base sm:text-lg bg-slate-950/90 border border-slate-700/80 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 text-slate-100 placeholder:text-slate-500 rounded-xl px-4 py-3.5 sm:py-4 transition-all duration-150 outline-none font-mono selection:bg-blue-600/30"
            aria-label="Paste a suspicious URL here"
            autoComplete="off"
            spellCheck="false"
          />
        </div>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            {/* Scan Link Button */}
            <button
              type="button"
              onClick={onScan}
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
