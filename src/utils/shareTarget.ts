import { extractUrlsFromText } from './clipboardUrl.js';

export interface ShareTargetParsedResult {
  hasShare: boolean;
  urls: string[];
  primaryUrl: string | null;
  rawContent: string | null;
  message?: string;
}

/**
 * Parses query parameters received via Web Share Target (GET action).
 * Extracts valid URLs from 'url', 'text', and 'title' query parameters.
 * Treats all received content strictly as untrusted user input.
 */
export function parseShareTargetParams(
  searchParams: URLSearchParams
): ShareTargetParsedResult {
  const urlParam = searchParams.get('url')?.trim() || '';
  const textParam = searchParams.get('text')?.trim() || '';
  const titleParam = searchParams.get('title')?.trim() || '';

  // Check if any share parameter was provided
  if (!urlParam && !textParam && !titleParam) {
    return {
      hasShare: false,
      urls: [],
      primaryUrl: null,
      rawContent: null,
    };
  }

  // Combine parameters to inspect all potential link occurrences
  const combinedPieces = [urlParam, textParam, titleParam].filter(Boolean);
  const combinedText = combinedPieces.join(' ');

  const extraction = extractUrlsFromText(combinedText);

  if (extraction.urls.length === 0) {
    return {
      hasShare: true,
      urls: [],
      primaryUrl: null,
      rawContent: combinedText,
      message: 'Shared content did not contain a valid web link.',
    };
  }

  return {
    hasShare: true,
    urls: extraction.urls,
    primaryUrl: extraction.primaryUrl,
    rawContent: combinedText,
  };
}

/**
 * Removes share-target query parameters (url, text, title) from the browser address bar.
 * Uses window.history.replaceState to prevent re-processing the same payload on refresh,
 * without creating extra history entries or exposing sensitive query parameters.
 */
export function cleanShareQueryParams(
  loc: { search: string; pathname: string } = typeof window !== 'undefined'
    ? window.location
    : { search: '', pathname: '/' },
  hist: { replaceState: (data: unknown, unused: string, url?: string | URL | null) => void } = typeof window !== 'undefined'
    ? window.history
    : { replaceState: () => {} }
): void {
  if (!loc || !loc.search) return;

  const currentParams = new URLSearchParams(loc.search);
  const shareKeys = ['url', 'text', 'title'];
  let modified = false;

  for (const key of shareKeys) {
    if (currentParams.has(key)) {
      currentParams.delete(key);
      modified = true;
    }
  }

  if (modified && hist && typeof hist.replaceState === 'function') {
    const remainingQuery = currentParams.toString();
    const cleanUrl = remainingQuery
      ? `${loc.pathname || '/'}?${remainingQuery}`
      : loc.pathname || '/';
    hist.replaceState({}, '', cleanUrl);
  }
}
