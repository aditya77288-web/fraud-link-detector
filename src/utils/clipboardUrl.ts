import { isValidUrl, normalizeUrlString } from './urlParser.js';

export interface ClipboardExtractionResult {
  status: 'empty' | 'no_url' | 'single_url' | 'multiple_urls';
  urls: string[];
  primaryUrl: string | null;
  message?: string;
}

export type ClipboardReadStatus =
  | 'success'
  | 'empty'
  | 'no_url'
  | 'denied'
  | 'unsupported';

export interface ClipboardReadResult {
  status: ClipboardReadStatus;
  rawText?: string;
  urls: string[];
  primaryUrl: string | null;
  message: string;
}

/**
 * Strips surrounding noise and common trailing punctuation from extracted URL candidates.
 * (e.g. "https://example.com/login." -> "https://example.com/login")
 */
export function cleanExtractedUrl(raw: string): string {
  if (!raw) return '';
  let cleaned = raw.trim();

  // Strip enclosing quotes, brackets, or angle brackets
  cleaned = cleaned.replace(/^[<(\["']+|[>)\]"']+$/g, '');

  // Strip trailing punctuation commonly appended in sentences
  cleaned = cleaned.replace(/[.,;:!?]+$/, '');

  return cleaned.trim();
}

/**
 * Extracts all valid web URLs (http/https) from arbitrary input text.
 * Handles empty content, surrounding natural language, punctuation, and multiple links safely.
 */
export function extractUrlsFromText(text: string): ClipboardExtractionResult {
  if (!text || !text.trim()) {
    return {
      status: 'empty',
      urls: [],
      primaryUrl: null,
      message: 'Clipboard is empty. Copy a link first, then try again.',
    };
  }

  const trimmed = text.trim();

  // Pattern matches http/https schemes and www. prefixes
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+/gi;
  const matches = trimmed.match(urlRegex) || [];

  const validUrls: string[] = [];
  const seen = new Set<string>();

  for (const rawMatch of matches) {
    const cleaned = cleanExtractedUrl(rawMatch);
    if (isValidUrl(cleaned)) {
      const normalized = normalizeUrlString(cleaned);
      if (!seen.has(normalized)) {
        seen.add(normalized);
        validUrls.push(cleaned);
      }
    }
  }

  // If regex found no explicit scheme/www, but the entire text without whitespace is a valid web URL
  if (validUrls.length === 0) {
    if (!/\s/.test(trimmed) && isValidUrl(trimmed)) {
      const cleaned = cleanExtractedUrl(trimmed);
      if (isValidUrl(cleaned)) {
        validUrls.push(cleaned);
      }
    }
  }

  if (validUrls.length === 0) {
    return {
      status: 'no_url',
      urls: [],
      primaryUrl: null,
      message: 'No valid web link was found in the copied text. You can paste the link directly into the input box.',
    };
  }

  if (validUrls.length === 1) {
    return {
      status: 'single_url',
      urls: validUrls,
      primaryUrl: validUrls[0],
    };
  }

  return {
    status: 'multiple_urls',
    urls: validUrls,
    primaryUrl: validUrls[0],
    message: `Found ${validUrls.length} web links in the clipboard text.`,
  };
}

/**
 * Safely reads the browser clipboard on user demand.
 * Never monitors the clipboard in the background or requests unnecessary permissions.
 * Gracefully handles permission denial, unsupported environments, and non-URL content.
 */
export async function readClipboardSafely(
  clipboardApi?: { readText?: () => Promise<string> }
): Promise<ClipboardReadResult> {
  const api =
    clipboardApi ||
    (typeof navigator !== 'undefined' && navigator.clipboard
      ? navigator.clipboard
      : undefined);

  if (!api || typeof api.readText !== 'function') {
    return {
      status: 'unsupported',
      urls: [],
      primaryUrl: null,
      message:
        'Clipboard access is not supported in this browser environment. You can paste the URL manually into the input box.',
    };
  }

  try {
    const text = await api.readText();
    if (!text || !text.trim()) {
      return {
        status: 'empty',
        urls: [],
        primaryUrl: null,
        message: 'Clipboard is empty. Copy a link first, then try again or paste it manually.',
      };
    }

    const extraction = extractUrlsFromText(text);
    if (extraction.status === 'no_url') {
      return {
        status: 'no_url',
        urls: [],
        primaryUrl: null,
        message:
          'No valid web link was found in the copied text. You can paste the link manually into the input box.',
      };
    }

    return {
      status: 'success',
      rawText: text,
      urls: extraction.urls,
      primaryUrl: extraction.primaryUrl,
      message:
        extraction.status === 'multiple_urls'
          ? `Detected ${extraction.urls.length} URLs in clipboard.`
          : 'Detected URL from clipboard.',
    };
  } catch (_err) {
    return {
      status: 'denied',
      urls: [],
      primaryUrl: null,
      message:
        'Clipboard access was blocked or denied by your browser. You can paste the URL manually into the input box.',
    };
  }
}
