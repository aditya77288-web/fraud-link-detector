import { ParsedUrlDetails } from './urlParser';
import { RiskAssessment, RiskLevel } from './riskEngine';

export interface ScanHistoryItem {
  id: string;
  displayUrl: string;
  hostname: string;
  score: number;
  level: RiskLevel;
  scannedAt: string; // Formatted date and time
  timestamp: number; // Numeric epoch for sorting
  indicatorsCount: number;
}

const STORAGE_KEY = 'fraud_link_detector_history_v1';
const MAX_HISTORY_ITEMS = 10;

// Sensitive query parameter keys that must be redacted before saving to localStorage
const SENSITIVE_PARAM_KEYS = new Set([
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'auth',
  'authtoken',
  'authentication',
  'key',
  'apikey',
  'api_key',
  'secret',
  'password',
  'pass',
  'pwd',
  'session',
  'sessionid',
  'session_id',
  'sess',
  'jwt',
  'sig',
  'signature',
  'credential',
  'credentials',
  'code',
  'pin',
  'otp',
  'card',
  'cvv',
  'ssn',
  'wallet_key',
  'private_key',
]);

/**
 * Redacts query parameter values that could contain passwords, access tokens,
 * or other sensitive secrets, and strips embedded authority passwords.
 */
export function redactSensitiveUrl(urlStr: string): string {
  if (!urlStr || !urlStr.trim()) return '';

  try {
    const parsed = new URL(urlStr);

    // 1. Redact authority password if present (e.g., http://user:password@host -> http://user:[REDACTED]@host)
    if (parsed.password) {
      parsed.password = '[REDACTED]';
    }

    // 2. Redact sensitive query parameters
    let hasModifiedParams = false;
    const newParams = new URLSearchParams();

    parsed.searchParams.forEach((val, key) => {
      const lowerKey = key.toLowerCase();
      const isSensitiveKey =
        SENSITIVE_PARAM_KEYS.has(lowerKey) ||
        Array.from(SENSITIVE_PARAM_KEYS).some((sensitive) => lowerKey.includes(sensitive));

      // Also check if value looks like a long hex/jwt token (> 32 chars of alphanumeric/dots)
      const isLikelyTokenValue =
        val.length >= 32 && (/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(val) || /^[a-fA-F0-9]{32,}$/.test(val));

      if (isSensitiveKey || isLikelyTokenValue) {
        newParams.append(key, '[REDACTED]');
        hasModifiedParams = true;
      } else {
        newParams.append(key, val);
      }
    });

    if (hasModifiedParams) {
      parsed.search = newParams.toString();
    }

    return parsed.href;
  } catch {
    // If not a standard URL, fallback to regex-based query masking
    return urlStr.replace(/([?&](?:token|pass|auth|key|secret|code|sig|jwt)=)[^&#]*/gi, '$1[REDACTED]');
  }
}

/**
 * Loads recent scans safely from browser localStorage.
 */
export function loadScanHistory(): ScanHistoryItem[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }

  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const items = JSON.parse(raw);
    if (!Array.isArray(items)) return [];

    // Validate structure of loaded items
    return items
      .filter((item) => item && typeof item.displayUrl === 'string' && typeof item.score === 'number')
      .slice(0, MAX_HISTORY_ITEMS);
  } catch {
    return [];
  }
}

/**
 * Saves recent scans into browser localStorage, capped strictly at the 10 most recent.
 */
export function saveScanHistory(items: ScanHistoryItem[]): void {
  if (typeof window === 'undefined' || !window.localStorage) {
    return;
  }

  try {
    const capped = items.slice(0, MAX_HISTORY_ITEMS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(capped));
  } catch {
    // Gracefully handle storage quota or privacy mode exceptions
  }
}

/**
 * Adds a new scan result to history with secrets redacted and caps at 10 items.
 */
export function addScanToHistory(
  parsed: ParsedUrlDetails,
  assessment: RiskAssessment
): ScanHistoryItem[] {
  const current = loadScanHistory();
  const redactedUrl = redactSensitiveUrl(parsed.normalizedUrl);

  const now = new Date();
  const formattedDateTime = now.toLocaleDateString([], {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }) + ' · ' + now.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });

  const newItem: ScanHistoryItem = {
    id: `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    displayUrl: redactedUrl,
    hostname: parsed.hostname,
    score: assessment.score,
    level: assessment.level,
    scannedAt: formattedDateTime,
    timestamp: Date.now(),
    indicatorsCount: assessment.indicators.length,
  };

  // Prepend new item and filter out duplicate displayUrl to keep list relevant
  const updated = [newItem, ...current.filter((item) => item.displayUrl !== redactedUrl)].slice(
    0,
    MAX_HISTORY_ITEMS
  );

  saveScanHistory(updated);
  return updated;
}

/**
 * Clears scan history from browser localStorage.
 */
export function clearScanHistory(): void {
  if (typeof window === 'undefined' || !window.localStorage) {
    return;
  }
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore
  }
}
