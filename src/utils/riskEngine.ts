import { ParsedUrlDetails } from './urlParser';

export type RiskLevel = 'Low' | 'Medium' | 'High';

export interface RiskIndicator {
  id: string;
  ruleNumber: number;
  name: string;
  points: number;
  explanation: string;
  evidence?: string;
}

export interface RiskAssessment {
  isValid: boolean;
  score: number; // 0 - 100
  level: RiskLevel;
  indicators: RiskIndicator[];
  summaryMessage: string;
  disclaimer: string;
}

// 6. Defined list of recognized URL shorteners
export const KNOWN_URL_SHORTENERS: readonly string[] = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'tiny.cc',
  'rebrand.ly',
  'cutt.ly',
  'shorte.st',
  'v.gd',
  'rb.gy',
  'shorturl.at',
];

// 7. Commonly abused words in paths or subdomains
export const SENSITIVE_KEYWORDS: readonly string[] = [
  'login',
  'signin',
  'verify',
  'verification',
  'password',
  'wallet',
  'gift',
  'urgent',
  'security',
  'update',
  'banking',
  'account',
  'claim',
  'prize',
  'recover',
  'credential',
];

// 8. Query parameter keys/patterns associated with sensitive redirection or session lures
export const SENSITIVE_QUERY_KEYS: readonly string[] = [
  'token',
  'session',
  'auth',
  'pass',
  'password',
  'redirect',
  'redirect_url',
  'redirect_uri',
  'url',
  'dest',
  'destination',
  'target',
  'goto',
  'callback',
  'wallet',
  'urgent',
  'claim',
  'gift',
];

/**
 * Assesses client-side risk for a parsed URL against 10 deterministic heuristic rules.
 * Does not make external network requests, use API keys, or claim absolute safety.
 */
export function assessUrlRisk(parsed: ParsedUrlDetails | null): RiskAssessment {
  const disclaimer =
    'These results are heuristic indicators based on link structure, not definitive proof of malicious activity or absolute safety.';

  // If input was null or invalid URL, return invalid assessment without misleading score
  if (!parsed || !parsed.isValid) {
    const errorDetails = parsed?.errorMessage || 'Unable to parse web address';
    return {
      isValid: false,
      score: 0,
      level: 'Low',
      indicators: [],
      summaryMessage: `Invalid URL format: ${errorDetails}. Please enter a valid web address.`,
      disclaimer,
    };
  }

  const indicators: RiskIndicator[] = [];

  // Rule 1: HTTP instead of HTTPS (+15 pts)
  if (!parsed.isHttps && parsed.protocol === 'http:') {
    indicators.push({
      id: 'rule-http',
      ruleNumber: 1,
      name: 'Unencrypted HTTP Protocol',
      points: 15,
      explanation: 'Uses unencrypted HTTP instead of secure HTTPS, exposing traffic to potential tampering or interception.',
      evidence: `${parsed.protocol}//`,
    });
  }

  // Rule 2: IP addresses used instead of ordinary domain names (+25 pts)
  if (parsed.isIpAddress) {
    indicators.push({
      id: 'rule-ip-address',
      ruleNumber: 2,
      name: 'Direct IP Address Host',
      points: 25,
      explanation: `Uses a direct numeric IP address (${parsed.hostname}) instead of a registered domain name, frequently employed to bypass domain reputation systems.`,
      evidence: parsed.hostname,
    });
  }

  // Rule 3: URLs containing user credentials before the @ symbol in authority (+25 pts)
  // Strictly checks credentials in authority; does not flag @ in path or query
  if (parsed.hasAuthorityCredentials) {
    const credInfo = parsed.username + (parsed.password ? `:${parsed.password}` : '');
    indicators.push({
      id: 'rule-credentials-at',
      ruleNumber: 3,
      name: 'User Credentials in URL Authority',
      points: 25,
      explanation: `Contains user credentials embedded before the '@' in the URL authority. The actual destination host is "${parsed.hostname}", not the preceding text.`,
      evidence: `${credInfo}@`,
    });
  }

  // Rule 4: Suspiciously long URLs (> 100 characters) (+15 pts)
  if (parsed.normalizedUrl.length > 100) {
    indicators.push({
      id: 'rule-long-url',
      ruleNumber: 4,
      name: 'Suspiciously Long URL Length',
      points: 15,
      explanation: `URL length is ${parsed.normalizedUrl.length} characters (exceeds 100 characters), which can obscure destination details in messaging apps.`,
      evidence: `${parsed.normalizedUrl.length} characters`,
    });
  }

  // Rule 5: Excessive subdomains (>= 3 subdomain levels on domain names, not IP hosts) (+15 pts)
  if (!parsed.isIpAddress && parsed.subdomainCount >= 3) {
    indicators.push({
      id: 'rule-excessive-subdomains',
      ruleNumber: 5,
      name: 'Excessive Subdomain Levels',
      points: 15,
      explanation: `Contains ${parsed.subdomainCount} subdomain levels, which is often used in phishing to spoof recognizable brand names within deep subdomains.`,
      evidence: parsed.hostname,
    });
  }

  // Rule 6: URL shortener domains from a clearly defined list (+20 pts)
  const isShortener = KNOWN_URL_SHORTENERS.some(
    (shortener) => parsed.hostname === shortener || parsed.hostname.endsWith(`.${shortener}`)
  );
  if (isShortener) {
    indicators.push({
      id: 'rule-url-shortener',
      ruleNumber: 6,
      name: 'Known URL Shortener Service',
      points: 20,
      explanation: 'Uses a link shortener service that obscures the real destination address until redirected.',
      evidence: parsed.hostname,
    });
  }

  // Rule 7: Commonly abused words in URL paths or subdomains (+20 pts)
  const lowerHostname = parsed.hostname.toLowerCase();
  const lowerPathname = parsed.pathname.toLowerCase();
  const matchedKeywords = SENSITIVE_KEYWORDS.filter((word) => {
    // Check in subdomains (avoiding top-level domain match) or in path segments
    const inSubdomain = !parsed.isIpAddress && lowerHostname.includes(word);
    const inPath = lowerPathname.includes(word);
    return inSubdomain || inPath;
  });

  if (matchedKeywords.length > 0) {
    const isPathOnly = !lowerHostname.includes(matchedKeywords[0]) && lowerPathname.includes(matchedKeywords[0]);
    indicators.push({
      id: 'rule-abused-words',
      ruleNumber: 7,
      name: isPathOnly ? 'Contextual Sensitive Keywords in Path' : 'Sensitive Keywords in Path or Host',
      points: 20,
      explanation: isPathOnly
        ? `Contains contextual keywords ([${matchedKeywords.slice(0, 4).join(', ')}]) in the URL path commonly associated with authentication or account actions. This is a contextual indicator requiring domain verification, not proof of phishing.`
        : `Contains keywords commonly associated with authentication or financial lures: [${matchedKeywords.slice(0, 4).join(', ')}]. Contextual indicator to verify destination identity.`,
      evidence: matchedKeywords.slice(0, 4).join(', '),
    });
  }

  // Rule 8: Risky-looking combinations of query parameters and sensitive words (+15 pts)
  const suspiciousParams = parsed.paramsList.filter((param) => {
    const key = param.key.toLowerCase();
    const val = param.value.toLowerCase();
    const keyMatches = SENSITIVE_QUERY_KEYS.some((k) => key.includes(k));
    const valMatches = SENSITIVE_KEYWORDS.some((w) => val.includes(w)) || val.startsWith('http');
    return keyMatches || valMatches;
  });

  if (suspiciousParams.length > 0) {
    const paramDescriptions = suspiciousParams.map((p) => p.key).slice(0, 3).join(', ');
    indicators.push({
      id: 'rule-risky-query-params',
      ruleNumber: 8,
      name: 'Sensitive Query Parameter Patterns',
      points: 15,
      explanation: `Contains query parameters handling authentication tokens, redirection, or sensitive keywords: [${paramDescriptions}]`,
      evidence: `${suspiciousParams.length} sensitive parameter(s) detected`,
    });
  }

  // Rule 9: Punycode domains beginning with xn-- (+25 pts)
  if (parsed.hasPunycode) {
    indicators.push({
      id: 'rule-punycode',
      ruleNumber: 9,
      name: 'Punycode Internationalized Domain (IDN)',
      points: 25,
      explanation:
        'Contains a hostname label beginning with "xn--" (Punycode / IDN). While Punycode legitimately enables internationalized domain names in non-Latin scripts and is not proof of malicious activity by itself, it can also be used in homograph phishing attacks to spoof familiar brand names with lookalike characters.',
      evidence: parsed.hostname,
    });
  }

  // Rule 10: Unusual ports (+15 pts)
  // Treats HTTP port 80 and HTTPS port 443 as standard defaults
  if (parsed.isNonStandardPort) {
    const standardPort = parsed.isHttps ? 'HTTPS (443)' : 'HTTP (80)';
    const portNote =
      parsed.explicitPort === '8080'
        ? 'Port 8080 is an alternative/non-default HTTP web port commonly used for local development, caching proxies, or testing. Standard default ports are HTTP (80) and HTTPS (443). Its presence is a contextual indicator to verify the destination, not proof of malicious activity.'
        : `Diverges from standard default web ports (HTTP (80) and HTTPS (443)). Non-standard ports warrant destination verification but do not prove malicious activity on their own.`;
    indicators.push({
      id: 'rule-unusual-port',
      ruleNumber: 10,
      name: 'Non-Standard Network Port',
      points: 15,
      explanation: `Specifies non-standard port :${parsed.explicitPort} instead of default ${standardPort}. ${portNote}`,
      evidence: `Port :${parsed.explicitPort}`,
    });
  }

  // Calculate total score capped strictly between 0 and 100
  const rawScore = indicators.reduce((sum, item) => sum + item.points, 0);
  const score = Math.min(100, Math.max(0, rawScore));

  // Determine Level strictly based on displayed thresholds:
  // Low Risk: 0 - 29
  // Medium Risk: 30 - 59
  // High Risk: 60 - 100
  let level: RiskLevel = 'Low';
  if (score >= 60) {
    level = 'High';
  } else if (score >= 30) {
    level = 'Medium';
  }

  // Summary message:
  // "If no indicators are detected, display "No obvious suspicious patterns detected" rather than "Safe"."
  let summaryMessage = '';
  if (indicators.length === 0) {
    summaryMessage = 'No obvious suspicious patterns detected';
  } else if (level === 'High') {
    summaryMessage = `${indicators.length} high-concern indicator(s) detected. Extreme caution advised before interacting.`;
  } else if (level === 'Medium') {
    summaryMessage = `${indicators.length} suspicious indicator(s) detected. Verify the sender through a trusted channel.`;
  } else {
    summaryMessage = `${indicators.length} low-severity indicator(s) noted. Proceed with normal caution.`;
  }

  return {
    isValid: true,
    score,
    level,
    indicators,
    summaryMessage,
    disclaimer,
  };
}
