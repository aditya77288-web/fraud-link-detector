import { ParsedUrlDetails } from './urlParser.js';
import {
  assessUrlRisk,
  RiskAssessment,
  KNOWN_URL_SHORTENERS,
  SENSITIVE_KEYWORDS,
  SENSITIVE_QUERY_KEYS,
  RiskLevel,
} from './riskEngine.js';
import { ThreatIntelligenceState } from '../types/threat.js';
import { ReconClientState } from '../types/recon.js';
import { RedirectClientState } from '../types/redirect.js';
import {
  ScamAwarenessReport,
  ScamAwarenessWarning,
  WarningSeverity,
  FindingConfidence,
} from '../types/warning.js';

export const SCAM_AWARENESS_DISCLAIMER =
  'These evidence-based warnings are derived from observed link structure, domain reconnaissance, and available threat intelligence. They describe potential risk scenarios, not definitive legal proof of fraud. The absence of detected indicators does not guarantee safety.';

export interface WarningEngineInput {
  parsedUrl: ParsedUrlDetails | null;
  assessment?: RiskAssessment | null;
  threatState?: ThreatIntelligenceState | null;
  reconState?: ReconClientState | null;
  redirectState?: RedirectClientState | null;
}

const SEVERITY_ORDER: Record<WarningSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Generates an evidence-based Scam Awareness Report by combining:
 * 1. Client-side URL structural analysis & deterministic heuristic indicators
 * 2. External threat intelligence (Google Safe Browsing)
 * 3. Domain & DNS reconnaissance (RDAP domain age, MX, IP resolution)
 * 4. HTTP redirect chain inspection (loops, downgrades, SSRF blocks)
 *
 * Never invents threat matches or claims a link is definitively safe.
 */
export function generateScamAwarenessReport({
  parsedUrl,
  assessment: providedAssessment,
  threatState,
  reconState,
  redirectState,
}: WarningEngineInput): ScamAwarenessReport {
  // 1. Handle missing or invalid URL safely
  if (!parsedUrl || !parsedUrl.isValid) {
    return {
      overallRiskLevel: 'Low',
      riskScore: 0,
      warnings: [],
      hasConfirmedThreat: false,
      hasUnavailableChecks: false,
      summaryGuidance:
        'Please enter a valid web URL to generate security and scam awareness warnings.',
      disclaimer: SCAM_AWARENESS_DISCLAIMER,
    };
  }

  // Use provided assessment or compute locally
  const assessment = providedAssessment || assessUrlRisk(parsedUrl);
  const warnings: ScamAwarenessWarning[] = [];

  // =========================================================================
  // CATEGORY D: Known Malicious Threat (External Safe Browsing Match)
  // =========================================================================
  const isConfirmedThreat = threatState?.status === 'threat_detected';
  if (isConfirmedThreat) {
    const threatTypes =
      threatState?.threatTypes && threatState.threatTypes.length > 0
        ? threatState.threatTypes
        : ['THREAT_MATCH'];
    warnings.push({
      id: 'warn-known-threat',
      category: 'known_threat',
      severity: 'critical',
      confidence: 'confirmed',
      title: 'Confirmed Malicious Threat (External Intelligence)',
      evidence: threatTypes.map((t) => `Cataloged threat category: ${t}`),
      explanation: `Google Safe Browsing explicitly identifies this URL as an active threat (${threatTypes.join(', ')}). It matches verified threat intelligence databases of harmful destinations.`,
      potentialScamScenario:
        'Known distribution of malicious software (malware), deceptive social engineering portals, or credential harvesting exploits designed to compromise your device or steal financial/account data.',
      recommendedAction:
        'Do not open this link or interact with the destination. Do not enter credentials, financial information, or download any offered files.',
    });
  }

  // =========================================================================
  // CATEGORY A: Phishing and Credential Theft
  // =========================================================================
  const phishingEvidences: string[] = [];
  let isPhishingConfirmed = false;

  if (threatState?.threatTypes?.includes('SOCIAL_ENGINEERING')) {
    phishingEvidences.push('External intelligence flagged as SOCIAL_ENGINEERING (deceptive portal)');
    isPhishingConfirmed = true;
  }

  if (parsedUrl.hasAuthorityCredentials) {
    phishingEvidences.push(
      `Authority contains credentials before '@' (${parsedUrl.username}@), while true host is "${parsedUrl.hostname}"`
    );
  }

  // Abused keywords in path or subdomains
  const lowerHost = parsedUrl.hostname.toLowerCase();
  const lowerPath = parsedUrl.pathname.toLowerCase();

  const matchedHostKeywords = !parsedUrl.isIpAddress
    ? SENSITIVE_KEYWORDS.filter((kw) => lowerHost.includes(kw))
    : [];
  const matchedPathKeywords = SENSITIVE_KEYWORDS.filter((kw) => lowerPath.includes(kw));

  // Determine if path keywords are the contextual indicator (no host brand lures, no authority credentials, no confirmed threat).
  // Note: Host structural attributes (IP host, non-standard port, Punycode) are evaluated independently in Category E.
  const isContextualPathOnly =
    matchedPathKeywords.length > 0 &&
    matchedHostKeywords.length === 0 &&
    !parsedUrl.hasAuthorityCredentials &&
    !isPhishingConfirmed;

  if (matchedHostKeywords.length > 0) {
    phishingEvidences.push(
      `Sensitive authentication/brand terms embedded in hostname: [${matchedHostKeywords.slice(0, 4).join(', ')}]`
    );
  }

  if (matchedPathKeywords.length > 0) {
    if (isContextualPathOnly) {
      phishingEvidences.push(
        `Sensitive authentication or account keyword(s) in URL path: [${matchedPathKeywords.slice(0, 4).join(', ')}] (contextual indicator; routine on authentic services, not proof of phishing by itself)`
      );
    } else {
      phishingEvidences.push(
        `Sensitive authentication/financial terms found in path: [${matchedPathKeywords.slice(0, 4).join(', ')}]`
      );
    }
  }

  // Risky query parameters
  const matchedParams = parsedUrl.paramsList.filter((p) => {
    const k = p.key.toLowerCase();
    const v = p.value.toLowerCase();
    return (
      SENSITIVE_QUERY_KEYS.some((sk) => k.includes(sk)) ||
      SENSITIVE_KEYWORDS.some((kw) => v.includes(kw)) ||
      v.startsWith('http')
    );
  });
  if (matchedParams.length > 0) {
    phishingEvidences.push(
      `Sensitive query parameters detected handling tokens/redirection: [${matchedParams.map((p) => p.key).slice(0, 3).join(', ')}]`
    );
  }

  if (phishingEvidences.length > 0) {
    // Strong phishing evidence requires genuine deceptive authentication indicators:
    // 1. External threat intelligence confirmed social engineering / malware
    // 2. Embedded authority credentials before '@' (e.g. user@hostname)
    // 3. Hostname-embedded brand/phishing keywords combined with deceptive structural elements
    //    (Punycode, deep subdomains >= 2, or direct IP hostname)
    // Note: URL-wide structural score alone must NOT classify sensitive path keywords as high-risk phishing.
    const hasStrongPhishingEvidence =
      isPhishingConfirmed ||
      parsedUrl.hasAuthorityCredentials ||
      (matchedHostKeywords.length > 0 && (parsedUrl.isIpAddress || parsedUrl.hasPunycode || parsedUrl.subdomainCount >= 2));

    let severity: WarningSeverity;
    let confidence: FindingConfidence;
    let title: string;
    let explanation: string;
    let potentialScamScenario: string;
    let recommendedAction: string;

    if (hasStrongPhishingEvidence) {
      severity = parsedUrl.hasAuthorityCredentials || isPhishingConfirmed ? 'critical' : 'high';
      confidence = isPhishingConfirmed ? 'confirmed' : 'suspicious';
      title = isPhishingConfirmed
        ? 'Confirmed Social Engineering / Deceptive Portal'
        : 'High-Risk Phishing or Credential Theft Indicators';
      explanation = isPhishingConfirmed
        ? 'External threat intelligence confirmed this link as a social engineering or phishing destination designed to harvest credentials or deceive users.'
        : 'The URL combines high-risk structural anomalies (such as deceptive authority credentials or spoofed host elements) with authentication lures. This strongly indicates a potential credential harvesting scheme.';
      potentialScamScenario =
        'Attackers use deceptive authority structures, spoofed hostnames, or unverified portals to capture account passwords, two-factor authentication tokens, or payment details.';
      recommendedAction =
        'Do not submit credentials, PINs, or sensitive information. Verify the organization’s authentic domain independently before taking any action.';
    } else if (isContextualPathOnly && matchedParams.length === 0) {
      // Sensitive path keywords alone (e.g. /login, /verify, /banking, /wallet on standard domain or IP)
      severity = 'low';
      confidence = 'informational';
      title = 'Contextual Sensitive Action Keywords in URL Path';
      explanation = `The URL path contains sensitive keywords ([${matchedPathKeywords.slice(0, 4).join(', ')}]) commonly associated with sign-in, verification, or banking actions. Sensitive path keywords are standard on authentic websites for user authentication; they serve as a contextual reminder to verify that the domain ("${parsedUrl.hostname}") belongs to your intended institution, not proof of phishing.`;
      potentialScamScenario =
        'While authentic services use these paths for legitimate account features, phishing campaigns mimic authentic paths on lookalike domains. If this link was sent unexpectedly via SMS or email, verify the domain before signing in.';
      recommendedAction = `Confirm that the domain "${parsedUrl.hostname}" is the authentic web address of the service you expect. If confirmed, sign in normally; if unverified or unexpected, navigate directly to the official website.`;
    } else {
      // Moderate indicators (e.g. matched parameters or moderate combinations)
      severity = 'medium';
      confidence = 'suspicious';
      title = 'Potential Authentication or Credential Indicators';
      explanation =
        'The link structure contains markers commonly used in sign-in portals and token handling. While legitimate websites utilize these patterns, verify that the host domain matches the service you intend to access.';
      potentialScamScenario =
        'An attacker may direct users to a login or verification page on an unverified domain to capture account credentials or session tokens.';
      recommendedAction =
        'Check that the destination domain matches the official service address. Never enter sensitive credentials through unverified links from unsolicited messages.';
    }

    warnings.push({
      id: isContextualPathOnly && matchedParams.length === 0 ? 'warn-contextual-keywords' : 'warn-phishing-credentials',
      category: 'phishing_credential_theft',
      severity,
      confidence,
      title,
      evidence: phishingEvidences,
      explanation,
      potentialScamScenario,
      recommendedAction,
    });
  }

  // =========================================================================
  // CATEGORY B: Suspicious Redirect Behaviour
  // =========================================================================
  if (redirectState?.status === 'completed' && redirectState.data) {
    const rData = redirectState.data;
    const redirectEvidences: string[] = [];
    let redirectSeverity: WarningSeverity = 'medium';

    if (rData.status === 'BLOCKED_SPECIAL_USE_IP') {
      redirectEvidences.push(
        'Redirect attempted to route to a blocked private, loopback, or reserved network address'
      );
      redirectSeverity = 'critical';
    } else if (rData.status === 'REDIRECT_LOOP') {
      redirectEvidences.push('Infinite redirect loop detected during inspection');
      redirectSeverity = 'high';
    } else if (rData.status === 'MAX_HOPS_EXCEEDED') {
      redirectEvidences.push('Maximum redirect threshold exceeded (5+ consecutive hops)');
      redirectSeverity = 'medium';
    }

    // Protocol downgrade (HTTPS -> HTTP)
    if (rData.hops.length >= 2) {
      const initialHop = rData.hops[0];
      const finalHop = rData.hops[rData.hops.length - 1];
      if (initialHop.isHttps && !finalHop.isHttps && finalHop.statusCode !== 0) {
        redirectEvidences.push(
          `HTTPS encryption was downgraded to unencrypted HTTP at hop ${finalHop.hopIndex} (${finalHop.url})`
        );
        redirectSeverity = 'high';
      }
    }

    // Critical/warning findings reported by inspector
    for (const f of rData.findings) {
      if (f.severity === 'critical' || f.severity === 'warning') {
        if (!redirectEvidences.some((e) => e.includes(f.title))) {
          redirectEvidences.push(`${f.title}: ${f.description}`);
        }
      }
    }

    // Cross-domain redirection
    if (rData.totalRedirects > 0 && rData.finalDestination) {
      try {
        const initialHost = new URL(rData.initialUrl).hostname;
        const finalHost = new URL(rData.finalDestination).hostname;
        if (initialHost !== finalHost && !redirectEvidences.some((e) => e.includes('Cross-domain'))) {
          redirectEvidences.push(
            `Destination shifts across domains: initial host "${initialHost}" forwards to "${finalHost}"`
          );
        }
      } catch {
        // ignore parsing errors on intermediate URLs
      }
    }

    if (redirectEvidences.length > 0) {
      warnings.push({
        id: 'warn-suspicious-redirect',
        category: 'suspicious_redirect',
        severity: redirectSeverity,
        confidence: 'suspicious',
        title: 'Suspicious Redirect Behaviour Detected',
        evidence: redirectEvidences,
        explanation:
          'The link executes redirect behavior that alters transport security or conceals the ultimate landing location. While benign short links and affiliate redirects exist, unexpected redirection is routinely employed to bypass messaging filters.',
        potentialScamScenario:
          'Fraudulent campaigns frequently chain multiple redirects or downgrade encryption to evade security inspection before steering victims to an unauthorized destination.',
        recommendedAction:
          'Inspect the final destination address carefully before proceeding. Never enter credentials or download content if the final domain differs unexpectedly from the link you received.',
      });
    }
  }

  // =========================================================================
  // CATEGORY C: Newly Registered Domain (RDAP Domain Age)
  // =========================================================================
  if (
    reconState?.status === 'completed' &&
    reconState.data?.rdap?.status === 'available' &&
    typeof reconState.data.rdap.domainAgeDays === 'number'
  ) {
    const ageDays = reconState.data.rdap.domainAgeDays;
    if (ageDays <= 30) {
      const regDateStr = reconState.data.rdap.registrationDate
        ? new Date(reconState.data.rdap.registrationDate).toLocaleDateString()
        : 'recent';
      const registrar = reconState.data.rdap.registrar || 'unspecified registrar';

      warnings.push({
        id: 'warn-new-domain',
        category: 'new_domain',
        severity: 'medium',
        confidence: 'suspicious',
        title: `Recently Registered Domain (${ageDays} Days Old)`,
        evidence: [
          `Domain "${reconState.data.hostname}" was registered ${ageDays} day(s) ago (${regDateStr}) via ${registrar}`,
        ],
        explanation: `This domain was registered only ${ageDays} day(s) ago. A newly registered domain is a notable risk indicator because threat actors routinely create disposable domains for short-lived phishing or fraud campaigns before domain reputation filters can flag them. However, a young domain is not definitive proof of fraud on its own.`,
        potentialScamScenario:
          'Disposable domains are commonly used for short-lived SMS delivery fee scams, fake parcel alerts, or time-sensitive emergency lures that vanish before defenses update.',
        recommendedAction:
          'Exercise extra vigilance. If the message claims to represent an established bank, courier, or public agency, do not trust this link—established entities do not send official communications from brand-new web addresses.',
      });
    }
  }

  // =========================================================================
  // CATEGORY E: Suspicious URL Structure or Host Anomaly
  // =========================================================================
  const structuralEvidences: string[] = [];

  if (parsedUrl.hasPunycode) {
    structuralEvidences.push(
      `Punycode (xn--) internationalized domain label in hostname (${parsedUrl.hostname})`
    );
  }

  if (parsedUrl.isIpAddress) {
    structuralEvidences.push(
      `Direct numeric IP address (${parsedUrl.hostname}) used instead of registered domain name`
    );
  }

  if (parsedUrl.subdomainCount >= 3) {
    structuralEvidences.push(
      `Excessive subdomain depth (${parsedUrl.subdomainCount} levels) on host "${parsedUrl.hostname}"`
    );
  }

  if (parsedUrl.isNonStandardPort) {
    const defaultWebPort = parsedUrl.isHttps ? '443 for HTTPS' : '80 for HTTP';
    const portEvidence =
      parsedUrl.explicitPort === '8080'
        ? `Non-standard network port :8080 specified (alternative/non-default HTTP web port; standard default port is 80 for HTTP and 443 for HTTPS). Note: port 8080 is commonly used for caching proxies or local testing and does not prove malicious activity on its own.`
        : `Non-standard network port :${parsedUrl.explicitPort} specified (standard default is port ${defaultWebPort}; standard web defaults are 80 for HTTP and 443 for HTTPS). Note: non-standard ports warrant destination verification but do not prove malicious activity by themselves.`;
    structuralEvidences.push(portEvidence);
  }

  if (!parsedUrl.isHttps && parsedUrl.protocol === 'http:') {
    structuralEvidences.push('Unencrypted HTTP protocol scheme (lacks TLS encryption)');
  }

  const isShortener = KNOWN_URL_SHORTENERS.some(
    (s) => parsedUrl.hostname === s || parsedUrl.hostname.endsWith(`.${s}`)
  );
  if (isShortener) {
    structuralEvidences.push(
      `Known URL shortener service (${parsedUrl.hostname}) obscuring true destination host`
    );
  }

  if (structuralEvidences.length > 0) {
    const hasSevereHostAnomaly =
      parsedUrl.hasPunycode || parsedUrl.isIpAddress || isShortener || parsedUrl.subdomainCount >= 3;

    const severity: WarningSeverity =
      parsedUrl.hasPunycode || parsedUrl.isIpAddress || structuralEvidences.length >= 3
        ? 'high'
        : structuralEvidences.length >= 2 || (parsedUrl.isNonStandardPort && parsedUrl.explicitPort !== '8080')
        ? 'medium'
        : 'low';

    const title = !hasSevereHostAnomaly && parsedUrl.isNonStandardPort
      ? 'Non-Standard Network Port Specified'
      : 'Suspicious Hostname or URL Structure';

    const explanation = !hasSevereHostAnomaly && parsedUrl.isNonStandardPort
      ? `The URL specifies non-standard port :${parsedUrl.explicitPort}. Standard web default ports are 80 for HTTP and 443 for HTTPS. While port 8080 and other alternative ports are widely used for local web servers, caching proxies, and testing, using an alternative port does not prove malicious activity on its own; it merely diverges from default web traffic conventions.`
      : `The address exhibits structural patterns (${structuralEvidences.length} noted) that diverge from standard web conventions. Direct IP addresses, lookalike Punycode characters, and obscured shorteners are frequently used in deceptive messages.`;

    warnings.push({
      id: 'warn-suspicious-structure',
      category: 'suspicious_url_structure',
      severity,
      confidence: 'suspicious',
      title,
      evidence: structuralEvidences,
      explanation,
      potentialScamScenario:
        'Attackers often use numeric IP addresses or internationalized homoglyphs to bypass domain blocklists, or shorteners to hide dangerous destinations from preview screens.',
      recommendedAction:
        'Verify the exact host address. Avoid connecting to numeric IP addresses or obscured short links received from unknown senders.',
    });
  }

  // =========================================================================
  // CATEGORY F: Inconclusive or Unavailable Checks
  // =========================================================================
  const unavailableEvidences: string[] = [];

  if (threatState?.status === 'unconfigured') {
    unavailableEvidences.push(
      'Google Safe Browsing: Not configured on server (running offline structural heuristic mode)'
    );
  } else if (threatState?.status === 'unavailable') {
    unavailableEvidences.push(
      'Google Safe Browsing: Threat intelligence service temporarily unavailable'
    );
  }

  if (reconState?.status === 'error') {
    unavailableEvidences.push(
      `Domain & DNS Reconnaissance: ${reconState.errorMessage || 'Service temporarily offline'}`
    );
  } else if (reconState?.status === 'completed' && reconState.data?.rdap) {
    const rdapStatus = reconState.data.rdap.status;
    if (rdapStatus === 'redacted') {
      unavailableEvidences.push(
        'Domain Registration Age: Registration date withheld by registry privacy policy'
      );
    } else if (rdapStatus === 'unsupported' || rdapStatus === 'error' || rdapStatus === 'timeout') {
      unavailableEvidences.push(
        `Domain Registration Age: Registry RDAP check ${rdapStatus}`
      );
    }
  }

  if (redirectState?.status === 'unavailable' || redirectState?.status === 'error') {
    unavailableEvidences.push(
      `Redirect Inspection: ${redirectState.errorMessage || 'Service temporarily unavailable'}`
    );
  }

  const hasUnavailableChecks = unavailableEvidences.length > 0;
  if (hasUnavailableChecks) {
    warnings.push({
      id: 'warn-inconclusive-checks',
      category: 'inconclusive_check',
      severity: 'info',
      confidence: 'inconclusive',
      title: 'Inconclusive / Unavailable External Checks',
      evidence: unavailableEvidences,
      explanation:
        'One or more secondary intelligence checks could not be completed for this link. While local structural analysis remains fully active, external databases could not verify or refute this URL. Never interpret an unavailable check as a clean result.',
      potentialScamScenario:
        'Evasive or brand-new threats cannot be ruled out when threat feeds or domain registries are unreachable.',
      recommendedAction:
        'Do not interpret unavailable checks as a clean result. Rely on local structural analysis and verify the sender independently before opening.',
    });
  }

  // =========================================================================
  // CATEGORY G: No Obvious Threats Detected
  // =========================================================================
  const hasSubstantiveWarning = warnings.some(
    (w) =>
      w.category === 'known_threat' ||
      w.category === 'phishing_credential_theft' ||
      w.category === 'suspicious_redirect' ||
      w.category === 'new_domain' ||
      (w.category === 'suspicious_url_structure' && w.severity !== 'low')
  );

  if (!hasSubstantiveWarning && assessment.score < 30) {
    const noThreatEvidences: string[] = [
      'All 10 structural heuristic checks passed (0 high-risk points triggered)',
      'Standard protocol and domain structure',
    ];
    if (threatState?.status === 'clean') {
      noThreatEvidences.push('Google Safe Browsing returned no active threat records');
    }

    warnings.push({
      id: 'warn-no-obvious-threat',
      category: 'no_obvious_threat',
      severity: 'low',
      confidence: 'informational',
      title: 'No Obvious Suspicious Indicators Detected',
      evidence: noThreatEvidences,
      explanation:
        'The link conforms to standard web conventions and none of the structural heuristic rules were triggered. No active threats were detected by the checks performed. However, this does not guarantee the link is safe.',
      potentialScamScenario:
        'Targeted social-engineering campaigns, compromised legitimate accounts, or newly launched zero-day phishing pages may appear technically standard and clean under automated inspection.',
      recommendedAction:
        'Even links with low risk scores can be dangerous if sent by an impostor. Always confirm the identity of the person or entity sending you the link via an independent, trusted communication channel before entering passwords or payment details.',
    });
  }

  // =========================================================================
  // SORT & COMBINE FINDINGS
  // =========================================================================
  // Sort prioritized by severity: critical -> high -> medium -> low -> info
  warnings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summaryGuidance = generateSummaryGuidance(
    assessment.level,
    isConfirmedThreat,
    hasUnavailableChecks,
    warnings
  );

  return {
    overallRiskLevel: assessment.level,
    riskScore: assessment.score,
    warnings,
    hasConfirmedThreat: isConfirmedThreat,
    hasUnavailableChecks,
    summaryGuidance,
    disclaimer: SCAM_AWARENESS_DISCLAIMER,
  };
}

function generateSummaryGuidance(
  level: RiskLevel,
  hasConfirmedThreat: boolean,
  hasUnavailableChecks: boolean,
  warnings: ScamAwarenessWarning[]
): string {
  if (hasConfirmedThreat) {
    return 'CRITICAL THREAT: This destination is confirmed malicious in threat intelligence databases. Do not open the link or enter any credentials or payment information.';
  }

  if (level === 'High') {
    return 'HIGH RISK: Multiple suspicious indicators or structural anomalies were identified. We strongly recommend NOT opening this link and verifying the sender through an official, independently obtained channel.';
  }

  if (level === 'Medium') {
    return 'MEDIUM RISK: Suspicious characteristics were observed. Review the specific evidence below and exercise caution before deciding whether to interact with this link.';
  }

  if (warnings.some((w) => w.id === 'warn-contextual-keywords')) {
    return 'LOW RISK: Standard domain structure with contextual authentication or account keywords in the path. Ensure the domain matches your intended service before signing in.';
  }

  if (hasUnavailableChecks && warnings.length === 1 && warnings[0].category === 'inconclusive_check') {
    return 'LIMITED CHECKS: No obvious structural red flags were detected, but some external intelligence checks were unavailable. Proceed with caution and verify the sender.';
  }

  return 'NO OBVIOUS THREATS: No suspicious indicators were flagged by the checks performed. However, this does not guarantee the link is safe—always verify unfamiliar senders.';
}
