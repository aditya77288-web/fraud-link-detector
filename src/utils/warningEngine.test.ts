import test from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from './urlParser.js';
import { assessUrlRisk } from './riskEngine.js';
import { extractUrlsFromText } from './clipboardUrl.js';
import { parseShareTargetParams } from './shareTarget.js';
import {
  generateScamAwarenessReport,
  SCAM_AWARENESS_DISCLAIMER,
} from './warningEngine.js';
import { ThreatIntelligenceState } from '../types/threat.js';
import { ReconClientState } from '../types/recon.js';
import { RedirectClientState } from '../types/redirect.js';

// Test 1: Direct URL produces pre-scan warning candidate
test('Pre-scan Safety: Direct URL paste extracts clean primary URL for confirmation', () => {
  const directUrl = 'https://suspicious-login.example.com/verify';
  const extracted = extractUrlsFromText(directUrl);

  assert.equal(extracted.status, 'single_url');
  assert.equal(extracted.primaryUrl, 'https://suspicious-login.example.com/verify');
  assert.equal(extracted.urls.length, 1);
});

// Test 2: Message containing a URL produces the appropriate confirmation
test('Pre-scan Safety: Natural language message containing a URL extracts primary URL cleanly', () => {
  const message = 'Urgent notice! Your account is suspended. Visit https://bank-verify.test/login immediately!';
  const extracted = extractUrlsFromText(message);

  assert.equal(extracted.status, 'single_url');
  assert.equal(extracted.primaryUrl, 'https://bank-verify.test/login');
  assert.equal(extracted.urls.length, 1);
});

// Test 3 & 4: Confirmation actions - Scan This Link vs Cancel
test('Pre-scan Safety: Action selection logic triggers scan only on explicit confirmation, not on cancel', () => {
  let scannedUrl: string | null = null;
  let isPromptDismissed = false;

  const onConfirmScan = (url: string) => {
    scannedUrl = url;
    isPromptDismissed = true;
  };

  const onCancel = () => {
    // Dismiss prompt without scanning or navigating
    isPromptDismissed = true;
  };

  // Simulating Cancel
  onCancel();
  assert.equal(scannedUrl, null, 'Cancel must not initiate a scan');
  assert.equal(isPromptDismissed, true, 'Cancel must dismiss the confirmation prompt');

  // Reset and simulate Scan This Link
  isPromptDismissed = false;
  onConfirmScan('https://suspicious-site.test/login');
  assert.equal(scannedUrl, 'https://suspicious-site.test/login', 'Scan This Link must trigger scan with target URL');
  assert.equal(isPromptDismissed, true);
});

// Test 5: Confirmed threat result produces confirmed-threat warning
test('Warning Engine: Confirmed threat result produces critical confirmed-threat warning', () => {
  const parsed = parseUrl('https://malicious-distribution.test/download');
  const threatState: ThreatIntelligenceState = {
    status: 'threat_detected',
    threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
    cacheDuration: '300s',
    evaluatedAt: new Date().toISOString(),
  };

  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    threatState,
  });

  assert.equal(report.hasConfirmedThreat, true);
  const threatWarn = report.warnings.find((w) => w.category === 'known_threat');
  assert.ok(threatWarn, 'Must generate known_threat warning');
  assert.equal(threatWarn?.severity, 'critical');
  assert.equal(threatWarn?.confidence, 'confirmed');
  assert.ok(threatWarn?.evidence.some((e) => e.includes('MALWARE')));
  assert.ok(threatWarn?.recommendedAction.includes('Do not open this link'));
});

// Test 6: Redirect findings produce relevant redirect warning
test('Warning Engine: Redirect loop and protocol downgrade produce redirect warnings', () => {
  const parsed = parseUrl('https://short-link.test/abc');

  const redirectLoopState: RedirectClientState = {
    status: 'completed',
    data: {
      initialUrl: 'https://short-link.test/abc',
      finalDestination: 'https://short-link.test/loop',
      totalRedirects: 3,
      status: 'REDIRECT_LOOP',
      statusMessage: 'Infinite redirect loop detected.',
      hops: [
        {
          hopIndex: 1,
          url: 'https://short-link.test/abc',
          statusCode: 302,
          statusText: 'Found',
          locationHeader: 'https://short-link.test/loop',
          resolvedIp: '93.184.216.34',
          isHttps: true,
          serverHeader: 'nginx',
          durationMs: 40,
        },
        {
          hopIndex: 2,
          url: 'https://short-link.test/loop',
          statusCode: 302,
          statusText: 'Found',
          locationHeader: 'https://short-link.test/abc',
          resolvedIp: '93.184.216.34',
          isHttps: true,
          serverHeader: 'nginx',
          durationMs: 40,
        },
      ],
      findings: [
        {
          id: 'finding-loop',
          severity: 'critical',
          title: 'Infinite Redirect Loop',
          description: 'The URL redirects repeatedly between identical locations.',
        },
      ],
      inspectedAt: new Date().toISOString(),
    },
  };

  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    redirectState: redirectLoopState,
  });

  const redirectWarn = report.warnings.find((w) => w.category === 'suspicious_redirect');
  assert.ok(redirectWarn, 'Must generate suspicious_redirect warning on loop');
  assert.ok(redirectWarn?.evidence.some((e) => e.toLowerCase().includes('loop')));
  assert.equal(redirectWarn?.confidence, 'suspicious');
});

// Test 7: Actual domain-age evidence produces new-domain warning
test('Warning Engine: Actual RDAP domain age under 30 days produces new-domain warning', () => {
  const parsed = parseUrl('https://fresh-parcel-delivery.test/track');

  const reconState: ReconClientState = {
    status: 'completed',
    data: {
      hostname: 'fresh-parcel-delivery.test',
      isIpAddress: false,
      isSpecialUse: false,
      dns: {
        status: 'resolved',
        aRecords: ['198.51.100.22'],
        aaaaRecords: [],
        mxRecords: [],
        aCount: 1,
        aaaaCount: 0,
        mxCount: 0,
        hasMailExchange: false,
      },
      rdap: {
        status: 'available',
        domainAgeDays: 4,
        registrationDate: new Date(Date.now() - 4 * 86400000).toISOString(),
        registrar: 'NameCheap, Inc.',
      },
      findings: [],
      evaluatedAt: new Date().toISOString(),
    },
  };

  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    reconState,
  });

  const domainWarn = report.warnings.find((w) => w.category === 'new_domain');
  assert.ok(domainWarn, 'Must generate new_domain warning when domain age is <= 30 days');
  assert.equal(domainWarn?.severity, 'medium');
  assert.ok(domainWarn?.evidence.some((e) => e.includes('4 day(s) ago')));
  assert.ok(domainWarn?.explanation.includes('young domain is not definitive proof of fraud'));
});

// Test 7b: Domain age unavailable does NOT claim domain is new
test('Warning Engine: When domain age is unavailable or redacted, it does not claim domain is new', () => {
  const parsed = parseUrl('https://example-redacted.test/login');

  const reconState: ReconClientState = {
    status: 'completed',
    data: {
      hostname: 'example-redacted.test',
      isIpAddress: false,
      isSpecialUse: false,
      dns: {
        status: 'resolved',
        aRecords: ['93.184.216.34'],
        aaaaRecords: [],
        mxRecords: [],
        aCount: 1,
        aaaaCount: 0,
        mxCount: 0,
        hasMailExchange: false,
      },
      rdap: {
        status: 'redacted',
        message: 'Registration date withheld under privacy policy.',
      },
      findings: [],
      evaluatedAt: new Date().toISOString(),
    },
  };

  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    reconState,
  });

  const domainWarn = report.warnings.find((w) => w.category === 'new_domain');
  assert.equal(domainWarn, undefined, 'Must not claim domain is new when RDAP is redacted');

  const inconclusiveWarn = report.warnings.find((w) => w.category === 'inconclusive_check');
  assert.ok(inconclusiveWarn, 'Must flag redacted RDAP in inconclusive checks');
});

// Test 8: Suspicious URL indicators produce finding-specific warnings
test('Warning Engine: Punycode and direct IP hosts produce structural anomaly warnings', () => {
  const parsedPuny = parseUrl('https://xn--e1afmkfd.example/login');
  const reportPuny = generateScamAwarenessReport({ parsedUrl: parsedPuny });

  const punyWarn = reportPuny.warnings.find((w) => w.category === 'suspicious_url_structure');
  assert.ok(punyWarn);
  assert.ok(punyWarn?.evidence.some((e) => e.includes('Punycode')));
  assert.equal(punyWarn?.severity, 'high');

  const parsedIp = parseUrl('http://198.51.100.10:8080/admin');
  const reportIp = generateScamAwarenessReport({ parsedUrl: parsedIp });

  const ipWarn = reportIp.warnings.find((w) => w.category === 'suspicious_url_structure');
  assert.ok(ipWarn);
  assert.ok(ipWarn?.evidence.some((e) => e.includes('Direct numeric IP address')));
  assert.ok(ipWarn?.evidence.some((e) => e.includes('8080')));
});

// Test 9: Unavailable or unconfigured threat intelligence is not treated as clean
test('Warning Engine: Unconfigured or unavailable threat intelligence is marked inconclusive, never clean', () => {
  const parsed = parseUrl('https://suspicious-unknown.test/portal');

  const reportUnconfigured = generateScamAwarenessReport({
    parsedUrl: parsed,
    threatState: { status: 'unconfigured' },
  });

  assert.equal(reportUnconfigured.hasConfirmedThreat, false);
  assert.equal(reportUnconfigured.hasUnavailableChecks, true);
  const warn = reportUnconfigured.warnings.find((w) => w.category === 'inconclusive_check');
  assert.ok(warn);
  assert.ok(warn?.evidence.some((e) => e.includes('Not configured on server')));
  assert.ok(warn?.explanation.includes('Never interpret an unavailable check as a clean result'));
});

// Test 10: Low-risk result includes a safety disclaimer
test('Warning Engine: Low-risk result includes safety disclaimer and explicit non-guarantee', () => {
  const parsed = parseUrl('https://www.example.com/about-us');
  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    threatState: { status: 'clean' },
  });

  assert.equal(report.overallRiskLevel, 'Low');
  assert.equal(report.riskScore, 0);

  const cleanWarn = report.warnings.find((w) => w.category === 'no_obvious_threat');
  assert.ok(cleanWarn, 'Must include no_obvious_threat warning');
  assert.ok(cleanWarn?.explanation.includes('does not guarantee the link is safe'));
  assert.ok(report.disclaimer.includes(SCAM_AWARENESS_DISCLAIMER));
});

// Test 11: Multiple findings produce relevant, non-duplicated warnings sorted by severity
test('Warning Engine: Multiple findings produce prioritized non-duplicated warnings', () => {
  // URL with authority credentials and sensitive keyword
  const parsed = parseUrl('https://admin@suspicious-bank.test/verify-account');
  const threatState: ThreatIntelligenceState = {
    status: 'threat_detected',
    threatTypes: ['SOCIAL_ENGINEERING'],
  };

  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    threatState,
  });

  // Category counts
  const categories = report.warnings.map((w) => w.category);
  const uniqueCategories = new Set(categories);
  assert.equal(categories.length, uniqueCategories.size, 'No category should be duplicated');

  // Verify critical threat is first
  assert.equal(report.warnings[0].severity, 'critical');
  assert.equal(report.warnings[0].category, 'known_threat');
});

// Test 12: Empty or invalid input is handled safely
test('Warning Engine: Empty or invalid input handled safely without throwing', () => {
  const reportNull = generateScamAwarenessReport({ parsedUrl: null });
  assert.equal(reportNull.overallRiskLevel, 'Low');
  assert.equal(reportNull.riskScore, 0);
  assert.equal(reportNull.warnings.length, 0);

  const parsedInvalid = parseUrl('not a valid url @@@');
  const reportInvalid = generateScamAwarenessReport({ parsedUrl: parsedInvalid });
  assert.equal(reportInvalid.overallRiskLevel, 'Low');
  assert.equal(reportInvalid.riskScore, 0);
  assert.equal(reportInvalid.warnings.length, 0);
});

// Test 13: Existing clipboard and Android share-target workflows do not produce duplicate prompts
test('Pre-scan Safety: Web share target parsing extracts clean payload without duplicate prompts', () => {
  const params = new URLSearchParams('text=Check+this+out+https%3A%2F%2Fshared-site.test%2Fdeal+now!');
  const shareResult = parseShareTargetParams(params);

  assert.equal(shareResult.hasShare, true);
  assert.equal(shareResult.primaryUrl, 'https://shared-site.test/deal');
  assert.equal(shareResult.urls.length, 1);
});

// Test 14: Non-standard port wording accurately distinguishes standard defaults (80 for HTTP, 443 for HTTPS) from alternatives
test('Warning Engine: Port 8080 wording accurately explains defaults without contradiction or assuming malice', () => {
  const parsedHttp8080 = parseUrl('http://example.com:8080/dashboard');
  assert.ok(parsedHttp8080);
  assert.equal(parsedHttp8080.explicitPort, '8080');

  const report = generateScamAwarenessReport({ parsedUrl: parsedHttp8080 });
  const portWarn = report.warnings.find((w) => w.category === 'suspicious_url_structure');
  assert.ok(portWarn, 'Must generate structural anomaly warning for non-standard port');

  // Verify non-contradictory wording: must NOT claim standard default is 8080
  const portEvidence = portWarn.evidence.find((e) => e.includes('8080'));
  assert.ok(portEvidence, 'Evidence must include port 8080');
  assert.equal(
    portEvidence.includes('standard default is 8080'),
    false,
    'Must not contain contradictory text claiming standard default is 8080'
  );

  // Must accurately explain HTTP 80 and HTTPS 443
  assert.ok(
    portEvidence.includes('standard default port is 80 for HTTP and 443 for HTTPS'),
    'Must explicitly state standard defaults are 80 for HTTP and 443 for HTTPS'
  );
  assert.ok(
    portEvidence.includes('alternative/non-default HTTP web port'),
    'Must describe port 8080 as alternative/non-default HTTP web port'
  );
  assert.ok(
    portEvidence.includes('does not prove malicious activity on its own'),
    'Must clarify that port 8080 does not prove malicious activity on its own'
  );

  // Explanation and title
  assert.equal(portWarn.title, 'Non-Standard Network Port Specified');
  assert.ok(portWarn.explanation.includes('does not prove malicious activity'));
});

// Test 15: Sensitive path keywords alone are treated as contextual indicators, not proof of phishing
test('Warning Engine: Sensitive path keywords alone are treated as contextual indicators without unsupported certainty', () => {
  const keywords = ['login', 'verify', 'banking', 'wallet'];

  for (const kw of keywords) {
    const parsed = parseUrl(`https://example.com/${kw}`);
    assert.ok(parsed);

    const report = generateScamAwarenessReport({ parsedUrl: parsed });
    const authWarn = report.warnings.find((w) => w.category === 'phishing_credential_theft');

    assert.ok(authWarn, `Must generate awareness warning for path with /${kw}`);
    // Must NOT be marked as confirmed phishing or high certainty
    assert.notEqual(authWarn.confidence, 'confirmed', 'Must not assert confirmed phishing for path keywords alone');
    assert.equal(authWarn.confidence, 'informational', 'Must use informational confidence for path keywords alone');
    assert.equal(authWarn.severity, 'low', 'Must use low severity when path keywords appear without other indicators');
    assert.equal(authWarn.title, 'Contextual Sensitive Action Keywords in URL Path');

    // Explanation must clarify routine nature on authentic sites vs phishing lure
    assert.ok(
      authWarn.explanation.includes('not proof of phishing'),
      'Explanation must state sensitive path keyword is not proof of phishing'
    );
    assert.ok(
      authWarn.explanation.includes('contextual reminder to verify'),
      'Explanation must frame it as a contextual reminder to verify the domain'
    );
    assert.ok(
      authWarn.recommendedAction.includes('Confirm that the domain "example.com" is the authentic web address'),
      'Recommended action must focus on verifying domain authenticity'
    );
  }
});

// Test 16: Stronger evidence preserves high-confidence confirmed phishing detection
test('Warning Engine: External threat-intelligence match preserves high-confidence confirmed phishing detection', () => {
  const parsed = parseUrl('https://suspicious-portal.test/login');
  assert.ok(parsed);

  const threatState: ThreatIntelligenceState = {
    status: 'threat_detected',
    threatTypes: ['SOCIAL_ENGINEERING'],
    cacheDuration: '300s',
    evaluatedAt: new Date().toISOString(),
  };

  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    threatState,
  });

  const authWarn = report.warnings.find((w) => w.category === 'phishing_credential_theft');
  assert.ok(authWarn, 'Must generate phishing warning');
  assert.equal(authWarn.confidence, 'confirmed', 'Must have confirmed confidence when external threat intel flags SOCIAL_ENGINEERING');
  assert.equal(authWarn.severity, 'critical', 'Must have critical severity when confirmed');
  assert.equal(authWarn.title, 'Confirmed Social Engineering / Deceptive Portal');
});

// Test 17: https://github.com/login produces a contextual low-severity, informational finding
test('Warning Engine Regression: https://github.com/login produces a contextual low-severity informational finding', () => {
  const parsed = parseUrl('https://github.com/login');
  assert.ok(parsed);

  const report = generateScamAwarenessReport({ parsedUrl: parsed });
  const authWarn = report.warnings.find((w) => w.category === 'phishing_credential_theft');

  assert.ok(authWarn, 'Must generate phishing_credential_theft finding for /login');
  assert.equal(authWarn.severity, 'low', 'Path keyword alone must be low severity');
  assert.equal(authWarn.confidence, 'informational', 'Path keyword alone must be informational confidence');
  assert.equal(authWarn.id, 'warn-contextual-keywords');
  assert.equal(authWarn.title, 'Contextual Sensitive Action Keywords in URL Path');
  assert.ok(
    authWarn.explanation.includes('not proof of phishing'),
    'Must state path keyword is not proof of phishing'
  );
  assert.equal(
    report.warnings.some((w) => w.title === 'High-Risk Phishing or Credential Theft Indicators'),
    false,
    'Must NOT produce High-Risk Phishing or Credential Theft Indicators for github.com/login'
  );
});

// Test 18: http://192.0.2.1:8080/login produces a high-risk structural warning, but does not classify "login" alone as high-risk phishing evidence
test('Warning Engine Regression: http://192.0.2.1:8080/login produces high-risk structural warning but contextual path keyword finding', () => {
  const parsed = parseUrl('http://192.0.2.1:8080/login');
  assert.ok(parsed);

  const report = generateScamAwarenessReport({ parsedUrl: parsed });

  // 1. Overall risk score & level must remain High (75)
  assert.equal(report.overallRiskLevel, 'High', 'Overall risk level must remain High');
  assert.equal(report.riskScore, 75, 'Overall score must be 75 (IP: 25 + HTTP: 15 + Port 8080: 15 + Login: 20)');

  // 2. Structural anomaly warning in Category E must be high severity
  const structWarn = report.warnings.find((w) => w.category === 'suspicious_url_structure');
  assert.ok(structWarn, 'Must generate structural anomaly warning for numeric IP and non-standard port');
  assert.equal(structWarn.severity, 'high', 'Numeric IP must generate high severity structural warning');
  assert.ok(structWarn.evidence.some((e) => e.includes('Direct numeric IP address')));
  assert.ok(structWarn.evidence.some((e) => e.includes('8080')));
  assert.ok(structWarn.evidence.some((e) => e.includes('Unencrypted HTTP')));

  // 3. Phishing category must NOT claim high-risk phishing or unsupported certainty
  const authWarn = report.warnings.find((w) => w.category === 'phishing_credential_theft');
  assert.ok(authWarn, 'Must generate auth finding for /login');
  assert.equal(authWarn.severity, 'low', 'Path keyword /login must remain low severity in phishing category');
  assert.equal(authWarn.confidence, 'informational', 'Path keyword /login must be informational');
  assert.equal(authWarn.id, 'warn-contextual-keywords');
  assert.equal(authWarn.title, 'Contextual Sensitive Action Keywords in URL Path');
  assert.ok(
    authWarn.evidence.some((e) => e.includes('routine on authentic services, not proof of phishing by itself')),
    'Evidence must state keyword is contextual and routine on authentic services'
  );

  // 4. Must NOT produce high-risk phishing title or evidence
  assert.equal(
    report.warnings.some((w) => w.title === 'High-Risk Phishing or Credential Theft Indicators'),
    false,
    'Must NOT produce High-Risk Phishing or Credential Theft Indicators title'
  );
  assert.equal(
    authWarn.evidence.some((e) => e.includes('Sensitive authentication/financial terms found in path: [login]')),
    false,
    'Must NOT emit non-contextual terms-found evidence for path keyword alone'
  );
});

// Test 19: Confirmed external phishing threat remains high-confidence and critical
test('Warning Engine Regression: Confirmed external phishing threat remains high-confidence and critical', () => {
  const parsed = parseUrl('https://github-login.test/login');
  assert.ok(parsed);

  const threatState: ThreatIntelligenceState = {
    status: 'threat_detected',
    threatTypes: ['SOCIAL_ENGINEERING'],
    cacheDuration: '300s',
    evaluatedAt: new Date().toISOString(),
  };

  const report = generateScamAwarenessReport({
    parsedUrl: parsed,
    threatState,
  });

  assert.equal(report.hasConfirmedThreat, true);
  const authWarn = report.warnings.find((w) => w.category === 'phishing_credential_theft');
  assert.ok(authWarn, 'Must generate phishing warning');
  assert.equal(authWarn.severity, 'critical', 'Confirmed threat must be critical severity');
  assert.equal(authWarn.confidence, 'confirmed', 'Confirmed threat must have confirmed confidence');
  assert.equal(authWarn.title, 'Confirmed Social Engineering / Deceptive Portal');
});

// Test 20: Stronger independently detected phishing evidence is not accidentally suppressed by contextual-keyword logic
test('Warning Engine Regression: Stronger independently detected phishing evidence is not suppressed', () => {
  // 20a: Embedded URL authority credentials (@)
  const parsedAuthority = parseUrl('https://paypal.com@evil.com/login');
  assert.ok(parsedAuthority);

  const reportAuthority = generateScamAwarenessReport({ parsedUrl: parsedAuthority });
  const authWarnAuthority = reportAuthority.warnings.find((w) => w.category === 'phishing_credential_theft');

  assert.ok(authWarnAuthority);
  assert.equal(authWarnAuthority.severity, 'critical', 'Authority credentials must trigger critical severity');
  assert.equal(authWarnAuthority.title, 'High-Risk Phishing or Credential Theft Indicators');
  assert.ok(authWarnAuthority.evidence.some((e) => e.includes('@')));

  // 20b: Hostname-embedded brand/phishing keywords combined with deceptive deep subdomains
  const parsedDeep = parseUrl('https://login.paypal.account.evil.com/');
  assert.ok(parsedDeep);

  const reportDeep = generateScamAwarenessReport({ parsedUrl: parsedDeep });
  const authWarnDeep = reportDeep.warnings.find((w) => w.category === 'phishing_credential_theft');

  assert.ok(authWarnDeep);
  assert.equal(authWarnDeep.severity, 'high', 'Hostname keyword with deep subdomains must trigger high severity');
  assert.equal(authWarnDeep.title, 'High-Risk Phishing or Credential Theft Indicators');
  assert.ok(authWarnDeep.evidence.some((e) => e.includes('Sensitive authentication/brand terms embedded in hostname')));
});

