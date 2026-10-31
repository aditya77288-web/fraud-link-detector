import test from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl } from './urlParser.js';
import { assessUrlRisk } from './riskEngine.js';

test('Target Test Case 1: http://192.0.2.1:8080/login', () => {
  const parsed = parseUrl('http://192.0.2.1:8080/login');
  assert.ok(parsed);
  assert.equal(parsed.hostname, '192.0.2.1');
  assert.equal(parsed.isIpAddress, true);
  assert.equal(parsed.explicitPort, '8080');
  assert.equal(parsed.isNonStandardPort, true);
  assert.equal(parsed.subdomainCount, 0); // IP addresses do not have subdomains

  const assessment = assessUrlRisk(parsed);
  assert.equal(assessment.isValid, true);
  
  const ruleNumbers = assessment.indicators.map((i) => i.ruleNumber).sort((a, b) => a - b);
  // Expected indicators:
  // Rule 1: HTTP instead of HTTPS (+15)
  // Rule 2: Direct IP address (+25)
  // Rule 7: Sensitive keyword in path 'login' (+20)
  // Rule 10: Non-standard port 8080 (+15)
  assert.deepEqual(ruleNumbers, [1, 2, 7, 10]);
  assert.equal(assessment.score, 75);
  assert.equal(assessment.level, 'High');

  // Verify non-standard port explanation
  const portIndicator = assessment.indicators.find((i) => i.ruleNumber === 10);
  assert.ok(portIndicator);
  assert.ok(portIndicator.explanation.includes('8080'));
  assert.ok(portIndicator.explanation.includes('HTTP (80)'));
  assert.ok(portIndicator.explanation.includes('HTTPS (443)'));
  assert.ok(portIndicator.explanation.includes('not proof of malicious activity'));

  // Verify sensitive path keyword explanation
  const keywordIndicator = assessment.indicators.find((i) => i.ruleNumber === 7);
  assert.ok(keywordIndicator);
  assert.ok(keywordIndicator.explanation.includes('not proof of phishing'));
});

test('Target Test Case 2: https://example.com@192.0.2.1/login', () => {
  const parsed = parseUrl('https://example.com@192.0.2.1/login');
  assert.ok(parsed);
  // Hostname must be 192.0.2.1, NOT example.com
  assert.equal(parsed.hostname, '192.0.2.1');
  assert.equal(parsed.username, 'example.com');
  assert.equal(parsed.hasAuthorityCredentials, true);
  assert.equal(parsed.isIpAddress, true);

  const assessment = assessUrlRisk(parsed);
  assert.equal(assessment.isValid, true);

  const ruleNumbers = assessment.indicators.map((i) => i.ruleNumber).sort((a, b) => a - b);
  // Expected indicators:
  // Rule 2: Direct IP address host (+25)
  // Rule 3: User credentials before @ in authority (+25)
  // Rule 7: Sensitive keyword 'login' in path (+20)
  assert.deepEqual(ruleNumbers, [2, 3, 7]);
  assert.equal(assessment.score, 70);
  assert.equal(assessment.level, 'High');

  // Verify explanation explains the true host is 192.0.2.1
  const authIndicator = assessment.indicators.find((i) => i.ruleNumber === 3);
  assert.ok(authIndicator);
  assert.ok(authIndicator.explanation.includes('192.0.2.1'));
});

test('Target Test Case 3: https://xn--e1afmkfd.example/login', () => {
  const parsed = parseUrl('https://xn--e1afmkfd.example/login');
  assert.ok(parsed);
  assert.equal(parsed.hostname, 'xn--e1afmkfd.example');
  assert.equal(parsed.hasPunycode, true);

  const assessment = assessUrlRisk(parsed);
  assert.equal(assessment.isValid, true);

  const ruleNumbers = assessment.indicators.map((i) => i.ruleNumber).sort((a, b) => a - b);
  // Expected indicators:
  // Rule 7: Sensitive keyword 'login' in path (+20)
  // Rule 9: Punycode label beginning with xn-- (+25)
  assert.deepEqual(ruleNumbers, [7, 9]);
  assert.equal(assessment.score, 45);
  assert.equal(assessment.level, 'Medium');

  // Verify explanation explains that Punycode is not proof of malicious activity by itself
  const punyIndicator = assessment.indicators.find((i) => i.ruleNumber === 9);
  assert.ok(punyIndicator);
  assert.ok(punyIndicator.explanation.includes('not proof of malicious activity by itself'));
});

test('Target Test Case 4: https://www.example.com/about-us', () => {
  const parsed = parseUrl('https://www.example.com/about-us');
  assert.ok(parsed);

  const assessment = assessUrlRisk(parsed);
  assert.equal(assessment.isValid, true);
  assert.equal(assessment.score, 0);
  assert.equal(assessment.level, 'Low');
  assert.equal(assessment.indicators.length, 0);
  assert.equal(assessment.summaryMessage, 'No obvious suspicious patterns detected');
});

test('Authority @ vs Path @: Does not flag @ character indiscriminately in path or query', () => {
  // @ in pathname should not trigger Rule 3
  const pathAt = parseUrl('https://medium.com/@techlead/story');
  assert.ok(pathAt);
  const pathAssessment = assessUrlRisk(pathAt);
  assert.equal(pathAssessment.indicators.some((i) => i.ruleNumber === 3), false);

  // @ in query string should not trigger Rule 3
  const queryAt = parseUrl('https://service.com/lookup?user=alice@company.com');
  assert.ok(queryAt);
  const queryAssessment = assessUrlRisk(queryAt);
  assert.equal(queryAssessment.indicators.some((i) => i.ruleNumber === 3), false);
});

test('Port Detection: Port 80 on HTTP and Port 443 on HTTPS are treated as usual defaults', () => {
  const http80 = parseUrl('http://example.com:80/about');
  assert.ok(http80);
  const assess80 = assessUrlRisk(http80);
  assert.equal(assess80.indicators.some((i) => i.ruleNumber === 10), false);

  const https443 = parseUrl('https://example.com:443/about');
  assert.ok(https443);
  const assess443 = assessUrlRisk(https443);
  assert.equal(assess443.indicators.some((i) => i.ruleNumber === 10), false);
});

test('Score Consistency: Clamped to 0-100 and categories match thresholds', () => {
  // Low: 0 - 29
  const low = assessUrlRisk(parseUrl('http://example.com/news'));
  assert.equal(low.score, 15);
  assert.equal(low.level, 'Low');

  // Medium: 30 - 59
  const med = assessUrlRisk(parseUrl('http://example.com/login'));
  assert.equal(med.score, 35);
  assert.equal(med.level, 'Medium');

  // High: 60 - 100 clamped
  const maxHigh = assessUrlRisk(
    parseUrl('http://admin:pass@192.0.2.1:9090/login/password/urgent/wallet/verify?token=123&dest=http://evil.com')
  );
  assert.equal(maxHigh.score, 100);
  assert.equal(maxHigh.level, 'High');

  // Ensure each rule ID appears at most once in indicators list
  const ruleIds = maxHigh.indicators.map((i) => i.id);
  const uniqueRuleIds = new Set(ruleIds);
  assert.equal(ruleIds.length, uniqueRuleIds.size);
});

test('Validation: Invalid URLs receive clear validation message, not misleading risk score', () => {
  const invalid = parseUrl('not a valid url format :::');
  assert.ok(invalid);
  assert.equal(invalid.isValid, false);

  const assessment = assessUrlRisk(invalid);
  assert.equal(assessment.isValid, false);
  assert.equal(assessment.score, 0);
  assert.equal(assessment.indicators.length, 0);
  assert.ok(assessment.summaryMessage.includes('Invalid URL format') || assessment.summaryMessage.includes('not a valid'));
});
