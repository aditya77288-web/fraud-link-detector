import test from 'node:test';
import assert from 'node:assert/strict';
import { ThreatIntelligenceState } from '../types/threat.js';

test('Threat State: Clean state format requires exact non-guarantee phrasing', () => {
  const cleanState: ThreatIntelligenceState = {
    status: 'clean',
    message: 'No threat records found in Google Safe Browsing. This does not guarantee the URL is safe.',
    evaluatedAt: new Date().toISOString(),
  };

  assert.equal(cleanState.status, 'clean');
  assert.equal(
    cleanState.message,
    'No threat records found in Google Safe Browsing. This does not guarantee the URL is safe.'
  );
  assert.ok(!cleanState.message?.toLowerCase().includes('this site is safe'));
});

test('Threat State: Threat detected state carries threat types and category details', () => {
  const threatState: ThreatIntelligenceState = {
    status: 'threat_detected',
    threatTypes: ['SOCIAL_ENGINEERING', 'MALWARE'],
    cacheDuration: '300s',
    evaluatedAt: new Date().toISOString(),
  };

  assert.equal(threatState.status, 'threat_detected');
  assert.ok(threatState.threatTypes?.includes('SOCIAL_ENGINEERING'));
  assert.ok(threatState.threatTypes?.includes('MALWARE'));
});

test('Threat State: Unconfigured state clearly marks offline heuristic operation', () => {
  const unconfiguredState: ThreatIntelligenceState = {
    status: 'unconfigured',
    message: 'Threat intelligence is not configured on this server. Running offline structural heuristic mode only.',
  };

  assert.equal(unconfiguredState.status, 'unconfigured');
  assert.ok(unconfiguredState.message?.includes('not configured'));
  assert.ok(unconfiguredState.message?.includes('offline structural heuristic mode'));
});

test('Threat State: Unavailable state gracefully notes heuristic analysis remains active', () => {
  const unavailableState: ThreatIntelligenceState = {
    status: 'unavailable',
    message: 'Threat intelligence service is temporarily unavailable. Local heuristic analysis remains active.',
  };

  assert.equal(unavailableState.status, 'unavailable');
  assert.ok(unavailableState.message?.includes('temporarily unavailable'));
  assert.ok(unavailableState.message?.includes('Local heuristic analysis remains active'));
});

test('Threat State: Checking state represents pending asynchronous request', () => {
  const checkingState: ThreatIntelligenceState = {
    status: 'checking',
  };

  assert.equal(checkingState.status, 'checking');
});
