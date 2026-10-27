export type ThreatCheckStatus =
  | 'idle'
  | 'checking'
  | 'threat_detected'
  | 'clean'
  | 'unconfigured'
  | 'unavailable';

export interface ThreatIntelligenceState {
  status: ThreatCheckStatus;
  threatTypes?: string[];
  cacheDuration?: string;
  evaluatedAt?: string;
  message?: string;
}
