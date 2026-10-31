import { RiskLevel } from '../utils/riskEngine';

export type WarningCategory =
  | 'known_threat'
  | 'phishing_credential_theft'
  | 'suspicious_redirect'
  | 'new_domain'
  | 'suspicious_url_structure'
  | 'inconclusive_check'
  | 'no_obvious_threat';

export type WarningSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingConfidence = 'confirmed' | 'suspicious' | 'inconclusive' | 'informational';

export interface ScamAwarenessWarning {
  id: string;
  category: WarningCategory;
  severity: WarningSeverity;
  confidence: FindingConfidence;
  title: string;
  evidence: string[];
  explanation: string;
  potentialScamScenario?: string;
  recommendedAction: string;
}

export interface ScamAwarenessReport {
  overallRiskLevel: RiskLevel;
  riskScore: number;
  warnings: ScamAwarenessWarning[];
  hasConfirmedThreat: boolean;
  hasUnavailableChecks: boolean;
  summaryGuidance: string;
  disclaimer: string;
}
