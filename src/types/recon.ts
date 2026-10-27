export type DnsResolutionStatus =
  | 'resolved'
  | 'nxdomain'
  | 'nodata'
  | 'timeout'
  | 'error'
  | 'skipped';

export type RdapStatus =
  | 'available'
  | 'redacted'
  | 'unsupported'
  | 'timeout'
  | 'error'
  | 'skipped';

export type ReconFindingSeverity = 'info' | 'neutral' | 'warning';

export interface ReconFinding {
  id: string;
  category: 'dns' | 'domain_age' | 'infrastructure' | 'notice';
  severity: ReconFindingSeverity;
  title: string;
  explanation: string;
}

export interface DnsRecordsData {
  status: DnsResolutionStatus;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: Array<{ exchange: string; priority: number }>;
  aCount: number;
  aaaaCount: number;
  mxCount: number;
  hasMailExchange: boolean;
  message?: string;
}

export interface RdapRegistrationData {
  status: RdapStatus;
  registrationDate?: string;
  expirationDate?: string;
  domainAgeDays?: number;
  registrar?: string;
  message?: string;
}

export interface ReconResult {
  hostname: string;
  isIpAddress: boolean;
  isSpecialUse: boolean;
  dns: DnsRecordsData;
  rdap: RdapRegistrationData;
  findings: ReconFinding[];
  evaluatedAt: string;
  error?: string;
}

export type ReconClientStatus = 'idle' | 'checking' | 'completed' | 'error';

export interface ReconClientState {
  status: ReconClientStatus;
  data: ReconResult | null;
  errorMessage?: string;
}
