export type ChainInspectionStatus =
  | 'COMPLETED'
  | 'MAX_HOPS_EXCEEDED'
  | 'REDIRECT_LOOP'
  | 'BLOCKED_SPECIAL_USE_IP'
  | 'UNSUPPORTED_PROTOCOL'
  | 'TIMEOUT'
  | 'NETWORK_ERROR';

export type ChainFindingSeverity = 'info' | 'warning' | 'critical';

export interface ChainFinding {
  id: string;
  severity: ChainFindingSeverity;
  title: string;
  description: string;
}

export interface RedirectHop {
  hopIndex: number;
  url: string;
  statusCode: number;
  statusText: string;
  locationHeader: string | null;
  resolvedIp: string | null;
  isHttps: boolean;
  serverHeader: string | null;
  durationMs: number;
}

export interface RedirectChainResult {
  initialUrl: string;
  finalDestination: string;
  totalRedirects: number;
  status: ChainInspectionStatus;
  statusMessage: string;
  hops: RedirectHop[];
  findings: ChainFinding[];
  inspectedAt: string;
}

export interface RedirectClientState {
  status: 'idle' | 'checking' | 'completed' | 'unavailable' | 'error';
  data: RedirectChainResult | null;
  errorMessage?: string;
}
