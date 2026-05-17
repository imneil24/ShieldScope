export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Confidence = 'low' | 'medium' | 'high';

export interface Finding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  whatItMeans: string;
  whyItMatters: string;
  risks: string;
  recommendation: string;
  evidence?: string;
}

export interface TechHit {
  name: string;
  confidence: Confidence;
  version?: string;
  evidence: string;
}

export interface CookieAnalysisRow {
  name: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: string;
  raw?: string;
  issues: string[];
}

export interface LibraryHit {
  name: string;
  version?: string;
  evidence: string;
  risk?: 'none' | 'low' | 'medium' | 'high';
  cveRefs?: string[];
  note?: string;
}

export interface FormSummary {
  index: number;
  method: string;
  action: string;
  hasPassword: boolean;
  hiddenFieldCount: number;
  issues: string[];
}

export interface ApiCall {
  url: string;
  method: string;
  type: string;
  timestamp: number;
}

export interface SecretFinding {
  kind: string;
  pattern: string;
  snippet: string;
  severity: Severity;
}

export interface ScoreBreakdown {
  headers: number;
  cookies: number;
  frontend: number;
  libraries: number;
  https: number;
}

export interface SecurityReport {
  tabId: number;
  url: string;
  host: string;
  isHttps: boolean;
  generatedAt: number;
  grade: string;
  score: number;
  maxScore: number;
  breakdown: ScoreBreakdown;
  technologies: TechHit[];
  findings: Finding[];
  cookies: CookieAnalysisRow[];
  libraries: LibraryHit[];
  forms: FormSummary[];
  apis: ApiCall[];
  secrets: SecretFinding[];
  recommendations: string[];
}

export interface MainWorldGlobals {
  [key: string]: boolean | string | undefined;
}

export interface ContentScanPayload {
  url: string;
  title: string;
  isHttps: boolean;
  documentCookie: string;
  htmlSample: string;
  scriptSrcs: string[];
  inlineScriptDigest: string;
  meta: Record<string, string>;
  linkHints: string[];
  globals: MainWorldGlobals;
  forms: FormSummary[];
  apisFromPage: ApiCall[];
}

export type MessageFromExtension =
  | { type: 'CONTENT_SCAN'; payload: ContentScanPayload }
  | { type: 'GET_REPORT'; tabId: number }
  | { type: 'CLEAR_TAB'; tabId: number }
  | { type: 'EXPORT_REPORT'; tabId: number }
  | { type: 'INJECT_EARLY' }
  | { type: 'API_HIT'; url?: string; method?: string; sourceType?: string }
  | { type: 'GLOBAL_HINTS'; payload: { jquery?: string; keys: Record<string, boolean> } };

export type MessageToContent = { type: 'PING' };
