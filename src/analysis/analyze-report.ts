import type {
  ApiCall,
  ContentScanPayload,
  Finding,
  LibraryHit,
  SecretFinding,
  SecurityReport,
  Severity,
} from '../shared/types';
import { analyzeSecurityHeaders } from './headers';
import { analyzeDocumentCookie, analyzeSetCookieHeaders } from './cookies';
import { detectTechnologies, techFindings } from './tech';
import { analyzeLibraries, type VulnerabilityDatabase } from './libs';
import { analyzeApis, analyzeForms, scanInlineSecrets } from './surface';
import { buildRecommendations } from './recommendations';
import { attachScores } from './scoring';

function pickHeaders(tabId: number, pageUrl: string, stored?: { url: string; headers: Record<string, string> }): Record<string, string> {
  if (!stored) return {};
  try {
    const a = new URL(pageUrl).host;
    const b = new URL(stored.url).host;
    if (a === b) return stored.headers;
  } catch {
    /* ignore */
  }
  return {};
}

function libraryFindings(libs: LibraryHit[]): Finding[] {
  return libs
    .filter((l) => l.risk && l.risk !== 'none')
    .map((l) => {
      const sev: Severity = l.risk === 'high' ? 'high' : l.risk === 'medium' ? 'medium' : 'low';
      return {
        id: `lib-${slug(l.name)}-${l.version ?? 'na'}-${l.risk}`,
        category: 'Libraries',
        severity: sev,
        title: `${l.name} matches a known risky or end-of-life baseline`,
        whatItMeans:
          'The detected version (or unknown version with known-vulnerable line) falls below a locally defined safe baseline in the bundled dataset.',
        whyItMatters: 'Older client libraries ship with memory of past CVE classes even if your exact bug is not triggered.',
        risks: 'Cross-site scripting, prototype pollution, or denial-of-service chains that vendors already patched.',
        recommendation: 'Upgrade to a supported release, verify with your package lockfile, and retest UI behavior.',
        evidence: `${l.evidence}${l.cveRefs?.length ? ` — refs: ${l.cveRefs.join(', ')}` : ''}`,
      } satisfies Finding;
    });
}

function secretFindings(findings: SecretFinding[]): Finding[] {
  return findings.map((s) => ({
    id: `secret-${slug(s.kind)}-${slug(s.snippet)}`,
    category: 'Frontend risks',
    severity: s.severity,
    title: `Possible ${s.kind} in page-visible script`,
    whatItMeans:
      'A static pattern resembling an API key or cloud credential appeared inside HTML or inline JavaScript visible to the browser.',
    whyItMatters: 'Secrets in frontend code can be extracted by anyone who can load the page source.',
    risks: 'Financial abuse, data exfiltration, or quota exhaustion on cloud accounts tied to the key.',
    recommendation: 'Rotate the credential immediately, move secrets to server-side configuration, and block keys in client bundles.',
    evidence: s.snippet,
  }));
}

function httpsFinding(isHttps: boolean): Finding[] {
  if (isHttps) return [];
  return [
    {
      id: 'https-missing',
      category: 'HTTPS security',
      severity: 'critical',
      title: 'Page is not served over HTTPS',
      whatItMeans: 'The connection between the browser and this host is not protected by TLS in the address you loaded.',
      whyItMatters: 'Network attackers can read or modify everything, including cookies and passwords.',
      risks: 'Account takeover, content injection, and loss of confidentiality.',
      recommendation: 'Enable HTTPS on the origin, redirect HTTP to HTTPS, and add HSTS once certificates are stable.',
    },
  ];
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 48);
}

export async function buildSecurityReport(input: {
  tabId: number;
  payload: ContentScanPayload;
  mainHeaders?: { url: string; headers: Record<string, string> };
  setCookieLines: string[];
  apiCalls: ApiCall[];
  vulnDb: VulnerabilityDatabase;
}): Promise<SecurityReport> {
  const { tabId, payload, mainHeaders, setCookieLines, apiCalls, vulnDb } = input;
  const headers = pickHeaders(tabId, payload.url, mainHeaders);

  const findings: Finding[] = [];
  findings.push(...httpsFinding(payload.isHttps));
  findings.push(...analyzeSecurityHeaders(headers));
  const cookieRows = analyzeSetCookieHeaders(setCookieLines);
  findings.push(...cookieRows.findings);
  findings.push(...analyzeDocumentCookie(payload.documentCookie, payload.isHttps));

  const technologies = detectTechnologies(
    payload.htmlSample,
    payload.scriptSrcs,
    payload.meta,
    payload.linkHints,
    payload.globals,
  );
  findings.push(...techFindings(technologies));

  const libraries = analyzeLibraries(payload.scriptSrcs, payload.globals, vulnDb);
  findings.push(...libraryFindings(libraries));

  findings.push(...analyzeForms(payload.forms, payload.isHttps));

  const mergedApis = [...apiCalls, ...payload.apisFromPage].slice(-250);
  findings.push(...analyzeApis(mergedApis));

  const secrets = scanInlineSecrets(payload.inlineScriptDigest);
  findings.push(...secretFindings(secrets));

  const dedup = new Map<string, Finding>();
  for (const f of findings) {
    if (!dedup.has(f.id)) dedup.set(f.id, f);
  }
  const uniqueFindings = [...dedup.values()];

  const recommendations = buildRecommendations(uniqueFindings);

  const base: SecurityReport = {
    tabId,
    url: payload.url,
    host: safeHost(payload.url),
    isHttps: payload.isHttps,
    generatedAt: Date.now(),
    grade: 'B',
    score: 0,
    maxScore: 100,
    breakdown: {
      headers: 0,
      cookies: 0,
      frontend: 0,
      libraries: 0,
      https: 0,
    },
    technologies,
    findings: uniqueFindings,
    cookies: cookieRows.rows,
    libraries,
    forms: payload.forms,
    apis: mergedApis,
    secrets,
    recommendations,
  };

  return attachScores(base);
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
