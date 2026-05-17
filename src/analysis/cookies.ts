import type { CookieAnalysisRow, Finding } from '../shared/types';

function splitSetCookieLines(lines: string[]): string[] {
  const out: string[] = [];
  for (const line of lines) {
    if (!line) continue;
    out.push(line);
  }
  return out;
}

function parseSetCookieHeader(line: string): CookieAnalysisRow {
  const parts = line.split(';').map((p) => p.trim());
  const [first] = parts;
  const name = first.includes('=') ? first.split('=')[0].trim() : first;
  const lower = parts.map((p) => p.toLowerCase());
  const secure = lower.some((p) => p === 'secure');
  const httpOnly = lower.some((p) => p === 'httponly');
  let sameSite: string | undefined;
  for (const p of parts) {
    const pl = p.toLowerCase();
    if (pl.startsWith('samesite=')) {
      sameSite = p.split('=')[1]?.trim();
    }
  }
  const issues: string[] = [];
  if (!secure) issues.push('Missing Secure flag');
  if (!httpOnly) issues.push('Missing HttpOnly flag');
  if (!sameSite) issues.push('SameSite not set');
  else if (sameSite.toLowerCase() === 'none' && !secure) {
    issues.push('SameSite=None without Secure is invalid in modern browsers');
  } else if (sameSite.toLowerCase() === 'lax' || sameSite.toLowerCase() === 'strict') {
    /* ok */
  }
  const looksSession = /sess|auth|token|jwt|sid|phpsess|asp\.net_session|csrf/i.test(name);
  if (looksSession && (!httpOnly || !secure || !sameSite)) {
    issues.push('Session-like cookie lacks hardening flags');
  }
  return { name, secure, httpOnly, sameSite, raw: line, issues: [...new Set(issues)] };
}

export function analyzeSetCookieHeaders(setCookieLines: string[]): { rows: CookieAnalysisRow[]; findings: Finding[] } {
  const rows = splitSetCookieLines(setCookieLines).map(parseSetCookieHeader);
  const findings: Finding[] = [];

  for (const row of rows) {
    if (row.issues.length === 0) continue;
    const sev =
      /sess|auth|token|jwt|sid/i.test(row.name) && (!row.httpOnly || !row.secure) ? 'high' : row.issues.length > 2 ? 'medium' : 'low';
    findings.push({
      id: `cookie-${row.name}-${row.issues.join('-')}`.replace(/\s+/g, '-').slice(0, 120),
      category: 'Cookies',
      severity: sev as Finding['severity'],
      title: `Cookie “${row.name}” has weak attributes`,
      whatItMeans:
        'This cookie was observed on an HTTP response without one or more security attributes that modern browsers understand.',
      whyItMatters:
        'Cookies often carry session identifiers. Missing HttpOnly exposes them to JavaScript after XSS. Missing Secure allows cleartext transmission.',
      risks: 'Session theft, fixation, or replay become easier when cookies are readable by scripts or sent over HTTP.',
      recommendation:
        'Set Secure and HttpOnly on session cookies, choose SameSite=Lax or Strict unless you truly require None with Secure.',
      evidence: row.raw?.slice(0, 240),
    });
  }

  return { rows, findings };
}

export function analyzeDocumentCookie(documentCookie: string, isHttps: boolean): Finding[] {
  const findings: Finding[] = [];
  if (!documentCookie) return findings;
  if (!isHttps) {
    findings.push({
      id: 'cookie-non-httponly-visible-http',
      category: 'Cookies',
      severity: 'high',
      title: 'Non-HttpOnly cookies readable on HTTP',
      whatItMeans:
        'Any cookie visible to document.cookie can be read by scripts on the page. On HTTP, network attackers can also read traffic.',
      whyItMatters: 'Session identifiers should never ride on unencrypted connections.',
      risks: 'Credential theft via sniffing or malicious JavaScript.',
      recommendation: 'Redirect all traffic to HTTPS, set Secure cookies, and mark session identifiers HttpOnly.',
    });
  }
  return findings;
}
