import type { ApiCall, Finding, FormSummary, SecretFinding } from '../shared/types';

const SENSITIVE_PATH = /(\/admin|\/wp-admin|\/phpmyadmin|\/graphql|\/api\/v\d|\/internal|\/debug|\/actuator)/i;

export function analyzeForms(forms: FormSummary[], isHttps: boolean): Finding[] {
  const findings: Finding[] = [];
  for (const f of forms) {
    if (f.hasPassword && !isHttps) {
      findings.push({
        id: `form-password-http-${f.index}`,
        category: 'Forms',
        severity: 'critical',
        title: 'Password field on a non-HTTPS page',
        whatItMeans: 'The browser can submit secrets over an unencrypted connection.',
        whyItMatters: 'Anyone on the same network can read the password in transit.',
        risks: 'Account takeover and credential theft.',
        recommendation: 'Serve the entire login flow on HTTPS with HSTS; reject password submissions on http://.',
        evidence: `Form #${f.index}`,
      });
    }
    if (f.hiddenFieldCount > 12) {
      findings.push({
        id: `form-many-hidden-${f.index}`,
        category: 'Forms',
        severity: 'info',
        title: 'Form contains many hidden fields',
        whatItMeans: 'Hidden inputs often carry anti-CSRF tokens, but large counts can hide malicious fields.',
        whyItMatters: 'Automated tampering checks are harder when the shape of the form is complex.',
        risks: 'Low direct risk; worth reviewing for unexpected fields after template changes.',
        recommendation: 'Review hidden inputs server-side and keep forms minimal.',
        evidence: `Form #${f.index} hidden count ${f.hiddenFieldCount}`,
      });
    }
  }
  return findings;
}

export function analyzeApis(calls: ApiCall[]): Finding[] {
  const findings: Finding[] = [];
  const urls = [...new Set(calls.map((c) => c.url))];
  for (const url of urls) {
    if (SENSITIVE_PATH.test(url)) {
      findings.push({
        id: `api-sensitive-${hash(url)}`,
        category: 'APIs',
        severity: 'low',
        title: 'Potentially sensitive endpoint observed',
        whatItMeans: 'The page triggered a request whose path resembles admin, GraphQL, or internal tooling.',
        whyItMatters: 'Such endpoints are valuable targets and should not be broadly exposed.',
        risks: 'Information disclosure or abuse if authorization is misconfigured.',
        recommendation: 'Verify authentication, authorization, and rate limits; avoid exposing admin APIs to anonymous sessions.',
        evidence: url,
      });
    }
    if (/firebaseio\.com|googleapis\.com\/v1\/projects/i.test(url)) {
      findings.push({
        id: `api-cloud-${hash(url)}`,
        category: 'APIs',
        severity: 'info',
        title: 'Cloud vendor API traffic detected',
        whatItMeans: 'The application talks to hosted vendor endpoints visible to the browser.',
        whyItMatters: 'Misconfigured client rules can leak more data than intended.',
        risks: 'Data exfiltration if API keys or tokens are mishandled.',
        recommendation: 'Use least-privilege API keys, rotate regularly, and never ship service-role secrets to browsers.',
        evidence: url,
      });
    }
  }
  return findings;
}

function hash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

const PATTERNS: { kind: string; re: RegExp; severity: SecretFinding['severity'] }[] = [
  { kind: 'Google API key', re: /AIza[0-9A-Za-z\-_]{20,}/, severity: 'high' },
  { kind: 'Firebase-like config', re: /apiKey\s*:\s*["'][^"']{10,}["']/, severity: 'medium' },
  { kind: 'AWS access key id', re: /AKIA[0-9A-Z]{16}/, severity: 'high' },
  { kind: 'Slack token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/, severity: 'high' },
];

export function scanInlineSecrets(inlineDigest: string): SecretFinding[] {
  const out: SecretFinding[] = [];
  const sample = inlineDigest.slice(0, 120_000);
  for (const p of PATTERNS) {
    const m = sample.match(p.re);
    if (m) {
      out.push({
        kind: p.kind,
        pattern: p.re.source,
        snippet: redact(m[0]),
        severity: p.severity,
      });
    }
  }
  return out;
}

function redact(s: string): string {
  if (s.length <= 16) return `${s.slice(0, 4)}…`;
  return `${s.slice(0, 6)}…${s.slice(-4)}`;
}
