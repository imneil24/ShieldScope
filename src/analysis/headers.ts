import type { Finding } from '../shared/types';

function normalizeName(n: string): string {
  return n.toLowerCase();
}

function parseHeaderMap(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[normalizeName(k)] = v;
  }
  return out;
}

function finding(f: Finding): Finding {
  return f;
}

export function analyzeSecurityHeaders(rawHeaders: Record<string, string>): Finding[] {
  const h = parseHeaderMap(rawHeaders);
  const findings: Finding[] = [];

  const csp = h['content-security-policy'] || h['content-security-policy-report-only'];
  if (!csp) {
    findings.push(
      finding({
        id: 'hdr-csp-missing',
        category: 'Security headers',
        severity: 'high',
        title: 'Content-Security-Policy (CSP) is missing',
        whatItMeans:
          'The site does not publish a Content-Security-Policy telling the browser which script and content sources are trusted.',
        whyItMatters:
          'Without CSP, successful injection of attacker-controlled markup or scripts faces fewer browser-enforced guardrails.',
        risks: 'Cross-site scripting can pivot to session theft, UI redressing, or wiring malicious behavior into trusted pages.',
        recommendation:
          'Start with a strict nonce- or hash-based CSP for scripts, allowlist required origins only, and iterate using report-only mode first.',
      }),
    );
  } else {
    const lower = csp.toLowerCase();
    if (lower.includes("'unsafe-inline'") && !lower.includes("'sha256-") && !lower.includes('nonce-')) {
      findings.push(
        finding({
          id: 'hdr-csp-unsafe-inline',
          category: 'Security headers',
          severity: 'medium',
          title: 'CSP allows unsafe-inline scripts',
          whatItMeans: 'The policy permits inline JavaScript without tying it to a per-response nonce or hash.',
          whyItMatters: 'Many real-world XSS payloads rely on executing inline script; unsafe-inline weakens CSP protection.',
          risks: 'A single HTML injection may become executable JavaScript in the user browser.',
          recommendation: 'Remove unsafe-inline, use nonces for trusted inline snippets, and move logic to external files.',
          evidence: 'unsafe-inline present in CSP',
        }),
      );
    }
    if (lower.includes('https:') === false && lower.includes('http:') && !lower.includes('upgrade-insecure-requests')) {
      findings.push(
        finding({
          id: 'hdr-csp-mixed-http',
          category: 'Security headers',
          severity: 'low',
          title: 'CSP references http: sources without upgrade-insecure-requests',
          whatItMeans: 'The policy may allow mixed or legacy HTTP behaviors.',
          whyItMatters: 'Active network attackers can tamper with or substitute insecure subresources.',
          risks: 'Downgrade and mixed-content attacks become easier to chain.',
          recommendation: 'Prefer https: scheme sources, use upgrade-insecure-requests, and enforce HTTPS at the edge.',
        }),
      );
    }
    if (lower.includes('*') && lower.includes('script-src')) {
      findings.push(
        finding({
          id: 'hdr-csp-wildcard',
          category: 'Security headers',
          severity: 'medium',
          title: 'CSP may include overly broad wildcards',
          whatItMeans: 'Wildcard host sources widen the set of servers that may execute as script origins.',
          whyItMatters: 'If any subdomain or shared host is compromised, CSP may still trust it.',
          risks: 'Supply-chain or DNS takeover incidents can silently expand trusted execution surface.',
          recommendation: 'Replace wildcards with explicit hostnames and tight path constraints where possible.',
        }),
      );
    }
  }

  const hsts = h['strict-transport-security'];
  if (!hsts) {
    findings.push(
      finding({
        id: 'hdr-hsts-missing',
        category: 'Security headers',
        severity: 'medium',
        title: 'Strict-Transport-Security (HSTS) is missing',
        whatItMeans: 'Browsers are not instructed to remember that this hostname must use HTTPS.',
        whyItMatters: 'Users can be tricked into visiting http:// variants on hostile networks.',
        risks: 'SSL stripping and cookie leakage over cleartext HTTP become more practical.',
        recommendation: 'Send HSTS with a long max-age, includeSubDomains when safe, and preload only after careful review.',
      }),
    );
  } else if (!hsts.toLowerCase().includes('max-age=') || hsts.match(/max-age=\s*0\b/i)) {
    findings.push(
      finding({
        id: 'hdr-hsts-weak',
        category: 'Security headers',
        severity: 'low',
        title: 'HSTS present but weak or disabled',
        whatItMeans: 'The HSTS header exists but may not enforce a meaningful retention window.',
        whyItMatters: 'Short or zero max-age provides little protection against downgrade attempts.',
        risks: 'Users quickly forget the HTTPS-only rule across sessions.',
        recommendation: 'Use max-age of at least six months in production, then consider preload with includeSubDomains.',
        evidence: hsts,
      }),
    );
  }

  const xfo = h['x-frame-options'];
  const frameAncestors = csp?.toLowerCase().includes('frame-ancestors');
  if (!xfo && !frameAncestors) {
    findings.push(
      finding({
        id: 'hdr-xfo-missing',
        category: 'Security headers',
        severity: 'medium',
        title: 'Clickjacking protections are missing',
        whatItMeans: 'Neither X-Frame-Options nor CSP frame-ancestors restricts who may embed this site in a frame.',
        whyItMatters: 'Attackers can hide your UI inside theirs to manipulate user clicks.',
        risks: 'Sensitive actions performed while the user thinks they interact with another site.',
        recommendation: 'Set frame-ancestors \'none\' or an explicit allowlist, or use DENY/SAMEORIGIN with X-Frame-Options as a fallback.',
      }),
    );
  } else if (xfo && xfo.toLowerCase() === 'allow-from') {
    findings.push(
      finding({
        id: 'hdr-xfo-legacy',
        category: 'Security headers',
        severity: 'low',
        title: 'Legacy X-Frame-Options value',
        whatItMeans: 'ALLOW-FROM is obsolete and inconsistently supported.',
        whyItMatters: 'Browsers may ignore the directive, leaving framing policy unclear.',
        risks: 'False sense of protection while framing remains possible.',
        recommendation: 'Move framing policy to CSP frame-ancestors with explicit origins.',
        evidence: xfo,
      }),
    );
  }

  const xcto = h['x-content-type-options'];
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    findings.push(
      finding({
        id: 'hdr-xcto-missing',
        category: 'Security headers',
        severity: 'low',
        title: 'X-Content-Type-Options: nosniff is missing',
        whatItMeans: 'Browsers may try to guess MIME types for downloaded or referenced content.',
        whyItMatters: 'MIME confusion can turn uploaded “images” into executable contexts in older browsers.',
        risks: 'Unexpected script execution from mislabeled responses on shared domains.',
        recommendation: 'Send X-Content-Type-Options: nosniff on HTML and static asset responses.',
      }),
    );
  }

  const rp = h['referrer-policy'];
  if (!rp) {
    findings.push(
      finding({
        id: 'hdr-referrer-missing',
        category: 'Security headers',
        severity: 'info',
        title: 'Referrer-Policy is not set',
        whatItMeans: 'The browser falls back to default referrer behavior, which may leak full URLs to third parties.',
        whyItMatters: 'URLs often contain tokens, emails, or internal paths in query strings.',
        risks: 'Accidental credential or PII leakage via Referer headers on outbound links.',
        recommendation: 'Use strict-origin-when-cross-origin or no-referrer-when-downgrade as a sensible default.',
      }),
    );
  }

  const pp = h['permissions-policy'] || h['feature-policy'];
  if (!pp) {
    findings.push(
      finding({
        id: 'hdr-permissions-policy-missing',
        category: 'Security headers',
        severity: 'info',
        title: 'Permissions-Policy (Feature-Policy) is missing',
        whatItMeans: 'Powerful browser features are not centrally restricted at the HTTP layer.',
        whyItMatters: 'If a script flaw appears, attackers can reach cameras, geolocation, or payment APIs more easily.',
        risks: 'Expanded blast radius for XSS or compromised third-party scripts.',
        recommendation: 'Deny-by-default sensitive features and allow only what the product truly needs.',
      }),
    );
  }

  const acao = h['access-control-allow-origin'];
  if (acao === '*') {
    findings.push(
      finding({
        id: 'hdr-acao-wildcard',
        category: 'Security headers',
        severity: 'low',
        title: 'Access-Control-Allow-Origin is *',
        whatItMeans: 'Responses announce that any origin may read the response in CORS-aware JavaScript.',
        whyItMatters: 'This is appropriate for fully public APIs but risky when responses include personalized data.',
        risks: 'Any website a victim visits may pull those responses into attacker-controlled JavaScript.',
        recommendation: 'Prefer explicit origins, vary by environment, and pair with credentials rules carefully.',
        evidence: acao,
      }),
    );
  }

  return findings;
}
