import type { Finding } from '../shared/types';

export function buildRecommendations(findings: Finding[]): string[] {
  const recs: string[] = [];
  const push = (s: string) => {
    if (!recs.includes(s)) recs.push(s);
  };

  const cats = new Set(findings.map((f) => f.id));

  if ([...cats].some((id) => id.startsWith('hdr-csp'))) {
    push(
      'Nginx sample: add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';" always;',
    );
    push(
      'Apache sample: Header set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'"',
    );
    push(
      'ASP.NET Core (Program.cs): app.Use(async (ctx, next) => { ctx.Response.Headers.Append("Content-Security-Policy", "default-src \'self\'"); await next(); });',
    );
  }
  if ([...cats].some((id) => id.startsWith('hdr-hsts'))) {
    push('Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;');
    push('Apache: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"');
    push('ASP.NET Core: ctx.Response.Headers.Append("Strict-Transport-Security", "max-age=31536000; includeSubDomains");');
  }
  if ([...cats].some((id) => id.startsWith('hdr-xfo'))) {
    push('Nginx: add_header X-Frame-Options "SAMEORIGIN" always; or prefer CSP frame-ancestors.');
    push('ASP.NET Core: ctx.Response.Headers.Append("X-Frame-Options", "DENY");');
  }
  if ([...cats].some((id) => id.startsWith('cookie-'))) {
    push(
      'Secure cookie example (Set-Cookie): session=abc; Path=/; HttpOnly; Secure; SameSite=Lax',
    );
  }
  if ([...cats].some((id) => id.startsWith('form-password-http'))) {
    push('Force HTTPS: redirect port 80 to 443 and enable HSTS after validating TLS everywhere.');
  }

  push('Review findings in each category; this tool performs passive inspection only and may miss issues visible only server-side.');

  return recs;
}
