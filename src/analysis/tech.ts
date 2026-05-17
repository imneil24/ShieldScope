import type { Finding, TechHit } from '../shared/types';

const META_GENERATOR = /name=["']generator["']\s+content=["']([^"']+)["']/i;

function firstMatch(html: string, re: RegExp): string | undefined {
  const m = html.match(re);
  return m?.[1]?.trim();
}

export function detectTechnologies(
  html: string,
  scriptSrcs: string[],
  meta: Record<string, string>,
  linkHints: string[],
  globals: Record<string, unknown>,
): TechHit[] {
  const hits: TechHit[] = [];
  const lowerHtml = html.slice(0, 250_000).toLowerCase();
  const scripts = scriptSrcs.map((s) => s.toLowerCase());
  const links = linkHints.map((s) => s.toLowerCase());

  const add = (t: TechHit) => hits.push(t);

  const gen = meta.generator || firstMatch(html, META_GENERATOR);
  if (gen) {
    const g = gen.toLowerCase();
    if (g.includes('wordpress')) {
      const ver = g.match(/wordpress\s*([\d.]+)/)?.[1];
      add({ name: 'WordPress', confidence: 'high', version: ver, evidence: `generator meta: ${gen}` });
    }
    if (g.includes('umbraco')) {
      const ver = g.match(/umbraco\s*([\d.]+)/)?.[1];
      add({ name: 'Umbraco', confidence: 'high', version: ver, evidence: `generator meta: ${gen}` });
    }
    if (g.includes('kentico')) {
      add({ name: 'Kentico', confidence: 'high', evidence: `generator meta: ${gen}` });
    }
  }

  if (scripts.some((u) => u.includes('wp-content') || u.includes('wp-includes'))) {
    add({ name: 'WordPress', confidence: 'high', evidence: 'Script paths reference wp-content or wp-includes' });
  }
  if (scripts.some((u) => u.includes('shopifycdn') || u.includes('shopify.com'))) {
    add({ name: 'Shopify', confidence: 'high', evidence: 'Script host matches Shopify CDN patterns' });
  }
  if (typeof globals.Shopify !== 'undefined' || scripts.some((u) => u.includes('shopify'))) {
    add({ name: 'Shopify', confidence: 'medium', evidence: 'Global Shopify object or Shopify scripts detected' });
  }
  if (scripts.some((u) => u.includes('magento') || u.includes('mage/') || lowerHtml.includes('magento'))) {
    add({ name: 'Magento', confidence: 'medium', evidence: 'Magento script paths or markers' });
  }
  if (scripts.some((u) => u.includes('/_next/static'))) {
    add({ name: 'Next.js', confidence: 'high', evidence: 'Next.js static chunk path /_next/static' });
  }
  if (typeof globals.__NEXT_DATA__ !== 'undefined' || lowerHtml.includes('__next_data__')) {
    add({ name: 'Next.js', confidence: 'high', evidence: '__NEXT_DATA__ bootstrap object present' });
  }
  if (typeof globals.React !== 'undefined' || scripts.some((u) => u.includes('react'))) {
    add({ name: 'React', confidence: 'medium', evidence: 'React global or react-related bundles' });
  }
  if (typeof globals.vue !== 'undefined' || scripts.some((u) => u.includes('vue.'))) {
    add({ name: 'Vue', confidence: 'medium', evidence: 'Vue global or vue bundle references' });
  }
  if (typeof globals.angular !== 'undefined' || meta['angular-version']) {
    add({
      name: 'Angular',
      confidence: 'high',
      version: meta['angular-version'],
      evidence: 'Angular global or angular-version meta',
    });
  }
  if (scripts.some((u) => u.includes('angular.js') || u.includes('angular.min.js'))) {
    add({ name: 'AngularJS', confidence: 'high', evidence: 'angular.js bundle detected (1.x line)' });
  }
  if (scripts.some((u) => u.includes('aspnetcdn') || u.includes('microsoft.com/ajax'))) {
    add({ name: 'ASP.NET', confidence: 'medium', evidence: 'Microsoft ASP.NET AJAX or CDN references' });
  }
  if (lowerHtml.includes('__viewstate') || lowerHtml.includes('aspnet') || scripts.some((u) => u.includes('webresource.axd'))) {
    add({ name: 'ASP.NET', confidence: 'low', evidence: 'Classic WebForms markers (ViewState or webresource.axd)' });
  }
  if (scripts.some((u) => u.includes('.php?') || u.endsWith('.php')) || lowerHtml.includes('php version')) {
    add({ name: 'PHP', confidence: 'low', evidence: 'PHP script endpoints or PHP markers in HTML' });
  }
  if (scripts.some((u) => u.includes('laravel') || links.some((l) => l.includes('laravel')))) {
    add({ name: 'Laravel', confidence: 'low', evidence: 'Laravel-related assets or routes hinted in links' });
  }
  if (typeof globals.jQuery !== 'undefined' || scripts.some((u) => u.includes('jquery'))) {
    const v = typeof globals.jQuery === 'string' ? (globals.jQuery as string) : undefined;
    add({ name: 'jQuery', confidence: scripts.some((u) => u.includes('jquery')) ? 'high' : 'medium', version: v, evidence: 'jQuery script or global' });
  }
  if (scripts.some((u) => u.includes('bootstrap')) || links.some((l) => l.includes('bootstrap'))) {
    add({ name: 'Bootstrap', confidence: 'medium', evidence: 'Bootstrap CSS/JS assets' });
  }

  const dedup = new Map<string, TechHit>();
  for (const h of hits) {
    const prev = dedup.get(h.name);
    if (!prev || (h.confidence === 'high' && prev.confidence !== 'high')) {
      dedup.set(h.name, h);
    }
  }
  return [...dedup.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function techFindings(technologies: TechHit[]): Finding[] {
  const out: Finding[] = [];
  if (technologies.some((t) => t.name === 'AngularJS')) {
    out.push({
      id: 'tech-angularjs-eol',
      category: 'Technologies',
      severity: 'high',
      title: 'AngularJS (1.x) detected',
      whatItMeans: 'This site still ships the legacy AngularJS framework, which no longer receives security fixes.',
      whyItMatters: 'Attackers actively scan for outdated JavaScript frameworks because known weaknesses stay unpatched.',
      risks: 'Cross-site scripting and sandbox escapes that were fixed in modern stacks may still be exploitable here.',
      recommendation: 'Migrate to Angular (2+) or another supported framework and remove AngularJS bundles from production.',
    });
  }
  return out;
}
