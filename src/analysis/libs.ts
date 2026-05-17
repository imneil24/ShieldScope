import type { LibraryHit } from '../shared/types';

export type VulnerabilityDatabase = Record<
  string,
  {
    name: string;
    rules: { safeAtOrAbove: string; severity: 'low' | 'medium' | 'high'; cves: string[]; note: string }[];
  }
>;

const SEMVER = /^(\d+)\.(\d+)(?:\.(\d+))?/;

function parseParts(v?: string): [number, number, number] | null {
  if (!v) return null;
  const m = v.match(SEMVER);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)];
}

/** true if a < b in semver terms (missing patch treated as 0). */
function ltSemver(a: string, b: string): boolean {
  const A = parseParts(a);
  const B = parseParts(b);
  if (!A || !B) return false;
  for (let i = 0; i < 3; i++) {
    if (A[i] !== B[i]) return A[i] < B[i];
  }
  return false;
}

function rank(s: LibraryHit['risk']): number {
  return s === 'high' ? 3 : s === 'medium' ? 2 : s === 'low' ? 1 : 0;
}

function worse(a: LibraryHit['risk'], b: LibraryHit['risk']): LibraryHit['risk'] {
  return rank(a) >= rank(b) ? a : b;
}

function extractVersionFromUrl(url: string, marker: RegExp): string | undefined {
  const m = url.match(marker);
  return m?.[1];
}

export function analyzeLibraries(
  scriptSrcs: string[],
  globals: Record<string, unknown>,
  db: VulnerabilityDatabase,
): LibraryHit[] {
  const hits: LibraryHit[] = [];

  const jqFromGlobal = typeof globals.jQuery === 'string' ? (globals.jQuery as string) : undefined;
  const jqUrl = scriptSrcs.map((u) => extractVersionFromUrl(u, /jquery[.-](\d+\.\d+\.\d+)/i)).find(Boolean);
  const jq = jqFromGlobal || jqUrl;
  if (jq || scriptSrcs.some((u) => u.toLowerCase().includes('jquery'))) {
    hits.push(evaluate('jquery', db, 'jQuery', jq, jq ? `version ${jq}` : 'detected without explicit version'));
  }

  const bs = extractVersionFromUrl(scriptSrcs.find((u) => /bootstrap/i.test(u)) || '', /bootstrap[/.-](\d+\.\d+\.\d+)/i);
  if (bs || scriptSrcs.some((u) => u.toLowerCase().includes('bootstrap'))) {
    hits.push(evaluate('bootstrap', db, 'Bootstrap', bs, bs ? `version ${bs}` : 'detected without explicit version'));
  }

  if (scriptSrcs.some((u) => /angular(\.min)?\.js$/i.test(u) || u.includes('angular.js'))) {
    const v = extractVersionFromUrl(scriptSrcs.find((u) => u.includes('angular')) || '', /angular[.-](\d+\.\d+\.\d+)/i);
    hits.push(evaluate('angularjs', db, 'AngularJS', v, v ? `version ${v}` : 'angular.js bundle'));
  }

  const vue = extractVersionFromUrl(scriptSrcs.find((u) => u.includes('vue')) || '', /vue[.-](\d+\.\d+\.\d+)/i);
  if (vue || scriptSrcs.some((u) => u.toLowerCase().includes('vue.'))) {
    hits.push(evaluate('vue', db, 'Vue', vue, vue ? `version ${vue}` : 'detected without explicit version'));
  }

  const react = extractVersionFromUrl(
    scriptSrcs.find((u) => /react(\.min)?\.js$/i.test(u) || u.includes('react.')) || '',
    /react[.-](\d+\.\d+\.\d+)/i,
  );
  if (react || scriptSrcs.some((u) => u.toLowerCase().includes('react'))) {
    hits.push(evaluate('react', db, 'React', react, react ? `version ${react}` : 'detected without explicit version'));
  }

  return hits;
}

function evaluate(
  key: string,
  db: VulnerabilityDatabase,
  label: string,
  version: string | undefined,
  evidence: string,
): LibraryHit {
  const entry = db[key];
  if (!entry) {
    return { name: label, version, evidence, risk: 'none' };
  }

  if (key === 'angularjs') {
    return {
      name: label,
      version,
      evidence,
      risk: 'high',
      cveRefs: ['EOL'],
      note: entry.rules[0]?.note ?? 'AngularJS is end-of-life; migrate to a supported framework.',
    };
  }

  if (!version) {
    return {
      name: label,
      version,
      evidence,
      risk: 'low',
      note: 'Version unknown; verify with your bundle lockfile and vendor advisories.',
    };
  }

  let risk: LibraryHit['risk'] = 'none';
  const cves: string[] = [];
  let note = '';

  for (const rule of entry.rules) {
    if (ltSemver(version, rule.safeAtOrAbove)) {
      risk = worse(risk, rule.severity);
      cves.push(...rule.cves);
      note = rule.note;
    }
  }

  const uniqCves = [...new Set(cves)].filter(Boolean);
  return {
    name: label,
    version,
    evidence,
    risk,
    cveRefs: uniqCves.length ? uniqCves : undefined,
    note: note || undefined,
  };
}
