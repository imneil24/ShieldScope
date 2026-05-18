import type { Finding, ScoreBreakdown, SecurityReport, Severity } from '../shared/types';

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 2,
  low: 5,
  medium: 10,
  high: 18,
  critical: 28,
};

export function scoreReport(findings: Finding[], ctx: { isHttps: boolean; libraryRisk: number }): { score: number; grade: string; breakdown: ScoreBreakdown } {
  const max = 100;
  let headers = 100;
  let cookies = 100;
  let frontend = 100;
  let libraries = 100 - Math.min(40, ctx.libraryRisk * 10);
  let https = ctx.isHttps ? 100 : 40;

  for (const f of findings) {
    const w = SEVERITY_WEIGHT[f.severity];
    if (f.category === 'Security headers') headers -= w * 0.35;
    if (f.category === 'Cookies') cookies -= w * 0.35;
    if (
      f.category === 'Forms' ||
      f.category === 'APIs' ||
      f.category === 'Technologies' ||
      f.category === 'Frontend risks'
    )
      frontend -= w * 0.25;
    if (f.category === 'Libraries') libraries -= w * 0.4;
  }

  headers = clamp(headers);
  cookies = clamp(cookies);
  frontend = clamp(frontend);
  libraries = clamp(libraries);
  https = clamp(https);

  const weighted =
    headers * 0.28 + cookies * 0.18 + frontend * 0.2 + libraries * 0.22 + https * 0.12;
  const score = clamp(Math.round(weighted));
  return {
    score,
    grade: toGrade(score),
    breakdown: { headers, cookies, frontend, libraries, https },
  };
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function toGrade(score: number): string {
  if (score >= 92) return 'A';
  if (score >= 85) return 'B';
  if (score >= 72) return 'C';
  if (score >= 58) return 'D';
  return 'F';
}

export function attachScores(report: SecurityReport): SecurityReport {
  const libPenalty = report.libraries.filter((l) => l.risk === 'high').length * 3 + report.libraries.filter((l) => l.risk === 'medium').length * 2;
  const { score, grade, breakdown } = scoreReport(report.findings, {
    isHttps: report.isHttps,
    libraryRisk: libPenalty,
  });
  return { ...report, score, grade, maxScore: 100, breakdown };
}
