import type { Finding, SecurityReport, Severity } from '../shared/types';
import '../popup/popup.css';

export type ReportUiDeps = {
  /** Return the latest report snapshot for the inspected target. */
  refresh: () => Promise<SecurityReport | undefined>;
  /** Optional polling for DevTools live mode. */
  liveIntervalMs?: number;
};

export function mountReportUi(root: HTMLElement, deps: ReportUiDeps): void {
  const state = { tab: 'Overview', filter: 'all' as Severity | 'all' };
  let latest: SecurityReport | undefined;

  const el = <K extends keyof HTMLElementTagNameMap>(
    tag: K,
    props?: Partial<HTMLElementTagNameMap[K]> & { class?: string; html?: string },
    children: (HTMLElement | string)[] = [],
  ): HTMLElementTagNameMap[K] => {
    const node = document.createElement(tag);
    if (props) {
      const { class: cls, html, ...rest } = props;
      if (cls) node.className = cls;
      if (html) node.innerHTML = html;
      Object.assign(node, rest as object);
    }
    for (const c of children) {
      if (typeof c === 'string') node.appendChild(document.createTextNode(c));
      else node.appendChild(c);
    }
    return node;
  };

  const escapeHtml = (s: string): string =>
    s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');

  const severityClass = (s: string): string => {
    if (s === 'none') return 'badge info';
    return `badge ${s}`;
  };

  const bool = (v?: boolean): string => (v ? 'yes' : 'no');

  const renderTopbar = (
    onRefresh: () => void,
    onTheme: () => void,
    onExportJson: () => void,
    onExportHtml: () => void,
    onCopy: () => void,
  ) =>
    el('div', { class: 'topbar' }, [
      el('div', { class: 'brand' }, [
        el('strong', {}, ['AI Website Security Inspector']),
        el('span', {}, ['Passive, local-only analysis']),
      ]),
      el('div', { class: 'actions' }, [
        el('button', { class: 'primary', onclick: () => onRefresh() }, ['Rescan']),
        el('button', { class: 'ghost', onclick: () => onTheme() }, ['Theme']),
        el('button', { class: 'ghost', onclick: () => onExportJson() }, ['JSON']),
        el('button', { class: 'ghost', onclick: () => onExportHtml() }, ['HTML']),
        el('button', { class: 'ghost', onclick: () => onCopy() }, ['Copy tips']),
      ]),
    ]);

  const renderScore = (report: SecurityReport) => {
    const b = report.breakdown;
    const meter = (label: string, value: number) => {
      const fill = el('div');
      fill.style.width = `${value}%`;
      fill.style.height = '100%';
      fill.style.background = 'linear-gradient(90deg,#22d3ee,#6366f1)';
      fill.style.borderRadius = '999px';
      return el('div', { class: 'meter-row' }, [
        el('span', {}, [label]),
        el('div', { class: 'bar' }, [fill]),
        el('span', {}, [String(value)]),
      ]);
    };
    return el('div', { class: 'score-row' }, [
      el('div', { class: 'score-pill' }, [
        el('div', { class: 'grade' }, [report.grade]),
        el('div', { class: 'sub' }, [`Score ${report.score}/${report.maxScore}`]),
      ]),
      el('div', { class: 'meter' }, [
        meter('Headers', b.headers),
        meter('Cookies', b.cookies),
        meter('Frontend', b.frontend),
        meter('Libraries', b.libraries),
        meter('HTTPS', b.https),
      ]),
    ]);
  };

  const renderTabs = (active: string, onTab: (t: string) => void) => {
    const tabs = [
      'Overview',
      'Technologies',
      'Headers',
      'Cookies',
      'Libraries',
      'Forms',
      'APIs',
      'Recommendations',
    ];
    return el(
      'nav',
      { class: 'tabs' },
      tabs.map((t) =>
        el(
          'button',
          {
            class: t === active ? 'active' : '',
            onclick: () => onTab(t),
          },
          [t],
        ),
      ),
    );
  };

  const renderFinding = (f: Finding) => {
    const kids: (HTMLElement | string)[] = [
      el('summary', {}, [`${f.title} `, el('span', { class: severityClass(f.severity) }, [f.severity])]),
      el('div', { class: 'muted', html: `<p><strong>What it means:</strong> ${escapeHtml(f.whatItMeans)}</p>` }),
      el('div', { class: 'muted', html: `<p><strong>Why it matters:</strong> ${escapeHtml(f.whyItMatters)}</p>` }),
      el('div', { class: 'muted', html: `<p><strong>Risks:</strong> ${escapeHtml(f.risks)}</p>` }),
      el('div', { class: 'muted', html: `<p><strong>Fix:</strong> ${escapeHtml(f.recommendation)}</p>` }),
    ];
    if (f.evidence) {
      kids.push(el('div', { class: 'muted', html: `<p><strong>Evidence:</strong> <code>${escapeHtml(f.evidence)}</code></p>` }));
    }
    return el('details', { class: 'block' }, kids);
  };

  const toggleTheme = async () => {
    const cur = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
    const next = cur === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next === 'light' ? 'light' : 'dark';
    await chrome.storage.local.set({ theme: next });
  };

  const exportJson = async () => {
    if (!latest) return;
    const blob = new Blob([JSON.stringify(latest, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${latest.host}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportHtml = async () => {
    if (!latest) return;
    const body = `<pre style="font:12px/1.5 ui-monospace,monospace;white-space:pre-wrap">${escapeHtml(
      JSON.stringify(latest, null, 2),
    )}</pre>`;
    const blob = new Blob(
      [
        `<!doctype html><meta charset="utf-8"><title>Security report ${escapeHtml(latest.host)}</title>` +
          `<body style="background:#0b1220;color:#e5e7eb;padding:16px">${body}</body>`,
      ],
      { type: 'text/html' },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${latest.host}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyTips = async () => {
    if (!latest) return;
    await navigator.clipboard.writeText(latest.recommendations.join('\n\n'));
  };

  const paint = () => {
    root.innerHTML = '';
    root.appendChild(
      renderTopbar(
        () => void doRefresh(),
        () => void toggleTheme(),
        () => void exportJson(),
        () => void exportHtml(),
        () => void copyTips(),
      ),
    );

    if (!latest) {
      root.appendChild(
        el('div', { class: 'empty' }, [
          'Open a website tab, then press Rescan. This extension only inspects what the browser already sees—no remote APIs.',
        ]),
      );
      return;
    }

    root.appendChild(renderScore(latest));

    const filterSelect = el('select', { class: 'filter' }) as HTMLSelectElement;
    for (const opt of ['all', 'critical', 'high', 'medium', 'low', 'info'] as const) {
      const o = document.createElement('option');
      o.value = opt;
      o.textContent = opt === 'all' ? 'All severities' : opt;
      filterSelect.appendChild(o);
    }
    filterSelect.value = state.filter;
    filterSelect.onchange = () => {
      state.filter = filterSelect.value as Severity | 'all';
      paint();
    };
    root.appendChild(filterSelect);

    const onTab = (t: string) => {
      state.tab = t;
      paint();
    };
    root.appendChild(renderTabs(state.tab, onTab));

    const panel = el('section', { class: 'panel' });
    if (state.tab === 'Overview') {
      const cats = new Map<string, number>();
      for (const f of latest.findings) cats.set(f.category, (cats.get(f.category) ?? 0) + 1);
      panel.appendChild(el('div', { class: 'muted', html: `<p><strong>Host:</strong> ${escapeHtml(latest.host)}</p>` }));
      panel.appendChild(el('div', { class: 'muted', html: `<p><strong>URL:</strong> <code>${escapeHtml(latest.url)}</code></p>` }));
      panel.appendChild(el('h4', {}, ['Findings by category']));
      for (const [k, v] of [...cats.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
        panel.appendChild(el('div', { class: 'pill-row' }, [el('span', { class: 'pill' }, [`${k}: ${v}`])]));
      }
      const filtered =
        state.filter === 'all' ? latest.findings : latest.findings.filter((f) => f.severity === state.filter);
      panel.appendChild(el('h4', {}, ['Issues']));
      if (!filtered.length) panel.appendChild(el('div', { class: 'muted' }, ['No issues match this filter.']));
      for (const f of filtered.slice(0, 60)) panel.appendChild(renderFinding(f));
    }

    if (state.tab === 'Technologies') {
      if (!latest.technologies.length) panel.appendChild(el('div', { class: 'muted' }, ['No strong technology signals detected.']));
      for (const t of latest.technologies) {
        panel.appendChild(
          el('div', { class: 'card' }, [
            el('header', {}, [el('strong', {}, [t.name]), el('span', { class: 'badge info' }, [t.confidence])]),
            el('div', { class: 'muted' }, [t.evidence]),
            t.version ? el('div', { class: 'muted' }, [`Version hint: ${t.version}`]) : el('span', {}),
          ]),
        );
      }
    }

    if (state.tab === 'Headers') {
      const list = latest.findings.filter((f) => f.category === 'Security headers');
      const filtered = state.filter === 'all' ? list : list.filter((f) => f.severity === state.filter);
      if (!filtered.length) panel.appendChild(el('div', { class: 'muted' }, ['No header issues at this severity.']));
      for (const f of filtered) panel.appendChild(renderFinding(f));
    }

    if (state.tab === 'Cookies') {
      if (!latest.cookies.length) panel.appendChild(el('div', { class: 'muted' }, ['No Set-Cookie headers captured yet for this navigation.']));
      for (const c of latest.cookies.slice(0, 40)) {
        panel.appendChild(
          el('div', { class: 'card' }, [
            el('header', {}, [el('strong', {}, [c.name]), el('span', { class: 'badge low' }, [c.issues.length ? 'Review' : 'OK'])]),
            el('div', { class: 'muted' }, [`Secure: ${bool(c.secure)} · HttpOnly: ${bool(c.httpOnly)} · SameSite: ${c.sameSite ?? 'unset'}`]),
            c.raw ? el('code', {}, [c.raw.slice(0, 220)]) : el('span', {}),
          ]),
        );
      }
      const cookieFindings = latest.findings.filter((f) => f.category === 'Cookies');
      for (const f of cookieFindings) panel.appendChild(renderFinding(f));
      panel.appendChild(
        el('div', {
          class: 'muted',
          html: '<p>Set-Cookie attributes are read from network responses. This view does not read the chrome.cookies permission; it still surfaces HttpOnly names because Set-Cookie is visible to the browser.</p>',
        }),
      );
    }

    if (state.tab === 'Libraries') {
      for (const lib of latest.libraries) {
        panel.appendChild(
          el('div', { class: 'card' }, [
            el('header', {}, [
              el('strong', {}, [lib.name]),
              el('span', { class: severityClass(lib.risk ?? 'none') }, [lib.risk ?? 'none']),
            ]),
            el('div', { class: 'muted' }, [lib.evidence]),
            lib.note ? el('div', { class: 'muted' }, [lib.note]) : el('span', {}),
            lib.cveRefs?.length ? el('div', { class: 'muted' }, [`Refs: ${lib.cveRefs.join(', ')}`]) : el('span', {}),
          ]),
        );
      }
      const libFindings = latest.findings.filter((f) => f.category === 'Libraries');
      for (const f of libFindings) panel.appendChild(renderFinding(f));
    }

    if (state.tab === 'Forms') {
      if (!latest.forms.length) panel.appendChild(el('div', { class: 'muted' }, ['No forms detected.']));
      for (const form of latest.forms) {
        panel.appendChild(
          el('div', { class: 'card' }, [
            el('header', {}, [el('strong', {}, [`Form #${form.index}`]), el('span', { class: 'badge info' }, [form.method])]),
            el('div', { class: 'muted' }, [`Action: ${form.action}`]),
            el('div', { class: 'muted' }, [
              `Password field: ${form.hasPassword ? 'yes' : 'no'} · Hidden fields: ${form.hiddenFieldCount}`,
            ]),
          ]),
        );
      }
      const formFindings = latest.findings.filter((f) => f.category === 'Forms');
      for (const f of formFindings) panel.appendChild(renderFinding(f));
    }

    if (state.tab === 'APIs') {
      const uniq = new Map<string, (typeof latest.apis)[number]>();
      for (const a of latest.apis) if (!uniq.has(a.url)) uniq.set(a.url, a);
      for (const a of [...uniq.values()].slice(0, 120)) {
        panel.appendChild(el('div', { class: 'card' }, [el('code', {}, [`[${a.type}] ${a.method} ${a.url}`])]));
      }
      const apiFindings = latest.findings.filter((f) => f.category === 'APIs');
      for (const f of apiFindings) panel.appendChild(renderFinding(f));
    }

    if (state.tab === 'Recommendations') {
      for (const line of latest.recommendations) {
        panel.appendChild(el('div', { class: 'card' }, [el('div', { class: 'muted' }, [line])]));
      }
    }

    root.appendChild(panel);
  };

  const doRefresh = async () => {
    latest = await deps.refresh();
    paint();
  };

  void chrome.storage.local.get('theme').then((r) => {
    if (r.theme === 'light') document.documentElement.dataset.theme = 'light';
  });

  void doRefresh();

  if (deps.liveIntervalMs) {
    window.setInterval(() => void doRefresh(), deps.liveIntervalMs);
  }
}
