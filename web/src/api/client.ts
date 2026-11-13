import type { components } from './schema';

export type Overview = components['schemas']['Overview'];
export type AttackerPage = components['schemas']['AttackerPage'];
export type AttackerRow = components['schemas']['AttackerRow'];
export type AttackerDetail = components['schemas']['AttackerDetail'];
export type AttackerEvents = components['schemas']['AttackerEvents'];
export type AccountPage = components['schemas']['AccountPage'];
export type IncidentPage = components['schemas']['IncidentPage'];
export type IncidentFull = components['schemas']['IncidentFull'];
export type ControlsOut = components['schemas']['ControlsOut'];
export type ControlRow = components['schemas']['ControlRow'];
export type ForecastOut = components['schemas']['ForecastOut'];
export type ReportsOut = components['schemas']['ReportsOut'];
export type Job = components['schemas']['JobOut'];
export type DatasetSummary = components['schemas']['DatasetSummary'];
export type Range = '24h' | '7d' | 'all';
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'No incident';
export type SortKey = 'rank' | 'ip' | 'attempts' | 'first_seen' | 'last_seen' | 'accounts' | 'severity';

export interface Rules {
  risk_formula?: string;
  risk_weights?: Record<string, number>;
  risk_components?: { key: string; label: string; formula: string; meaning: string }[];
  detection: { id: string; title: string; technique_id: string; technique: string; tactic: string; plain: string; action: string; severity_rule: string | null }[];
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// Fixture mode (VITE_FIXTURES=1) serves committed excerpts of real pipeline output instead of calling the API.
export const FIX = import.meta.env.VITE_FIXTURES === '1';
// Prefix for static files, so the demo also works under a sub-path such as GitHub Pages (/repo-name/).
export const BASE = import.meta.env.BASE_URL;

async function get<T>(path: string, fixture?: string): Promise<T> {
  const url = FIX && fixture ? `${BASE}fixtures/${fixture}.json` : `/api/v1${path}`;
  const r = await fetch(url);
  if (!r.ok) {
    let detail = r.statusText;
    try {
      detail = (await r.json()).detail ?? detail;
    } catch { /* not json */ }
    throw new ApiError(r.status, detail);
  }
  return r.json() as Promise<T>;
}

export const api = {
  datasets: () => get<DatasetSummary[]>('/datasets', 'datasets'),
  overview: (id: string, range: Range) => get<Overview>(`/datasets/${id}/overview?range=${range}`, `overview_${range}`),
  attackers: (id: string, p: { range: Range; sort: SortKey; dir: 'asc' | 'desc'; q: string; severity: string; limit: number; offset: number }) => {
    const qs = new URLSearchParams({ range: p.range, sort: p.sort, dir: p.dir, limit: String(p.limit), offset: String(p.offset) });
    if (p.q) qs.set('q', p.q);
    if (p.severity) qs.set('severity', p.severity);
    return get<AttackerPage>(`/datasets/${id}/attackers?${qs}`, `attackers_${p.range}`);
  },
  attacker: (id: string, ip: string) => get<AttackerDetail>(`/datasets/${id}/attackers/${ip}`, `attacker_${ip}`),
  events: (id: string, ip: string) => get<AttackerEvents>(`/datasets/${id}/attackers/${ip}/events?limit=50`, `events_${ip}`),
  accounts: (id: string, p: { range: Range; sort: string; dir: 'asc' | 'desc'; q: string; limit: number; offset: number }) => {
    const qs = new URLSearchParams({ range: p.range, sort: p.sort, dir: p.dir, limit: String(p.limit), offset: String(p.offset) });
    if (p.q) qs.set('q', p.q);
    return get<AccountPage>(`/datasets/${id}/accounts?${qs}`, `accounts_${p.range}`);
  },
  incidents: (id: string, p: { range: Range; sort: string; dir: 'asc' | 'desc'; q: string; severity: string; rule: string; limit: number; offset: number }) => {
    const qs = new URLSearchParams({ range: p.range, sort: p.sort, dir: p.dir, limit: String(p.limit), offset: String(p.offset) });
    if (p.q) qs.set('q', p.q);
    if (p.severity) qs.set('severity', p.severity);
    if (p.rule) qs.set('rule', p.rule);
    return get<IncidentPage>(`/datasets/${id}/incidents?${qs}`, `incidents_${p.range}`);
  },
  controls: (id: string) => get<ControlsOut>(`/datasets/${id}/controls`, 'controls'),
  forecast: (id: string) => get<ForecastOut>(`/datasets/${id}/forecast`, 'forecast'),
  reports: (id: string) => get<ReportsOut>(`/datasets/${id}/reports`, 'reports'),
  reportUrl: (id: string, file: string) => FIX
    ? `${BASE}fixtures/reports/${file}`
    : `/api/v1/datasets/${id}/reports/download?file=${encodeURIComponent(file)}`,
  upload: async (file: File, year: number, name: string): Promise<Job> => {
    if (FIX) throw new ApiError(503, 'Uploads are switched off in this read-only online demo. Run the app locally to analyse your own log');
    const fd = new FormData();
    fd.append('file', file); fd.append('year', String(year)); if (name) fd.append('name', name);
    const r = await fetch('/api/v1/datasets', { method: 'POST', body: fd });
    if (!r.ok) { let d = r.statusText; try { d = (await r.json()).detail ?? d; } catch { /* */ } throw new ApiError(r.status, d); }
    return r.json();
  },
  job: (id: string) => get<Job>(`/jobs/${id}`),
  rules: () => get<Rules>('/rules', 'rules'),
  csvUrl: (id: string, range: Range, severity: string) => FIX
    ? `${BASE}fixtures/reports/ip_risk.csv`
    : `/api/v1/datasets/${id}/exports/attackers.csv?range=${range}${severity ? `&severity=${severity}` : ''}`,
};
