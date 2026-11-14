// Read-only demo (VITE_FIXTURES=1): the full tables are exported per range, and this file filters, sorts and
// pages them in the browser. It mirrors sla/overview.py (attackers, accounts, incidents) so the demo answers
// exactly what the API would: same filters, same stable sort with ties in the same base order, same captions.

type Row = Record<string, unknown>;
type Table = { total: number; rows: Row[]; caption: string; [k: string]: unknown };

const SEVERITY_ORDER: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, 'No incident': 0 };
const fmt = (n: number) => n.toLocaleString('en-US');
const isNull = (v: unknown) => v === null || v === undefined || (typeof v === 'number' && Number.isNaN(v));

// Stable sort like pandas sort_values(kind="stable"): ties keep their base order, missing values go last.
function sortRows(rows: Row[], key: (r: Row) => unknown, dir: 'asc' | 'desc'): Row[] {
  const sign = dir === 'asc' ? 1 : -1;
  return rows
    .map((r, i) => ({ r, i, k: key(r) }))
    .sort((a, b) => {
      const an = isNull(a.k), bn = isNull(b.k);
      if (an || bn) return an === bn ? a.i - b.i : an ? 1 : -1;
      const c = (a.k as number | string) < (b.k as number | string) ? -1 : (a.k as number | string) > (b.k as number | string) ? 1 : 0;
      return c === 0 ? a.i - b.i : sign * c;
    })
    .map((x) => x.r);
}

const page = <T extends Table>(t: T, rows: Row[], limit: number, offset: number, caption: string): T =>
  ({ ...t, total: rows.length, limit, offset, rows: rows.slice(offset, offset + limit), caption });

const withCount = (caption: string, n: number) => caption.replace(/^[\d,]+/, fmt(n));

export function queryAttackers(t: Table, p: { sort: string; dir: 'asc' | 'desc'; q: string; severity: string; limit: number; offset: number }) {
  let rows = t.rows; // exported in rank order (attempts, descending)
  const q = p.q.trim();
  if (q) rows = rows.filter((r) => String(r.ip).includes(q));
  if (p.severity) rows = rows.filter((r) => r.severity === p.severity);
  if (rows.length && p.sort in rows[0]) {
    rows = sortRows(rows, p.sort === 'severity' ? (r) => SEVERITY_ORDER[String(r.severity)] : (r) => r[p.sort], p.dir);
  }
  return page(t, rows, p.limit, p.offset, withCount(t.caption, rows.length));
}

export function queryAccounts(t: Table, p: { sort: string; dir: 'asc' | 'desc'; q: string; limit: number; offset: number }) {
  let rows = t.rows; // exported sorted by attempts, descending
  const q = p.q.trim().toLowerCase();
  if (q) rows = rows.filter((r) => String(r.username).toLowerCase().includes(q));
  if (rows.length && p.sort in rows[0]) rows = sortRows(rows, (r) => r[p.sort], p.dir);
  // "top" and the top-3 share are recomputed from the filtered rows, like the API
  const byAttempts = sortRows(rows, (r) => r.attempts, 'desc');
  const top = byAttempts.slice(0, 10).map((r) => ({ username: r.username, attempts: r.attempts }));
  const totalAttempts = Number((t.caption.match(/of the ([\d,]+) attempts/) ?? [, '0'])[1]!.replace(/,/g, ''));
  const top3 = byAttempts.slice(0, 3).reduce((s, r) => s + Number(r.attempts), 0) / Math.max(totalAttempts, 1) * 100;
  const caption = withCount(t.caption, rows.length).replace(/top 3 account for [\d.]+%/, `top 3 account for ${top3.toFixed(1)}%`);
  return { ...page(t, rows, p.limit, p.offset, caption), top };
}

export function queryIncidents(t: Table, p: { sort: string; dir: 'asc' | 'desc'; q: string; severity: string; rule: string; limit: number; offset: number }) {
  let rows = t.rows; // exported in table order (incident_id); by_severity counts are taken before filters, as in the API
  if (p.rule) rows = rows.filter((r) => r.rule === p.rule);
  if (p.severity) rows = rows.filter((r) => r.severity === p.severity);
  const q = p.q.trim().toLowerCase();
  if (q) {
    const has = (v: unknown) => (typeof v === 'string' ? v : '').toLowerCase().includes(q);
    rows = rows.filter((r) => String(r.ip ?? '').includes(q) || has(r.incident_id) || has(r.username));
  }
  const key = p.sort === 'severity' ? (r: Row) => SEVERITY_ORDER[String(r.severity)]
    : rows.length && p.sort in rows[0] ? (r: Row) => r[p.sort] : (r: Row) => r.start_ts;
  rows = sortRows(rows, key, p.dir);
  return page(t, rows, p.limit, p.offset, withCount(t.caption, rows.length));
}
