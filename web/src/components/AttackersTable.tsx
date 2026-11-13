import { useEffect, useRef, useState } from 'react';
import { Pagination, Search, Select, SelectItem } from '@carbon/react';
import { ArrowDown, ArrowUp, ArrowsVertical, Download } from '@carbon/icons-react';
import { api, type AttackerPage, type Range, type Rules, type SortKey } from '../api/client';
import { dt, n } from '../lib/format';
import { SeverityBadge, TechniqueTag } from './Badges';
import { Sparkline } from './Sparkline';

type Dir = 'asc' | 'desc';
const COLS: { key: SortKey | null; label: string; num?: boolean }[] = [
  { key: 'rank', label: 'Rank', num: true }, { key: 'ip', label: 'Source IP' }, { key: 'attempts', label: 'Attempts', num: true },
  { key: 'first_seen', label: 'First seen' }, { key: 'last_seen', label: 'Last seen' }, { key: 'accounts', label: 'Accounts', num: true },
  { key: null, label: 'Last 14 days' }, { key: 'severity', label: 'Severity' }, { key: null, label: 'ATT&CK' }, { key: null, label: 'Recommended action' },
];

export function AttackersTable({ dataset, range, selected, onSelect, rules, initialSize = 10, hideTitle = false }: {
  dataset: string; range: Range; selected: string | null; onSelect: (ip: string | null) => void; rules: Rules | null; initialSize?: number; hideTitle?: boolean;
}) {
  const [sort, setSort] = useState<SortKey>('attempts');
  const [dir, setDir] = useState<Dir>('desc');
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('');
  const [page, setPage] = useState({ offset: 0, size: initialSize });
  const [data, setData] = useState<AttackerPage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const sig = [dataset, range, q, sev].join('|');
  const lastSig = useRef(sig);
  useEffect(() => {
    if (lastSig.current !== sig) {            // filters changed: go back to page 1 (one request, not two)
      lastSig.current = sig;
      if (page.offset !== 0) { setPage((p) => ({ ...p, offset: 0 })); return; }
    }
    let live = true;
    setErr(null);
    api.attackers(dataset, { range, sort, dir, q, severity: sev, limit: page.size, offset: page.offset })
      .then((r) => live && setData(r)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, range, sort, dir, q, sev, page, tick]);

  const toggle = (k: SortKey) => { if (k === sort) setDir(dir === 'asc' ? 'desc' : 'asc'); else { setSort(k); setDir(k === 'ip' || k === 'rank' ? 'asc' : 'desc'); } };
  const tname = (id: string) => rules?.detection.find((r) => r.technique_id === id)?.technique;

  return (
    <section className="panel band" aria-label="Attackers">
      <div style={{ padding: '0.75rem 1rem 0.5rem' }}>
        {!hideTitle && <h2 className="table-title">Attackers</h2>}
        <p className="caption" style={{ margin: 0 }}>{data?.caption ?? 'Loading attackers.'}</p>
      </div>
      <div className="toolbar">
        <Search size="sm" labelText="Search source IP" placeholder="Search source IP" value={q} onChange={(e) => setQ(e.target.value)} onClear={() => setQ('')} />
        <Select id="sev-filter" size="sm" labelText="Severity" inline value={sev} onChange={(e) => setSev(e.target.value)}>
          <SelectItem value="" text="All severities" />
          {['Critical', 'High', 'Medium', 'Low', 'No incident'].map((s) => <SelectItem key={s} value={s} text={s} />)}
        </Select>
        <a className="toolbar__spacer cds--link" href={api.csvUrl(dataset, range, sev)} style={{ display: 'inline-flex', gap: 4, alignItems: 'center', fontSize: '0.875rem' }}>
          <Download size={16} /> Export CSV
        </a>
      </div>
      {err && <div className="state" role="alert"><h3>Could not load attackers</h3><p>{err}</p><button className="cds--btn cds--btn--sm cds--btn--tertiary" onClick={() => setTick(tick + 1)}>Retry</button></div>}
      {!err && !data && <div className="state" aria-busy="true"><div className="skeleton" /><br /><div className="skeleton" style={{ width: '70%' }} /></div>}
      {data && data.rows.length === 0 && <div className="state"><h3>No attackers match</h3><p>No source IP has failed attempts in this range with the current search and filter. Clear the search or choose All severities.</p></div>}
      {data && data.rows.length > 0 && (
        <div className="table-wrap">
          <table className="atk-table">
            <thead>
              <tr>
                {COLS.map((c) => (
                  <th key={c.label} className={c.num ? 'num' : ''} aria-sort={c.key === sort ? (dir === 'asc' ? 'ascending' : 'descending') : undefined}>
                    {c.key ? (
                      <button onClick={() => toggle(c.key as SortKey)} aria-label={`Sort by ${c.label}`}>
                        {c.label} {c.key === sort ? (dir === 'asc' ? <ArrowUp size={12} /> : <ArrowDown size={12} />) : <ArrowsVertical size={12} />}
                      </button>
                    ) : c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.rows.map((r) => (
                <tr key={r.ip} tabIndex={0} aria-selected={selected === r.ip} onClick={() => onSelect(selected === r.ip ? null : r.ip)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(selected === r.ip ? null : r.ip); } }}>
                  <td className="num">{r.rank}</td>
                  <td className="mono">{r.ip}</td>
                  <td className="num mono">{n(r.attempts)}</td>
                  <td className="mono">{dt(r.first_seen)}</td>
                  <td className="mono">{dt(r.last_seen)}</td>
                  <td className="num mono">{n(r.accounts)}</td>
                  <td style={{ width: 120 }}><Sparkline data={r.spark14} label={`${r.ip} attempts, last 14 days`} /></td>
                  <td><SeverityBadge severity={r.severity} /></td>
                  <td>{r.techniques.length ? r.techniques.map((t) => <TechniqueTag key={t} id={t} name={tname(t)} />) : <span style={{ color: 'var(--cds-text-secondary)' }}>None</span>}</td>
                  <td className="action">{r.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && (
        <Pagination size="sm" page={page.offset / page.size + 1} pageSize={page.size} pageSizes={[10, 25, 50, 100]} totalItems={data.total}
          onChange={({ page: p, pageSize }) => setPage({ offset: (p - 1) * pageSize, size: pageSize })} />
      )}
    </section>
  );
}
