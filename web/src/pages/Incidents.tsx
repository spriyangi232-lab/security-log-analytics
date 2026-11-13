import { useEffect, useRef, useState } from 'react';
import { Button, Pagination, Search, Select, SelectItem } from '@carbon/react';
import { Close } from '@carbon/icons-react';
import { api, type IncidentFull, type IncidentPage, type Range, type Rules } from '../api/client';
import { dt, n } from '../lib/format';
import { SeverityBadge, TechniqueTag } from '../components/Badges';
import { RangeControl } from '../components/TrustBar';
import { Empty, ErrorState, Loading, PageHeader, SortTh, type Dir } from '../components/Table';

export function Incidents({ dataset, range, onRange, rules }: { dataset: string; range: Range; onRange: (r: Range) => void; rules: Rules | null }) {
  const [st, setSt] = useState<{ sort: string; dir: Dir }>({ sort: 'start_ts', dir: 'desc' });
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('');
  const [rule, setRule] = useState('');
  const [page, setPage] = useState({ offset: 0, size: 25 });
  const [data, setData] = useState<IncidentPage | null>(null);
  const [sel, setSel] = useState<IncidentFull | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const sig = [dataset, range, q, sev, rule].join('|');
  const last = useRef(sig);
  useEffect(() => {
    if (last.current !== sig) { last.current = sig; if (page.offset !== 0) { setPage((p) => ({ ...p, offset: 0 })); return; } }
    let live = true;
    setErr(null);
    api.incidents(dataset, { range, sort: st.sort, dir: st.dir, q, severity: sev, rule, limit: page.size, offset: page.offset })
      .then((r) => live && setData(r)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, range, st, q, sev, rule, page, tick, sig]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') setSel(null); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);
  const onSort = (k: string) => { setPage((p) => ({ ...p, offset: 0 })); setSt(k === st.sort ? { sort: k, dir: st.dir === 'asc' ? 'desc' : 'asc' } : { sort: k, dir: k === 'incident_id' ? 'asc' : 'desc' }); };
  const r = sel && rules?.detection.find((x) => x.id === sel.rule);
  return (
    <>
      <div className="app__content">
        <PageHeader title="Incidents"><RangeControl range={range} onRange={onRange} /></PageHeader>
        {err && <ErrorState what="incidents" msg={err} onRetry={() => setTick(tick + 1)} />}
        {!data && !err && <Loading />}
        {data && (
          <>
            <section className="panel strip band" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }} aria-label="Incidents by severity">
              {data.by_severity.map((s) => (
                <div className="cell" key={s.severity}>
                  <div className="cell__label"><SeverityBadge severity={s.severity} /></div>
                  <div className="cell__value">{n(s.count)}</div>
                  <div className="cell__delta">incidents in range</div>
                </div>
              ))}
            </section>
            <section className="panel band" aria-label="Incident list">
              <div style={{ padding: '0.75rem 1rem 0.5rem' }}><p className="caption" style={{ margin: 0 }}>{data.caption}</p></div>
              <div className="toolbar">
                <Search size="sm" labelText="Search incident, IP or account" placeholder="Search ID, IP or account" value={q} onChange={(e) => setQ(e.target.value)} onClear={() => setQ('')} />
                <Select id="inc-sev" size="sm" labelText="Severity" inline value={sev} onChange={(e) => setSev(e.target.value)}>
                  <SelectItem value="" text="All severities" />
                  {['Critical', 'High', 'Medium', 'Low'].map((s) => <SelectItem key={s} value={s} text={s} />)}
                </Select>
                <Select id="inc-rule" size="sm" labelText="Rule" inline value={rule} onChange={(e) => setRule(e.target.value)}>
                  <SelectItem value="" text="All rules" />
                  {data.rules.map((x) => <SelectItem key={x.id} value={x.id} text={x.title} />)}
                </Select>
              </div>
              {data.rows.length === 0 ? <Empty title="No incidents match">No incident started in this range with the current search and filters.</Empty> : (
                <div className="table-wrap">
                  <table className="atk-table">
                    <thead><tr>
                      <SortTh label="ID" k="incident_id" sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="Severity" k="severity" sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="Priority" k={null} sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="What happened" k={null} sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="ATT&CK" k={null} sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="Source IP" k="ip" sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="Account" k={null} sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="Started" k="start_ts" sort={st.sort} dir={st.dir} onSort={onSort} />
                      <SortTh label="Attempts" k="attempts" sort={st.sort} dir={st.dir} onSort={onSort} num />
                    </tr></thead>
                    <tbody>
                      {data.rows.map((i) => (
                        <tr key={i.incident_id} tabIndex={0} aria-selected={sel?.incident_id === i.incident_id}
                          onClick={() => setSel(sel?.incident_id === i.incident_id ? null : i)}
                          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSel(sel?.incident_id === i.incident_id ? null : i); } }}>
                          <td className="mono">{i.incident_id}</td>
                          <td><SeverityBadge severity={i.severity} /></td>
                          <td className="mono">{i.priority}</td>
                          <td>{i.title}</td>
                          <td><TechniqueTag id={i.technique_id} name={rules?.detection.find((x) => x.technique_id === i.technique_id)?.technique} /></td>
                          <td className="mono">{i.ip ?? '—'}</td>
                          <td className="mono">{i.username ?? '—'}</td>
                          <td className="mono">{dt(i.start_ts)}</td>
                          <td className="num mono">{n(i.attempts)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <Pagination size="sm" page={page.offset / page.size + 1} pageSize={page.size} pageSizes={[25, 50, 100]} totalItems={data.total}
                onChange={({ page: p, pageSize }) => setPage({ offset: (p - 1) * pageSize, size: pageSize })} />
            </section>
          </>
        )}
      </div>
      {sel && (
        <aside className="app__detail" aria-label={`Details for ${sel.incident_id}`}>
          <div className="detail">
            <div className="detail__head">
              <h2 className="mono" style={{ fontSize: '1.125rem', margin: 0, fontWeight: 600 }}>{sel.incident_id}</h2>
              <Button kind="ghost" size="sm" hasIconOnly renderIcon={Close} iconDescription="Close details" onClick={() => setSel(null)} />
            </div>
            <SeverityBadge severity={sel.severity} /> <span className="mono" style={{ marginLeft: 8 }}>{sel.priority}</span>
            <h3>What happened</h3><p>{sel.title}. {sel.evidence}.</p>
            {r && <><h3>In plain words</h3><p>{r.plain}</p></>}
            <h3>Why this severity</h3><p>{r?.severity_rule ?? 'See the detection rule.'}</p>
            <h3>Response target ({sel.priority})</h3><p>{sel.response_target}</p>
            {r && <><h3>Recommended action</h3><p>{r.action}</p><h3>MITRE ATT&amp;CK</h3><p><TechniqueTag id={r.technique_id} /> {r.technique} ({r.tactic})</p></>}
            <h3>Facts</h3>
            <table><tbody>
              <tr><th>Source IP</th><td className="mono">{sel.ip ?? 'Several'}</td></tr>
              <tr><th>Account</th><td className="mono">{sel.username ?? 'Several'}</td></tr>
              <tr><th>Started</th><td className="mono">{sel.start_ts}</td></tr>
              <tr><th>Ended</th><td className="mono">{sel.end_ts}</td></tr>
              <tr><th>Attempts</th><td className="mono">{n(sel.attempts)}</td></tr>
              {sel.peak_window_attempts != null && <tr><th>Peak in 5 minutes</th><td className="mono">{n(sel.peak_window_attempts)}</td></tr>}
            </tbody></table>
          </div>
        </aside>
      )}
    </>
  );
}
