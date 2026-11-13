import { useEffect, useState } from 'react';
import { Button } from '@carbon/react';
import { Close } from '@carbon/icons-react';
import { api, type ControlRow, type ControlsOut } from '../api/client';
import { n } from '../lib/format';
import { ErrorState, Loading, PageHeader } from '../components/Table';

/** Control results use neutral tags: red/orange/yellow are reserved for severity. */
function ResultTag({ result }: { result: string }) {
  const strong = result === 'Ineffective';
  return <span className="tech" style={{ fontFamily: 'inherit', fontWeight: strong ? 600 : 400, borderColor: strong ? '#161616' : '#8d8d8d', background: result === 'Effective' ? '#fff' : '#eceff3' }}>{result}</span>;
}

export function Controls({ dataset }: { dataset: string }) {
  const [data, setData] = useState<ControlsOut | null>(null);
  const [sel, setSel] = useState<ControlRow | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setErr(null); setData(null); setSel(null);
    api.controls(dataset).then((r) => live && setData(r)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, tick]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') setSel(null); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);
  return (
    <>
      <div className="app__content">
        <PageHeader title="Controls" />
        {err && <ErrorState what="controls" msg={err} onRetry={() => setTick(tick + 1)} />}
        {!data && !err && <Loading />}
        {data && (
          <>
            <section className="panel strip band" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }} aria-label="Control results">
              {data.summary.map((s) => (
                <div className="cell" key={s.result}>
                  <div className="cell__label">{s.result}</div>
                  <div className="cell__value">{s.count}</div>
                  <div className="cell__delta">of {data.rows.length} controls</div>
                </div>
              ))}
            </section>
            <section className="panel band" aria-label="Control tests">
              <div style={{ padding: '0.75rem 1rem 0.75rem' }}><p className="caption" style={{ margin: 0 }}>{data.caption} Controls are tested over the whole dataset, so the range control does not apply here.</p></div>
              <div className="table-wrap">
                <table className="atk-table">
                  <thead><tr><th>ID</th><th>Result</th><th>Domain</th><th>Control objective</th><th className="num">Population</th><th className="num">Exceptions</th></tr></thead>
                  <tbody>
                    {data.rows.map((c) => (
                      <tr key={c.control_id} tabIndex={0} aria-selected={sel?.control_id === c.control_id}
                        onClick={() => setSel(sel?.control_id === c.control_id ? null : c)}
                        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSel(sel?.control_id === c.control_id ? null : c); } }}>
                        <td className="mono">{c.control_id}</td>
                        <td><ResultTag result={c.result} /></td>
                        <td>{c.domain}</td>
                        <td style={{ whiteSpace: 'normal', minWidth: '14rem' }}>{c.control_objective}</td>
                        <td className="num mono">{n(c.population)}</td>
                        <td className="num mono">{n(c.exceptions)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </div>
      {sel && (
        <aside className="app__detail" aria-label={`Details for ${sel.control_id}`}>
          <div className="detail">
            <div className="detail__head">
              <h2 className="mono" style={{ fontSize: '1.125rem', margin: 0, fontWeight: 600 }}>{sel.control_id}</h2>
              <Button kind="ghost" size="sm" hasIconOnly renderIcon={Close} iconDescription="Close details" onClick={() => setSel(null)} />
            </div>
            <ResultTag result={sel.result} />
            <h3>Objective</h3><p>{sel.control_objective}</p>
            <h3>Risk addressed</h3><p>{sel.risk_addressed}</p>
            <h3>How it was tested</h3><p>{sel.test_procedure}</p>
            <h3>Population and exceptions</h3>
            <p>{sel.population_description}: <b className="mono">{n(sel.population)}</b> tested, <b className="mono">{n(sel.exceptions)}</b> exceptions.</p>
            <h3>Evidence</h3><p>{sel.evidence}</p>
            <h3>Recommendation</h3><p>{sel.recommendation}</p>
            <h3>Framework reference</h3><p>{sel.framework_reference}</p>
          </div>
        </aside>
      )}
    </>
  );
}
