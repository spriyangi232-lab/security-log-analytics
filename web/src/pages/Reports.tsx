import { useEffect, useState } from 'react';
import { Download } from '@carbon/icons-react';
import { api, type ReportsOut } from '../api/client';
import { ErrorState, Loading, PageHeader } from '../components/Table';

const size = (b: number | null | undefined) => (b == null ? '' : b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`);

export function Reports({ dataset }: { dataset: string }) {
  const [d, setD] = useState<ReportsOut | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setErr(null); setD(null);
    api.reports(dataset).then((r) => live && setD(r)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, tick]);
  return (
    <div className="app__content">
      <PageHeader title="Reports" />
      {err && <ErrorState what="reports" msg={err} onRetry={() => setTick(tick + 1)} />}
      {!d && !err && <Loading />}
      {d && (
        <section className="panel band" aria-label="Report files">
          <div style={{ padding: '0.75rem 1rem 0.5rem' }}><p className="caption" style={{ margin: 0 }}>{d.caption}</p></div>
          <div className="table-wrap">
            <table className="atk-table">
              <thead><tr><th>Report</th><th>What it contains</th><th>For</th><th>File</th><th className="num">Size</th><th>Download</th></tr></thead>
              <tbody>
                {d.rows.map((r) => (
                  <tr key={r.file} style={{ cursor: 'default' }}>
                    <td style={{ fontWeight: 600 }}>{r.title}</td>
                    <td style={{ whiteSpace: 'normal', minWidth: '20rem' }}>{r.description}</td>
                    <td>{r.audience}</td>
                    <td className="mono">{r.file.split('/').pop()}</td>
                    <td className="num mono">{size(r.size_bytes)}</td>
                    <td>{r.available
                      ? <a className="cds--link" href={api.reportUrl(dataset, r.file)} style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}><Download size={16} /> Download</a>
                      : <span style={{ color: 'var(--cds-text-secondary)' }}>Not available</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
