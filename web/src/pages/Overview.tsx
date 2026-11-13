import { useEffect, useState } from 'react';
import { InlineNotification, Button } from '@carbon/react';
import { api, type Overview as OV, type Range, type Rules } from '../api/client';
import { SummaryStrip } from '../components/SummaryStrip';
import { RangeControl, TrustBar } from '../components/TrustBar';
import { SeverityChart, TimeSeriesChart } from '../components/Charts';
import { AttackersTable } from '../components/AttackersTable';
import { DetailPane } from '../components/DetailPane';

export function Overview({ dataset, range, onRange, selected, onSelect, rules }: {
  dataset: string; range: Range; onRange: (r: Range) => void; selected: string | null; onSelect: (ip: string | null) => void; rules: Rules | null;
}) {
  const [data, setData] = useState<OV | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setErr(null);
    setData(null);
    api.overview(dataset, range).then((r) => live && setData(r)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, range, tick]);

  return (
    <>
      <div className="app__content">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <h1 className="page-title" style={{ margin: 0 }}>Overview</h1>
        <RangeControl range={range} onRange={onRange} />
      </div>
      {err && (
        <div className="band">
          <InlineNotification kind="error" title="Could not load the overview." subtitle={err} lowContrast hideCloseButton />
          <Button kind="tertiary" size="sm" onClick={() => setTick(tick + 1)}>Retry</Button>
        </div>
      )}
      {!data && !err && (
        <div aria-busy="true" aria-label="Loading overview">
          <div className="panel band" style={{ height: 40 }} /><div className="panel band" style={{ height: 124 }} /><div className="panel band" style={{ height: 300 }} />
        </div>
      )}
      {data && (
        <>
          <TrustBar data={data} />
          <SummaryStrip data={data} range={range} />
          <div className="charts band">
            <section className="panel chart-panel" aria-label="Attempts over time">
              <h2>Failed attempts over time</h2>
              <TimeSeriesChart data={data.timeseries} />
              <p className="caption">{data.timeseries.caption}</p>
            </section>
            <section className="panel chart-panel" aria-label="Attempts by severity">
              <h2>Attempts by severity</h2>
              <SeverityChart data={data.by_severity} />
              <p className="caption">{data.by_severity.caption}</p>
            </section>
          </div>
        </>
      )}
      <AttackersTable dataset={dataset} range={range} selected={selected} onSelect={onSelect} rules={rules} />
      </div>
      {selected && <DetailPane dataset={dataset} ip={selected} rules={rules} onClose={() => onSelect(null)} />}
    </>
  );
}
