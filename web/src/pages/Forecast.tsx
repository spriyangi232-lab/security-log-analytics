import { useEffect, useState } from 'react';
import { Toggletip, ToggletipButton, ToggletipContent } from '@carbon/react';
import { Information } from '@carbon/icons-react';
import ReactEChartsRaw from 'echarts-for-react/lib/core';
import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { GridComponent, LegendComponent, MarkLineComponent, TooltipComponent } from 'echarts/components';
import { SVGRenderer } from 'echarts/renderers';
import { api, type ForecastOut } from '../api/client';
import { FONT, tokens } from '../lib/chartTheme';
import { n } from '../lib/format';
import { ErrorState, Loading, PageHeader } from '../components/Table';

const Chart: typeof ReactEChartsRaw = (ReactEChartsRaw as unknown as { default?: typeof ReactEChartsRaw }).default ?? ReactEChartsRaw;
echarts.use([LineChart, LegendComponent, GridComponent, TooltipComponent, MarkLineComponent, SVGRenderer]);
const ms = (s: string) => +new Date(s.replace(' ', 'T') + 'Z');

function FChart({ actual, fc, unit, daily }: { actual: [string, number | null][]; fc: [string, number, number, number][]; unit: string; daily: boolean }) {
  const t = tokens();
  const option = {
    animation: false, useUTC: true, textStyle: { fontFamily: FONT }, grid: { left: 60, right: 16, top: 28, bottom: 28 },
    legend: { show: true, top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: t.text, fontSize: 11, fontFamily: FONT }, data: ['Actual', 'Forecast', 'Likely range'] },
    tooltip: { trigger: 'axis', backgroundColor: '#fff', borderColor: t.grid, textStyle: { color: t.primary, fontSize: 12, fontFamily: FONT },
      formatter: (ps: { seriesName: string; value: [number, number | null]; }[]) => {
        const x = ps[0].value[0]; const d = new Date(x).toISOString().slice(0, daily ? 10 : 13).replace('T', ' ') + (daily ? '' : ':00');
        const rows = ps.filter((p) => p.seriesName !== 'band-base' && p.value[1] != null).map((p) => `${p.seriesName}: <b>${n(Math.round(p.value[1] as number))}</b>`);
        return `${d} UTC<br/>${rows.join('<br/>')}`;
      } },
    xAxis: { type: 'time', axisLine: { lineStyle: { color: t.strong } }, axisLabel: { color: t.text, fontSize: 11, hideOverlap: true, formatter: { day: '{d} {MMM}', hour: '{HH}:00', month: '{MMM}', year: '{yyyy}' } }, splitLine: { show: false } },
    yAxis: { type: 'value', name: unit, nameTextStyle: { color: t.text, fontSize: 11, align: 'left', padding: [0, 0, 0, -48] }, axisLabel: { color: t.text, fontSize: 11, formatter: (v: number) => n(v) }, splitLine: { lineStyle: { color: t.grid } } },
    series: [
      { name: 'band-base', type: 'line', stack: 'band', symbol: 'none', lineStyle: { opacity: 0 }, silent: true, data: fc.map((r) => [ms(r[0]), r[2]]), tooltip: { show: false } },
      { name: 'Likely range', type: 'line', stack: 'band', symbol: 'none', lineStyle: { opacity: 0 }, areaStyle: { color: t.fill, opacity: 1 }, data: fc.map((r) => [ms(r[0]), r[3] - r[2]]) },
      { name: 'Actual', type: 'line', symbol: 'none', connectNulls: false, lineStyle: { color: t.line, width: 1.5 }, itemStyle: { color: t.line }, data: actual.map(([a, v]) => [ms(a), v]) },
      { name: 'Forecast', type: 'line', symbol: 'none', lineStyle: { color: t.primary, width: 1.5, type: 'dashed' }, itemStyle: { color: t.primary }, data: fc.map((r) => [ms(r[0]), r[1]]) },
    ],
  };
  return <Chart echarts={echarts} option={option} opts={{ renderer: 'svg' }} style={{ height: 260 }} notMerge />;
}

export function Forecast({ dataset }: { dataset: string }) {
  const [d, setD] = useState<ForecastOut | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setErr(null); setD(null);
    api.forecast(dataset).then((r) => live && setD(r)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, tick]);
  const o = d?.outlook;
  const none = o?.level === 'Insufficient data';
  const v = (x: number) => (none ? '—' : n(x));
  return (
    <div className="app__content">
      <PageHeader title="Forecast" />
      {err && <ErrorState what="the forecast" msg={err} onRetry={() => setTick(tick + 1)} />}
      {!d && !err && <Loading />}
      {d && o && (
        <>
          <section className="panel strip band" style={{ gridTemplateColumns: '1.4fr 1fr 1fr 1fr' }} aria-label="Risk outlook">
            <div className="cell">
              <div className="cell__label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                Risk outlook
                <Toggletip align="bottom-left">
                  <ToggletipButton label="How is the outlook decided?"><Information size={14} /></ToggletipButton>
                  <ToggletipContent>
                    <p>The outlook is called Rising, Falling or Stable only when all four checks pass. Otherwise it says Low confidence.</p>
                    <ul style={{ marginTop: 8, paddingLeft: 16 }}>{d.confidence_rules.map((r) => <li key={r} style={{ fontSize: 12, marginBottom: 4 }}>{r}</li>)}</ul>
                  </ToggletipContent>
                </Toggletip>
              </div>
              <div className="cell__value" style={{ fontSize: '1.5rem' }}>{o.level}</div>
              <div className="cell__delta" style={{ whiteSpace: 'normal' }}>{o.headline}</div>
            </div>
            <div className="cell"><div className="cell__label">Last 24 hours (actual)</div><div className="cell__value">{v(o.last24h)}</div><div className="cell__delta">failed attempts</div></div>
            <div className="cell"><div className="cell__label">Next 24 hours (hourly model)</div><div className="cell__value">{v(o.next24h)}</div><div className="cell__delta">failed attempts, forecast</div></div>
            <div className="cell"><div className="cell__label">Earlier 7-day average</div><div className="cell__value">{v(o.baseline_daily)}</div><div className="cell__delta">failed attempts per day</div></div>
          </section>
          <section className="panel chart-panel band" aria-label="Outlook explanation">
            <h2>Why this outlook</h2>
            <p style={{ fontSize: '0.875rem', margin: '0.25rem 0' }}>{o.message}</p>
          </section>
          <div className="charts band" style={{ gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)' }}>
            <section className="panel chart-panel" aria-label="Hourly forecast">
              <h2>Next 72 hours, by hour</h2>
              <FChart actual={d.hourly.actual} fc={d.hourly.forecast} unit="Attempts per hour" daily={false} />
              <p className="caption">Model: {d.models.hourly}. Actual values are the last 7 days.</p>
            </section>
            <section className="panel chart-panel" aria-label="Daily forecast">
              <h2>Next 7 days, by day</h2>
              <FChart actual={d.daily.actual} fc={d.daily.forecast} unit="Attempts per day" daily />
              <p className="caption">Model: {d.models.daily}. Days with no log lines are left blank, not shown as zero.</p>
            </section>
          </div>
          <section className="panel band" aria-label="Backtest results">
            <div style={{ padding: '0.75rem 1rem 0.5rem' }}>
              <h2 className="table-title">How well each model did in testing</h2>
              <p className="caption" style={{ margin: 0 }}>{d.caption} Skill is how much better a model is than repeating the last season; 0% means no better.</p>
            </div>
            {(['hourly', 'daily'] as const).map((k) => (
              <div className="table-wrap" key={k}>
                <table className="atk-table">
                  <thead><tr><th>{k === 'hourly' ? 'Hourly models' : 'Daily models'}</th><th className="num">Average error (MAE)</th><th className="num">RMSE</th><th className="num">Bias</th><th className="num">Test rounds</th><th className="num">Skill vs baseline</th></tr></thead>
                  <tbody>
                    {d.backtest[k].map((r) => (
                      <tr key={r.model} style={{ cursor: 'default' }}>
                        <td className="mono">{r.model}{r.model === (k === 'hourly' ? d.models.hourly : d.models.daily) ? ' (used)' : ''}</td>
                        <td className="num mono">{n(Math.round(r.MAE))}</td><td className="num mono">{n(Math.round(r.RMSE))}</td>
                        <td className="num mono">{n(Math.round(r.bias))}</td><td className="num mono">{r.folds}</td><td className="num mono">{r.skill_vs_naive_pct.toFixed(1)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </section>
        </>
      )}
    </div>
  );
}
