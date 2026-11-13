import { useEffect, useState } from 'react';
import { Pagination, Search } from '@carbon/react';
import ReactEChartsRaw from 'echarts-for-react/lib/core';
import * as echarts from 'echarts/core';
import { BarChart } from 'echarts/charts';
import { GridComponent, TooltipComponent } from 'echarts/components';
import { SVGRenderer } from 'echarts/renderers';
import { api, type AccountPage, type Range } from '../api/client';
import { FONT, tokens } from '../lib/chartTheme';
import { dt, n } from '../lib/format';
import { RangeControl } from '../components/TrustBar';
import { Empty, ErrorState, Loading, PageHeader, SortTh, type Dir } from '../components/Table';

const Chart: typeof ReactEChartsRaw = (ReactEChartsRaw as unknown as { default?: typeof ReactEChartsRaw }).default ?? ReactEChartsRaw;
echarts.use([BarChart, GridComponent, TooltipComponent, SVGRenderer]);

export function Accounts({ dataset, range, onRange }: { dataset: string; range: Range; onRange: (r: Range) => void }) {
  const [st, setSt] = useState<{ sort: string; dir: Dir }>({ sort: 'attempts', dir: 'desc' });
  const [q, setQ] = useState('');
  const [page, setPage] = useState({ offset: 0, size: 25 });
  const [data, setData] = useState<AccountPage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setErr(null);
    api.accounts(dataset, { range, sort: st.sort, dir: st.dir, q, limit: page.size, offset: page.offset })
      .then((r) => live && setData(r)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, range, st, q, page, tick]);
  const onSort = (k: string) => { setPage((p) => ({ ...p, offset: 0 })); setSt(k === st.sort ? { sort: k, dir: st.dir === 'asc' ? 'desc' : 'asc' } : { sort: k, dir: k === 'username' ? 'asc' : 'desc' }); };
  const t = tokens();
  const top = data ? [...data.top].reverse() : [];
  const option = {
    animation: false, textStyle: { fontFamily: FONT }, grid: { left: 90, right: 70, top: 8, bottom: 24 },
    tooltip: { trigger: 'item', backgroundColor: '#fff', borderColor: t.grid, textStyle: { color: t.primary, fontSize: 12, fontFamily: FONT },
      formatter: (p: { name: string; value: number }) => `${p.name}<br/><b>${n(p.value)} failed attempts</b>` },
    xAxis: { type: 'value', splitNumber: 3, axisLabel: { color: t.text, fontSize: 11, formatter: (v: number) => (v >= 1000 ? `${v / 1000}k` : String(v)) }, splitLine: { lineStyle: { color: t.grid } } },
    yAxis: { type: 'category', data: top.map((r) => r.username), axisTick: { show: false }, axisLine: { lineStyle: { color: t.strong } }, axisLabel: { color: t.primary, fontSize: 12, fontFamily: 'IBM Plex Mono, monospace' } },
    series: [{ type: 'bar', barWidth: 14, data: top.map((r) => r.attempts), itemStyle: { color: t.line },
      label: { show: true, position: 'right', color: t.primary, fontSize: 11, formatter: (p: { value: number }) => n(p.value) } }],
  };
  return (
    <div className="app__content">
      <PageHeader title="Targeted accounts"><RangeControl range={range} onRange={onRange} /></PageHeader>
      {err && <ErrorState what="accounts" msg={err} onRetry={() => setTick(tick + 1)} />}
      {!data && !err && <Loading />}
      {data && (
        <>
          <section className="panel chart-panel band" aria-label="Top targeted usernames">
            <h2>Ten most targeted usernames</h2>
            <Chart echarts={echarts} option={option} opts={{ renderer: 'svg' }} style={{ height: 260 }} notMerge />
            <p className="caption">{data.caption}</p>
          </section>
          <section className="panel band" aria-label="Accounts table">
            <div className="toolbar">
              <Search size="sm" labelText="Search username" placeholder="Search username" value={q} onChange={(e) => { setPage((p) => ({ ...p, offset: 0 })); setQ(e.target.value); }} onClear={() => setQ('')} />
            </div>
            {data.rows.length === 0 ? <Empty title="No accounts match">No username matches this search in the selected range.</Empty> : (
              <div className="table-wrap">
                <table className="atk-table">
                  <thead><tr>
                    <SortTh label="Username" k="username" sort={st.sort} dir={st.dir} onSort={onSort} />
                    <SortTh label="Attempts" k="attempts" sort={st.sort} dir={st.dir} onSort={onSort} num />
                    <SortTh label="Share of attempts" k="share_pct" sort={st.sort} dir={st.dir} onSort={onSort} num />
                    <SortTh label="Source IPs" k="source_ips" sort={st.sort} dir={st.dir} onSort={onSort} num />
                    <SortTh label="Exists on server" k={null} sort={st.sort} dir={st.dir} onSort={onSort} />
                    <SortTh label="Privileged" k={null} sort={st.sort} dir={st.dir} onSort={onSort} />
                    <SortTh label="Successful logins" k="successful_logins" sort={st.sort} dir={st.dir} onSort={onSort} num />
                    <SortTh label="Last attempt" k="last_seen" sort={st.sort} dir={st.dir} onSort={onSort} />
                  </tr></thead>
                  <tbody>
                    {data.rows.map((r) => (
                      <tr key={r.username} style={{ cursor: 'default' }}>
                        <td className="mono">{r.username}</td>
                        <td className="num mono">{n(r.attempts)}</td>
                        <td className="num mono">{r.share_pct.toFixed(2)}%</td>
                        <td className="num mono">{n(r.source_ips)}</td>
                        <td>{r.exists ? 'Yes' : 'No, guessed'}</td>
                        <td>{r.privileged ? 'Yes' : 'No'}</td>
                        <td className="num mono">{n(r.successful_logins)}</td>
                        <td className="mono">{dt(r.last_seen)}</td>
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
  );
}
