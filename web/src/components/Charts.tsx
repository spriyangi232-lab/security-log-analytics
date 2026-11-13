import ReactEChartsRaw from 'echarts-for-react/lib/core';
import * as echarts from 'echarts/core';
import { BarChart, LineChart } from 'echarts/charts';
import { GridComponent, MarkAreaComponent, TooltipComponent } from 'echarts/components';
import { SVGRenderer } from 'echarts/renderers';
import type { Overview } from '../api/client';
import { FONT, tokens } from '../lib/chartTheme';
import { n } from '../lib/format';

// CommonJS default-export interop under Vite
const ReactEChartsCore: typeof ReactEChartsRaw = (ReactEChartsRaw as unknown as { default?: typeof ReactEChartsRaw }).default ?? ReactEChartsRaw;

echarts.use([LineChart, BarChart, GridComponent, TooltipComponent, MarkAreaComponent, SVGRenderer]);

export function TimeSeriesChart({ data }: { data: Overview['timeseries'] }) {
  const t = tokens();
  const ms = (s: string) => +new Date(s.replace(' ', 'T') + 'Z');
  const pts = data.points.map(([ts, v]) => [ms(ts), v]);
  const areas: object[] = [
    ...data.gaps.map((g) => [{ xAxis: ms(g.start), itemStyle: { color: t.fill, opacity: 1 }, name: 'No log lines',
      label: { show: true, color: t.text, fontSize: 11, fontFamily: FONT, position: 'insideTop', formatter: 'No log lines' } }, { xAxis: ms(g.end) }]),
    ...data.anomalies.map((a) => [{ xAxis: ms(a.start_ts), itemStyle: { color: 'transparent', borderColor: t.line, borderWidth: 1, borderType: 'dashed' },
      label: { show: true, color: t.primary, fontSize: 11, fontFamily: FONT, position: 'insideTop', formatter: `Spike: ${n(a.peak_attempts)}/h (${a.rule_id})` } }, { xAxis: ms(a.end_ts) }]),
  ];
  const option = {
    animation: false, useUTC: true, textStyle: { fontFamily: FONT },
    grid: { left: 56, right: 16, top: 12, bottom: 28 },
    tooltip: {
      trigger: 'axis', axisPointer: { type: 'line', lineStyle: { color: t.strong } }, borderColor: t.grid, backgroundColor: '#fff',
      textStyle: { color: t.primary, fontSize: 12, fontFamily: FONT },
      formatter: (p: { value: [number, number | null] }[]) => {
        const [x, v] = p[0].value;
        const d = new Date(x).toISOString().slice(0, 13).replace('T', ' ');
        return `${d}:00 UTC<br/><b>${v == null ? 'No log lines' : n(v) + ' failed attempts'}</b>`;
      },
    },
    xAxis: { type: 'time', axisLine: { lineStyle: { color: t.strong } }, axisLabel: { color: t.text, fontSize: 11, hideOverlap: true, fontFamily: FONT, formatter: { year: '{yyyy}', month: '{MMM}', day: '{d} {MMM}', hour: '{HH}:00', minute: '{HH}:{mm}' } }, splitLine: { show: false } },
    yAxis: { type: 'value', name: 'Attempts per hour', nameTextStyle: { color: t.text, fontSize: 11, align: 'left', padding: [0, 0, 0, -40] },
      axisLabel: { color: t.text, fontSize: 11, formatter: (v: number) => n(v), fontFamily: FONT }, splitLine: { lineStyle: { color: t.grid } } },
    series: [{ type: 'line', data: pts, showSymbol: false, connectNulls: false, lineStyle: { color: t.line, width: 1.5 }, itemStyle: { color: t.line },
      markArea: { silent: true, data: areas } }],
  };
  return <ReactEChartsCore echarts={echarts} option={option} opts={{ renderer: 'svg' }} style={{ height: 230 }} notMerge aria-label="Failed attempts per hour" />;
}

export function SeverityChart({ data }: { data: Overview['by_severity'] }) {
  const t = tokens();
  const rows = [...data.rows].reverse();
  const option = {
    animation: false, textStyle: { fontFamily: FONT },
    grid: { left: 84, right: 56, top: 8, bottom: 28 },
    tooltip: { trigger: 'item', backgroundColor: '#fff', borderColor: t.grid, textStyle: { color: t.primary, fontSize: 12, fontFamily: FONT },
      formatter: (p: { name: string; value: number }) => `${p.name}<br/><b>${n(p.value)} failed attempts</b>` },
    xAxis: { type: 'value', splitNumber: 3, axisLabel: { color: t.text, fontSize: 11, formatter: (v: number) => (v >= 1000 ? `${v / 1000}k` : String(v)), fontFamily: FONT }, splitLine: { lineStyle: { color: t.grid } } },
    yAxis: { type: 'category', data: rows.map((r) => r.severity), axisLine: { lineStyle: { color: t.strong } }, axisTick: { show: false }, axisLabel: { color: t.primary, fontSize: 12, fontFamily: FONT } },
    series: [{ type: 'bar', barWidth: 18, data: rows.map((r) => ({ value: r.attempts, itemStyle: { color: t.sev[r.severity] } })),
      label: { show: true, position: 'right', color: t.primary, fontSize: 11, fontFamily: FONT, formatter: (p: { value: number }) => n(p.value) } }],
  };
  return <ReactEChartsCore echarts={echarts} option={option} opts={{ renderer: 'svg' }} style={{ height: 230 }} notMerge aria-label="Attempts by severity" />;
}
