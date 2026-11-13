import { ContentSwitcher, Switch } from '@carbon/react';
import type { Overview, Range } from '../api/client';
import { day, dt, n } from '../lib/format';

const RANGES: Range[] = ['24h', '7d', 'all'];

export function RangeControl({ range, onRange }: { range: Range; onRange: (r: Range) => void }) {
  return (
    <div className="trust__range">
      <span id="range-label">Range</span>
      <ContentSwitcher size="sm" selectedIndex={RANGES.indexOf(range)} onChange={(e) => onRange(RANGES[e.index as number])} aria-labelledby="range-label">
        <Switch name="24h" text="24h" />
        <Switch name="7d" text="7d" />
        <Switch name="all" text="All" />
      </ContentSwitcher>
    </div>
  );
}

export function TrustBar({ data }: { data: Overview }) {
  const t = data.trust;
  return (
    <section className="panel trust band" aria-label="Data trust">
      <span className="t">File <b className="mono">{t.filename}</b></span>
      <span className="t">Period <b className="mono">{day(t.period_start)}</b> to <b className="mono">{day(t.period_end)}</b></span>
      <span className="t"><b>{n(t.lines_total)}</b> lines, <b>{t.unparsed_pct.toLocaleString('en-US', { maximumFractionDigits: 2 })}%</b> not understood</span>
      <span className="t">Analysed <b className="mono">{dt(t.last_upload)}</b> UTC</span>
      {t.gaps.length > 0 && (
        <>
          <span className="t">{t.gaps.length} gap{t.gaps.length > 1 ? 's' : ''} with no log lines ({t.gaps.reduce((a, g) => a + g.hours, 0)} h)</span>
        </>
      )}
    </section>
  );
}
