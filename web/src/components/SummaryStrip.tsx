import { Toggletip, ToggletipButton, ToggletipContent } from '@carbon/react';
import { Information } from '@carbon/icons-react';
import type { Overview, Range } from '../api/client';
import { n, RANGE_LABEL } from '../lib/format';
import { Sparkline } from './Sparkline';

const HELP: Record<string, string> = {
  failed_attempts: 'Failed password attempts in the selected range. A line saying "repeated N times" counts N.',
  unique_ips: 'Distinct source IP addresses behind those failed attempts.',
  high_critical: 'Incidents rated High or Critical that started in the selected range.',
  targeted_accounts: 'Distinct usernames that received at least one failed attempt.',
  controls_effective: 'Audit-style control tests whose result is Effective, out of all tests run on this dataset.',
};

function Delta({ pct, previous, range, note }: { pct: number | null | undefined; previous: number | null | undefined; range: Range; note: string }) {
  if (range === 'all') return <span title={note}>No previous period</span>;
  if (pct == null) return <span title={note}>{previous == null ? 'No previous period' : 'Not compared (see note)'}</span>;
  const sign = pct > 0 ? '+' : pct < 0 ? '−' : '';
  return <span title={note}>{`${sign}${Math.abs(pct).toLocaleString('en-US', { maximumFractionDigits: 1 })}% vs ${RANGE_LABEL[range]}`}</span>;
}

export function SummaryStrip({ data, range }: { data: Overview; range: Range }) {
  return (
    <>
    <section className="panel strip band" aria-label="Summary">
      {data.cells.map((c) => (
        <div className="cell" key={c.key}>
          <div className="cell__label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {c.label}
            <Toggletip align="bottom-left">
              <ToggletipButton label={`How is ${c.label} calculated?`}>
                <Information size={14} />
              </ToggletipButton>
              <ToggletipContent>
                <p>{HELP[c.key]}</p>
              </ToggletipContent>
            </Toggletip>
          </div>
          <div className="cell__value">
            {n(c.value)}
            {c.of != null && <small>of {n(c.of)} tested</small>}
          </div>
          <div className="cell__delta">
            {c.key === 'controls_effective' ? 'Whole dataset' : <Delta pct={c.change_pct} previous={c.previous} range={range} note={data.change_note} />}
          </div>
          <div className="cell__spark">{c.spark && <Sparkline data={c.spark} label={`${c.label} trend`} />}</div>
        </div>
      ))}
    </section>
    <p className="strip-note">{data.change_note}</p>
    </>
  );
}
