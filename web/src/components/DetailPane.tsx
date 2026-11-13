import { useEffect, useState } from 'react';
import { Button, Toggletip, ToggletipButton, ToggletipContent } from '@carbon/react';
import { Close, Information } from '@carbon/icons-react';
import { api, type AttackerDetail, type AttackerEvents, type Rules } from '../api/client';
import { dt, n } from '../lib/format';
import { SeverityBadge, TechniqueTag } from './Badges';

export function DetailPane({ dataset, ip, rules, onClose }: { dataset: string; ip: string; rules: Rules | null; onClose: () => void }) {
  const [d, setD] = useState<AttackerDetail | null>(null);
  const [ev, setEv] = useState<AttackerEvents | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setD(null); setEv(null); setErr(null);
    Promise.all([api.attacker(dataset, ip), api.events(dataset, ip)])
      .then(([a, e]) => { if (live) { setD(a); setEv(e); } })
      .catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [dataset, ip]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  const tname = (id: string) => rules?.detection.find((r) => r.technique_id === id)?.technique;
  return (
    <aside className="app__detail" aria-label={`Details for ${ip}`}>
      <div className="detail">
        <div className="detail__head">
          <h2 className="mono" style={{ fontSize: '1.125rem', margin: 0, fontWeight: 600 }}>{ip}</h2>
          <Button kind="ghost" size="sm" hasIconOnly renderIcon={Close} iconDescription="Close details" onClick={onClose} />
        </div>
        {err && <p role="alert">Could not load details: {err}</p>}
        {!d && !err && <div aria-busy="true"><div className="skeleton" style={{ width: '60%' }} /><br /><div className="skeleton" /><br /><div className="skeleton" style={{ width: '80%' }} /></div>}
        {d && (
          <>
            <SeverityBadge severity={d.severity} />
            <h3>Why this severity</h3>
            <p>{d.reason}</p>
            <h3>Recommended action</h3>
            <p>{d.action}</p>
            {d.techniques.length > 0 && (
              <>
                <h3>MITRE ATT&amp;CK technique</h3>
                <p>{d.techniques.map((t) => <span key={t} style={{ marginRight: 6 }}><TechniqueTag id={t} name={tname(t)} /> {tname(t)}</span>)}</p>
              </>
            )}
            <h3 style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              Risk score
              <Toggletip align="bottom-left">
                <ToggletipButton label="How is the risk score calculated?"><Information size={14} /></ToggletipButton>
                <ToggletipContent><p>{d.risk.formula}</p></ToggletipContent>
              </Toggletip>
            </h3>
            <div><span className="score">{d.risk.score.toFixed(1)}</span> <span style={{ fontSize: '0.8125rem' }}>of 100, tier {d.risk.tier}</span></div>
            <p style={{ color: 'var(--cds-text-secondary)' }}>Risk score and severity are separate: the score ranks the IP, severity comes from the detection rules.</p>
            <table>
              <thead><tr><th>Part</th><th className="num">Weight</th><th className="num">Points</th></tr></thead>
              <tbody>
                {d.risk.components.map((c) => (
                  <tr key={c.key} title={`${c.formula}. ${c.meaning}`}>
                    <td>{c.label}</td><td className="num">{(c.weight * 100).toFixed(0)}%</td><td className="num">{c.points.toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {d.incidents.length > 0 && (
              <>
                <h3>Incidents ({d.incidents.length})</h3>
                <table>
                  <thead><tr><th>ID</th><th>Severity</th><th className="num">Attempts</th></tr></thead>
                  <tbody>
                    {d.incidents.slice(0, 8).map((i) => (
                      <tr key={i.incident_id}><td className="mono">{i.incident_id}</td><td><SeverityBadge severity={i.severity} /></td><td className="num">{n(i.attempts)}</td></tr>
                    ))}
                  </tbody>
                </table>
                {d.incidents.length > 8 && <p className="caption">Showing 8 of {d.incidents.length}.</p>}
              </>
            )}
            <h3>Raw log lines</h3>
            {ev && (
              <>
                <pre className="loglines" tabIndex={0} aria-label="Raw log lines">{ev.lines.map((l) => l.raw).join('\n')}</pre>
                <p className="caption">First {ev.shown} of {n(ev.total)} lines from this IP, oldest first. Seen {dt(d.first_seen)} to {dt(d.last_seen)}.</p>
              </>
            )}
          </>
        )}
      </div>
    </aside>
  );
}
