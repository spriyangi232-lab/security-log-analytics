import { useEffect, useState } from 'react';
import { api, type Overview, type Rules } from '../api/client';
import { n } from '../lib/format';

const go = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });

export function TopBar() {
  return (
    <header className="land__bar">
      <div className="land__bar-in">
        <a className="land__brand" href="#/">Security Log Analytics</a>
        <nav className="land__links" aria-label="Sections">
          <button onClick={() => go('how')}>How it works</button>
          <button onClick={() => go('features')}>What you get</button>
          <button onClick={() => go('explain')}>How scores work</button>
          <button onClick={() => go('standards')}>Standards</button>
          <button onClick={() => go('limits')}>Limits</button>
          <button onClick={() => go('faq')}>FAQ</button>
        </nav>
        <div className="land__actions">
          <a className="btn btn--secondary btn--sm" href="#/overview">Try the demo</a>
          <a className="btn btn--primary btn--sm" href="#/upload">Upload a log</a>
        </div>
      </div>
    </header>
  );
}

const FAQ: [string, string][] = [
  ['Which logs can I upload?', 'OpenSSH (sshd) syslog files, .log or .txt, up to 300 MB. Syslog lines carry no year, so you enter it when you upload. Other formats such as web server or Windows logs are not supported yet.'],
  ['Where does my data go?', 'The file is analysed on the server that runs this application and the upload is deleted once the analysis finishes. The results are kept, including the raw log lines behind each finding, so you can check the evidence yourself.'],
  ['Do I need to install anything?', 'No. There is no agent to install on your servers. You upload a file you already have.'],
  ['How accurate are the detections?', 'The detection rules are deliberately simple and explainable, so an analyst can reproduce every finding from the evidence shown. Simple rules can raise false alarms. Treat the output as a prioritised starting point for an analyst, not a verdict.'],
  ['Is this a SIEM?', 'No. A SIEM collects logs continuously from many systems. This analyses a log file you give it and explains what it found. It does not replace a SIEM.'],
  ['What does the forecast do with short logs?', 'It refuses. Under 7 days of history there is not enough data, and the page says so instead of guessing. Even with enough data, it only names a trend when it passes its own sanity checks.'],
];

export function Landing() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [rules, setRules] = useState<Rules | null>(null);
  useEffect(() => {
    api.datasets().then((d) => (d.length ? api.overview(d[0].id, 'all') : null)).then((o) => o && setOv(o)).catch(() => setOv(null));
    api.rules().then(setRules).catch(() => setRules(null));
  }, []);
  const cell = (k: string) => ov?.cells.find((c) => c.key === k);

  return (
    <div className="land">
      <TopBar />

      <section className="hero">
        <div className="hero__in">
          <div>
            <div className="eyebrow">SECURITY LOG ANALYTICS</div>
            <h1>Turn raw server logs into a ranked list of what to fix.</h1>
            <p className="hero__sub">
              Upload an SSH log. See who is attacking, the incidents they caused, the security controls that failed and the reports an auditor expects, with the rule behind every number.
            </p>
            <div className="hero__cta">
              <a className="btn btn--primary" href="#/upload">Upload a log</a>
              <a className="btn btn--secondary" href="#/overview">Try the demo</a>
            </div>
            <p className="hero__note">The demo opens a real public log, read-only. OpenSSH logs are supported today.</p>
          </div>
          <figure className="shot" style={{ margin: 0 }}>
            <img src={`${import.meta.env.BASE_URL}img/overview.png`} alt="The Overview screen showing failed attempts, source IPs, incidents and a time series chart" />
            <figcaption>The Overview screen, on the public Loghub OpenSSH sample.</figcaption>
          </figure>
        </div>
      </section>

      {ov && (
        <section className="sec sec--gray" aria-label="Results on the sample log">
          <div className="sec__in">
            <div className="eyebrow">WHAT IT FOUND IN A REAL LOG</div>
            <h2>One public log. Four weeks of attacks.</h2>
            <p className="sec__lead">
              These numbers are read live from the analysed sample ({ov.trust.filename}, {n(ov.trust.lines_total)} lines, {ov.trust.period_start.slice(0, 10)} to {ov.trust.period_end.slice(0, 10)}).
              It is public research data, not customer data.
            </p>
            <div className="facts">
              <div><b>{n(cell('failed_attempts')?.value ?? 0)}</b><span>failed login attempts</span></div>
              <div><b>{n(cell('unique_ips')?.value ?? 0)}</b><span>different source IP addresses</span></div>
              <div><b>{n(cell('high_critical')?.value ?? 0)}</b><span>High or Critical incidents</span></div>
              <div><b>{cell('controls_effective')?.value ?? 0} of {cell('controls_effective')?.of ?? 0}</b><span>security controls tested as effective</span></div>
            </div>
          </div>
        </section>
      )}

      <section className="sec" id="how">
        <div className="sec__in">
          <div className="eyebrow">HOW IT WORKS</div>
          <h2>From a raw log file to a ranked list of what to do.</h2>
          <p className="sec__lead">Three steps. You do the first one.</p>
          <div className="steps">
            <div><span className="no">01</span><h3>Upload a log</h3><p>Drop in an OpenSSH log file. Every line is read, and the screen tells you how many lines were understood and how many were not.</p></div>
            <div><span className="no">02</span><h3>Detect and score</h3><p>Five detection rules look for brute force, password spraying, distributed attacks, a login that succeeded after many failures, and scanning. Each source IP gets a 0 to 100 risk score.</p></div>
            <div><span className="no">03</span><h3>Act and report</h3><p>Every finding comes with a recommended action and a response urgency. Word, Excel and PowerPoint reports are generated for the people who need them.</p></div>
          </div>
        </div>
      </section>

      <section className="sec sec--gray" id="features">
        <div className="sec__in">
          <div className="eyebrow">WHAT YOU GET</div>
          <h2>The screens a security analyst works in.</h2>
          <p className="sec__lead">The menu follows the work: watch, respond, check, report.</p>
          <div className="split">
            <dl className="deflist">
              <div><dt>Monitor</dt><dd><b>Overview, Attackers, Targeted accounts.</b> Volume over time, who is attacking, and which usernames they try.</dd></div>
              <div><dt>Respond</dt><dd><b>Incidents.</b> Each one with its severity, response priority, the rule that fired and the raw evidence.</dd></div>
              <div><dt>Assure</dt><dd><b>Controls, Forecast.</b> Audit-style tests with the population tested and exceptions found, and a forecast that says when it cannot be trusted.</dd></div>
              <div><dt>Output</dt><dd><b>Reports.</b> A client report, an executive deck, a control workpaper, a runbook, and data exports.</dd></div>
            </dl>
            <figure className="shot" style={{ margin: 0 }}>
              <img src={`${import.meta.env.BASE_URL}img/incidents.png`} alt="The Incidents screen with a detail panel open" />
              <figcaption>An incident with its severity, response target and recommended action.</figcaption>
            </figure>
          </div>
        </div>
      </section>

      <section className="sec" id="explain">
        <div className="sec__in">
          <div className="eyebrow">NO BLACK BOX</div>
          <h2>Every score shows how it was calculated.</h2>
          <p className="sec__lead">
            Each source IP gets a risk score from 0 to 100, built from six parts with fixed weights. Open any attacker and you see its points for each part. The formula is the same for everyone and is shown on screen. The weights are expert-judgement settings, not values calibrated on a large data set, so treat the score as a way to rank, not as a probability.
          </p>
          {rules?.risk_components && rules.risk_weights ? (
            <table className="mini">
              <thead><tr><th>Part of the score</th><th>How it is measured</th><th className="num">Weight</th></tr></thead>
              <tbody>
                {rules.risk_components.map((c) => (
                  <tr key={c.key}><td><b>{c.label}</b><br />{c.meaning}</td><td className="f">{c.formula}</td><td className="num">{Math.round((rules.risk_weights?.[c.key] ?? 0) * 100)}%</td></tr>
                ))}
              </tbody>
            </table>
          ) : null}
          <p className="caption" style={{ marginTop: '0.75rem' }}>Severity (Critical, High, Medium, Low) is separate: it comes from the detection rule. Priority (P1 to P4) is the response urgency.</p>
        </div>
      </section>

      <section className="sec sec--gray" id="standards">
        <div className="sec__in">
          <div className="eyebrow">STANDARDS</div>
          <h2>Findings reference the frameworks auditors use.</h2>
          <p className="sec__lead">Output is mapped to public frameworks. Mapped means referenced. It does not mean certified, audited or compliant.</p>
          <div className="two">
            <div>
              <h3>MITRE ATT&amp;CK techniques used</h3>
              <ul>
                {(rules?.detection ?? []).map((r) => <li key={r.id}><span className="mono">{r.technique_id}</span> {r.technique}</li>)}
              </ul>
            </div>
            <div>
              <h3>Frameworks referenced</h3>
              <ul>
                <li>ISO/IEC 27001:2022 Annex A, on all 9 control tests</li>
                <li>NIST Cybersecurity Framework 2.0, on the control tests where a matching function exists</li>
                <li>ITIL incident, problem and change registers, with response targets by priority</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="sec" id="limits">
        <div className="sec__in">
          <div className="eyebrow">LIMITS</div>
          <h2>What it is, and what it is not.</h2>
          <p className="sec__lead">A tool you can trust says where it stops.</p>
          <div className="two">
            <div>
              <h3>What it does</h3>
              <ul>
                <li>Analyses an OpenSSH log file you upload</li>
                <li>Explains every finding with the rule and the raw lines</li>
                <li>Reports gaps in the log and lines it could not read</li>
                <li>Refuses to forecast when there is not enough data</li>
              </ul>
            </div>
            <div>
              <h3>What it does not do</h3>
              <ul>
                <li>It is not a live SIEM and does not collect logs continuously</li>
                <li>It reads OpenSSH logs only, other formats are not supported yet</li>
                <li>It does not block anything. It recommends actions for a person to take</li>
                <li>Its rules are simple and can raise false alarms</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="sec sec--gray" id="faq">
        <div className="sec__in">
          <div className="eyebrow">FAQ</div>
          <h2>Questions people ask first.</h2>
          <div className="faq" style={{ marginTop: '2rem' }}>
            {FAQ.map(([q, a]) => <details key={q}><summary>{q}</summary><p>{a}</p></details>)}
          </div>
        </div>
      </section>

      <section className="cta">
        <div className="cta__in">
          <h2>See it on a real log.</h2>
          <div className="hero__cta">
            <a className="btn btn--primary" href="#/upload">Upload a log</a>
            <a className="btn btn--secondary" href="#/overview">Try the demo</a>
          </div>
        </div>
      </section>

      <footer className="foot">
        <div className="foot__in">
          <div className="foot__cols">
            <div><b style={{ fontSize: '1rem' }}>Security Log Analytics</b><p style={{ color: 'var(--cds-text-secondary)', maxWidth: '22rem', lineHeight: 1.6 }}>Explainable analysis of server logs, from raw lines to audit-ready reports.</p></div>
            <div><h4>Product</h4><ul><li><a href="#/overview">Demo</a></li><li><button onClick={() => go('features')}>What you get</button></li><li><button onClick={() => go('limits')}>Limits</button></li></ul></div>
            <div><h4>Learn</h4><ul><li><button onClick={() => go('how')}>How it works</button></li><li><button onClick={() => go('explain')}>How scores work</button></li><li><button onClick={() => go('faq')}>FAQ</button></li></ul></div>
            <div><h4>Start</h4><ul><li><a href="#/upload">Upload a log</a></li><li><a href="#/overview">Try the demo</a></li></ul></div>
          </div>
          <p className="foot__legal">
            Sample data: Loghub OpenSSH log (public research dataset, Zhu et al., Loghub: A Large Collection of System Log Datasets). Not customer data.<br />
            Built by Priyangi Singh Chouhan as a portfolio project.
          </p>
        </div>
      </footer>
    </div>
  );
}
