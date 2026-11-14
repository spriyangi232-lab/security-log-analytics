import { useEffect, useState } from 'react';
import { Header, HeaderName, Select, SelectItem } from '@carbon/react';
import { api, FIX, type DatasetSummary, type Range, type Rules } from './api/client';
import { Overview } from './pages/Overview';
import { Attackers } from './pages/Attackers';
import { Accounts } from './pages/Accounts';
import { Incidents } from './pages/Incidents';
import { Controls } from './pages/Controls';
import { Forecast } from './pages/Forecast';
import { Reports } from './pages/Reports';
import { Upload } from './pages/Upload';
import { Landing } from './pages/Landing';

type Route = { path: string; label: string } | null;
const NAV: { cat: string; items: { label: string; path?: string }[] }[] = [
  { cat: 'Data', items: [{ label: 'Upload logs', path: '/upload' }] },
  { cat: 'Monitor', items: [{ label: 'Overview', path: '/overview' }, { label: 'Attackers', path: '/attackers' }, { label: 'Targeted accounts', path: '/accounts' }] },
  { cat: 'Respond', items: [{ label: 'Incidents', path: '/incidents' }] },
  { cat: 'Assure', items: [{ label: 'Controls', path: '/controls' }, { label: 'Forecast', path: '/forecast' }] },
  { cat: 'Output', items: [{ label: 'Reports', path: '/reports' }, { label: 'Settings' }] },
];
const hashPath = () => window.location.hash.replace(/^#/, '') || '/';

export default function App() {
  const [datasets, setDatasets] = useState<DatasetSummary[] | null>(null);
  const [dataset, setDataset] = useState<string>('');
  const [range, setRange] = useState<Range>('7d');
  const [selected, setSelected] = useState<string | null>(null);
  const [rules, setRules] = useState<Rules | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [path, setPath] = useState(hashPath());
  void (null as Route);

  const loadDatasets = (select?: string) =>
    api.datasets().then((d) => { setDatasets(d); setDataset((cur) => select ?? (cur && d.some((x) => x.id === cur) ? cur : d[0]?.id ?? '')); }).catch((e) => setErr(e.message));
  useEffect(() => {
    loadDatasets();
    api.rules().then(setRules).catch(() => setRules(null));
    const h = () => { setPath(hashPath()); setSelected(null); };
    window.addEventListener('hashchange', h);
    return () => window.removeEventListener('hashchange', h);
  }, []);
  useEffect(() => setSelected(null), [dataset]);

  const page = () => {
    switch (path) {
      case '/upload': return <Upload onDone={(id) => { loadDatasets(id); window.location.hash = '#/'; }} onRefresh={() => loadDatasets()} />;
      case '/attackers': return <Attackers dataset={dataset} range={range} onRange={setRange} selected={selected} onSelect={setSelected} rules={rules} />;
      case '/accounts': return <Accounts dataset={dataset} range={range} onRange={setRange} />;
      case '/incidents': return <Incidents dataset={dataset} range={range} onRange={setRange} rules={rules} />;
      case '/forecast': return <Forecast dataset={dataset} />;
      case '/reports': return <Reports dataset={dataset} />;
      case '/controls': return <Controls dataset={dataset} />;
      default: return <Overview dataset={dataset} range={range} onRange={setRange} selected={selected} onSelect={setSelected} rules={rules} />;
    }
  };

  if (path === '/' || path === '/welcome') return <Landing />;

  return (
    <>
      <Header aria-label="Security Log Analytics">
        <HeaderName href="#/overview" prefix="">Security Log Analytics</HeaderName>
        <div className="header-right">
          {datasets && datasets.length > 0 && (
            <Select id="dataset" size="sm" labelText="Dataset" hideLabel value={dataset} onChange={(e) => setDataset(e.target.value)}>
              {datasets.map((d) => <SelectItem key={d.id} value={d.id} text={d.filename} />)}
            </Select>
          )}
        </div>
      </Header>
      <div className="app">
        <nav className="app__nav" aria-label="Main">
          {NAV.map((g) => (
            <div key={g.cat} role="group" aria-label={g.cat}>
              <div className="nav-cat">{g.cat}</div>
              {g.items.map((i) => i.path
                ? <a key={i.label} className="nav-item" href={`#${i.path}`} aria-current={path === i.path ? 'page' : undefined}>{i.label}</a>
                : <a key={i.label} className="nav-item" aria-disabled="true" title="Not built yet" tabIndex={-1}>{i.label}</a>)}
            </div>
          ))}
        </nav>
        <div className="app__col">
        {FIX && (
          <div className="demo-note" role="note">
            Read-only online demo: real results from the public Loghub OpenSSH log (655,147 lines), saved with the site.
            Uploads are off. Run the app locally to analyse your own log.
          </div>
        )}
        <main className="app__main">
          {err && <div className="app__content"><div className="state" role="alert"><h3>The analytics service is not reachable</h3><p>{err}. Start it with <code>uvicorn api.main:app</code> and reload.</p></div></div>}
          {!err && datasets && datasets.length === 0 && path !== '/upload' && (
            <div className="app__content"><div className="state"><h3>No datasets yet</h3>
              <p>Open <a href="#/upload">Upload logs</a> in the menu and add an OpenSSH log file.</p></div></div>
          )}
          {!err && !datasets && <div className="app__content"><div aria-busy="true" className="skeleton" style={{ width: 200 }} /></div>}
          {path === '/upload' ? page() : dataset && page()}
        </main>
        </div>
      </div>
    </>
  );
}
