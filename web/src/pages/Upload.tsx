import { useEffect, useRef, useState } from 'react';
import { Button, FileUploaderDropContainer, FileUploaderItem, InlineNotification, NumberInput, TextInput } from '@carbon/react';
import { api, type Job } from '../api/client';
import { PageHeader } from '../components/Table';

const mb = (b: number) => `${(b / 1048576).toFixed(1)} MB`;

export function Upload({ onDone, onRefresh }: { onDone: (id: string) => void; onRefresh: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [year, setYear] = useState<number>(new Date().getFullYear());
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearInterval(timer.current), []);

  const submit = async () => {
    if (!file) return;
    setBusy(true); setErr(null); setJob(null);
    try {
      let j = await api.upload(file, year, name.trim());
      setJob(j);
      timer.current = window.setInterval(async () => {
        try {
          j = await api.job(j.job_id);
          setJob(j);
          if (j.status === 'done' || j.status === 'failed') { window.clearInterval(timer.current); setBusy(false); if (j.status === 'done') onRefresh(); }
        } catch (e) { window.clearInterval(timer.current); setBusy(false); setErr((e as Error).message); }
      }, 1500);
    } catch (e) { setBusy(false); setErr((e as Error).message); }
  };

  return (
    <div className="app__content">
      <PageHeader title="Upload logs" />
      <section className="panel band" style={{ padding: '1rem 1.25rem', maxWidth: '46rem' }}>
        <h2 className="table-title">Add a log file</h2>
        <p className="caption" style={{ marginBottom: '1rem' }}>
          Supported now: OpenSSH (sshd) syslog files, <b>.log</b> or <b>.txt</b>, up to 300 MB. Syslog lines have no year, so tell us which year the log is from.
          Large files take a minute or two. Other log formats are not supported yet.
        </p>
        {!file ? (
          <FileUploaderDropContainer labelText="Drag a log file here or click to choose" accept={['.log', '.txt']} multiple={false} name="logfile"
            onAddFiles={(_e: unknown, { addedFiles }: { addedFiles: File[] }) => setFile(addedFiles[0] ?? null)} />
        ) : (
          <FileUploaderItem name={`${file.name} (${mb(file.size)})`} status="edit" onDelete={() => { setFile(null); setJob(null); }} />
        )}
        <div style={{ display: 'flex', gap: '1rem', margin: '1rem 0', flexWrap: 'wrap' }}>
          <NumberInput id="year" label="Year of the log" min={1990} max={2100} step={1} value={year} allowEmpty={false}
            helperText="Example: 2015 for the Loghub sample" onChange={(_e: unknown, { value }: { value: number | string }) => setYear(Number(value))} />
          <TextInput id="dsname" labelText="Dataset name (optional)" placeholder="Defaults to the file name" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <Button kind="primary" disabled={!file || busy} onClick={submit}>{busy ? 'Analysing…' : 'Upload and analyse'}</Button>
        {err && <InlineNotification kind="error" title="Upload failed." subtitle={err} lowContrast hideCloseButton />}
        {job && (
          <div style={{ marginTop: '1.25rem' }} aria-live="polite">
            <h3 style={{ fontSize: '0.875rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
              {job.status === 'done' ? 'Analysis complete' : job.status === 'failed' ? 'Analysis failed' : 'Analysing ' + job.filename}
            </h3>
            <pre className="loglines" style={{ maxHeight: '12rem' }}>{job.steps.length ? job.steps.join('\n') : 'Waiting to start…'}</pre>
            {job.status === 'failed' && <InlineNotification kind="error" title="Could not analyse this file." subtitle={job.error ?? ''} lowContrast hideCloseButton />}
            {job.status === 'done' && <p style={{ marginTop: '0.75rem' }}><Button kind="tertiary" size="sm" onClick={() => onDone(job.dataset_id)}>Open the overview</Button></p>}
          </div>
        )}
      </section>
    </div>
  );
}
