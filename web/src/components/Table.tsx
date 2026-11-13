import { ArrowDown, ArrowsVertical, ArrowUp } from '@carbon/icons-react';

export type Dir = 'asc' | 'desc';

export function SortTh({ label, k, sort, dir, onSort, num }: { label: string; k: string | null; sort: string; dir: Dir; onSort: (k: string) => void; num?: boolean }) {
  return (
    <th className={num ? 'num' : ''} aria-sort={k && k === sort ? (dir === 'asc' ? 'ascending' : 'descending') : undefined}>
      {k ? (
        <button onClick={() => onSort(k)} aria-label={`Sort by ${label}`}>
          {label} {k === sort ? (dir === 'asc' ? <ArrowUp size={12} /> : <ArrowDown size={12} />) : <ArrowsVertical size={12} />}
        </button>
      ) : label}
    </th>
  );
}

export function Loading() {
  return <div className="state" aria-busy="true"><div className="skeleton" /><br /><div className="skeleton" style={{ width: '70%' }} /></div>;
}

export function ErrorState({ what, msg, onRetry }: { what: string; msg: string; onRetry: () => void }) {
  return (
    <div className="state" role="alert"><h3>Could not load {what}</h3><p>{msg}</p>
      <button className="cds--btn cds--btn--sm cds--btn--tertiary" onClick={onRetry}>Retry</button></div>
  );
}

export function Empty({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="state"><h3>{title}</h3><p>{children}</p></div>;
}

export function PageHeader({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
      <h1 className="page-title" style={{ margin: 0 }}>{title}</h1>
      {children}
    </div>
  );
}
