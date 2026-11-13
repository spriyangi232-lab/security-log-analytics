import type { Range, Rules } from '../api/client';
import { AttackersTable } from '../components/AttackersTable';
import { DetailPane } from '../components/DetailPane';
import { RangeControl } from '../components/TrustBar';
import { PageHeader } from '../components/Table';

export function Attackers({ dataset, range, onRange, selected, onSelect, rules }: {
  dataset: string; range: Range; onRange: (r: Range) => void; selected: string | null; onSelect: (ip: string | null) => void; rules: Rules | null;
}) {
  return (
    <>
      <div className="app__content">
        <PageHeader title="Attackers"><RangeControl range={range} onRange={onRange} /></PageHeader>
        <AttackersTable dataset={dataset} range={range} selected={selected} onSelect={onSelect} rules={rules} initialSize={25} hideTitle />
      </div>
      {selected && <DetailPane dataset={dataset} ip={selected} rules={rules} onClose={() => onSelect(null)} />}
    </>
  );
}
