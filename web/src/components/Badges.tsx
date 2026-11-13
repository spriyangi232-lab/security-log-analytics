import type { Severity } from '../api/client';

const CLS: Record<string, string> = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', 'No incident': 'none' };

/** Severity is text plus colour, never colour alone. Priority (P1..P4) is a separate concept and not shown here. */
export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`sev sev--${CLS[severity] ?? 'none'}`}>{severity}</span>;
}

export function TechniqueTag({ id, name }: { id: string; name?: string }) {
  return (
    <span className="tech" title={name ? `MITRE ATT&CK ${id}: ${name}` : `MITRE ATT&CK ${id}`}>
      {id}
    </span>
  );
}
