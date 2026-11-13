/** ECharts cannot read CSS variables, so resolve the Carbon tokens once at runtime. */
export function tokens() {
  const s = getComputedStyle(document.documentElement);
  const v = (name: string, fb: string) => s.getPropertyValue(name).trim() || fb;
  return {
    line: v('--cds-interactive', '#0f6e56'),
    text: v('--cds-text-secondary', '#525252'),
    primary: v('--cds-text-primary', '#161616'),
    grid: v('--cds-border-subtle', '#e0e0e0'),
    strong: v('--cds-border-strong', '#8d8d8d'),
    fill: v('--cds-layer-accent', '#e8e8e8'),
    sev: {
      Critical: v('--sev-critical-fg', '#b3202a'), High: v('--sev-high-fg', '#a8470a'),
      Medium: v('--sev-medium-fg', '#7a5a00'), Low: v('--sev-low-fg', '#525252'), 'No incident': v('--cds-border-strong', '#8d8d8d'),
    } as Record<string, string>,
  };
}
export const FONT = 'IBM Plex Sans, system-ui, sans-serif';
