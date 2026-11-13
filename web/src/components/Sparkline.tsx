/** Inline SVG sparkline. Draws what it is given; no smoothing, no animation. */
export function Sparkline({ data, width = 120, height = 28, label }: { data: number[]; width?: number; height?: number; label: string }) {
  if (!data.length) return null;
  const max = Math.max(...data, 1);
  const step = data.length > 1 ? (width - 2) / (data.length - 1) : 0;
  const pts = data.map((v, i) => `${(1 + i * step).toFixed(1)},${(height - 2 - (v / max) * (height - 4)).toFixed(1)}`).join(' ');
  return (
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={label}>
      <polyline points={pts} fill="none" stroke="var(--sla-teal)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
