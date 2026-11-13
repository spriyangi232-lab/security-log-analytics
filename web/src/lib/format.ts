export const n = (v: number) => v.toLocaleString('en-US');
export const dt = (s: string) => s.slice(0, 16).replace('T', ' ');
export const day = (s: string) => s.slice(0, 10);
export const RANGE_LABEL = { '24h': 'previous 24 hours', '7d': 'previous 7 days', all: '' } as const;
