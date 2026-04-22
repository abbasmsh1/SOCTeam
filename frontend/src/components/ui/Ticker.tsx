export interface TickerItem {
  label: string;
  value: string | number;
  tone?: 'default' | 'ember' | 'phosphor' | 'arterial' | 'radar';
}

interface TickerProps {
  items: TickerItem[];
}

const toneColor: Record<NonNullable<TickerItem['tone']>, string> = {
  default:  'text-paper/80',
  ember:    'text-primary',
  phosphor: 'text-benign',
  arterial: 'text-malicious',
  radar:    'text-warning',
};

/**
 * Ticker
 * ------
 * Horizontal infinite marquee of tiny status chips. The track is duplicated
 * so that translating by -50% wraps cleanly without a visible seam.
 */
export function Ticker({ items }: TickerProps) {
  if (items.length === 0) return null;
  const row = (keyPrefix: string) =>
    items.map((it, idx) => (
      <div key={`${keyPrefix}-${idx}`} className="flex items-center gap-2">
        <span className="label text-fog">{it.label}</span>
        <span className={`num text-[11px] font-semibold ${toneColor[it.tone ?? 'default']}`}>
          {it.value}
        </span>
        <span className="text-fog/30">·</span>
      </div>
    ));

  return (
    <div className="ticker">
      <div className="ticker__track">
        {row('a')}
        {row('b')}
      </div>
    </div>
  );
}
