import React from 'react';
import { clsx } from 'clsx';

type Accent = 'default' | 'ember' | 'phosphor' | 'arterial';

interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  accent?: Accent;
  label?: React.ReactNode;
  meta?: React.ReactNode;
  icon?: React.ReactNode;
  as?: 'div' | 'section' | 'article';
}

/**
 * Panel
 * -----
 * Instrument-panel shell with four drawn corner brackets. The two top/bottom-left
 * brackets come from ::before/::after; the two right-side brackets are real spans
 * injected here so all four can animate together on hover.
 */
export function Panel({
  accent = 'default',
  label,
  meta,
  icon,
  className,
  children,
  as = 'div',
  ...rest
}: PanelProps) {
  const Tag = as as any;
  return (
    <Tag
      {...rest}
      className={clsx(
        'panel',
        accent === 'phosphor' && 'panel--phosphor',
        accent === 'arterial' && 'panel--arterial',
        accent === 'ember' && 'panel--ember',
        className,
      )}
    >
      <span className="bracket-tr" aria-hidden />
      <span className="bracket-br" aria-hidden />
      {(label || meta) && (
        <header className="flex items-center justify-between mb-6 pb-3 border-b border-paper/5">
          <h3 className="label flex items-center gap-2 text-paper">
            {icon && <span className="text-primary">{icon}</span>}
            {label}
          </h3>
          {meta && <div className="label text-fog">{meta}</div>}
        </header>
      )}
      {children}
    </Tag>
  );
}
