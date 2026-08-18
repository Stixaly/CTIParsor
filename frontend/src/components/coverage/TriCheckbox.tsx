import { markOf } from '../../hooks/useRuleSelection'

/** The tri-state selection marker used at every scope level: format board card,
 *  tactic column header, matrix cell, drill-in format column, rule row and
 *  export table row. */
export default function TriCheckbox({ sel, total, size = 14, title, onToggle }: {
  sel: number
  total: number
  /** 14 in cells and column headers, 16 on board cards and export table rows. */
  size?: 14 | 16
  title?: string
  /** When given, click toggles the scope and NEVER bubbles to the row/cell —
   *  the enclosing cell has its own click action (drill-in), and the design
   *  requires stopPropagation on every nested checkbox. */
  onToggle?: (e: React.MouseEvent) => void
}) {
  const mark = markOf(sel, total)

  // Visual states driven by tokens, not hardcoded hex — the prototype's partial
  // fill (#C98F80) maps to a color-mix of the accent (ADR-0022).
  let background: string
  let border: string
  if (total === 0) {
    background = 'var(--bg-soft)'
    border = '1px solid var(--rule-soft)'
  } else if (mark === '✓') {
    background = 'var(--accent)'
    border = '1px solid var(--accent)'
  } else if (mark === '–') {
    background = 'color-mix(in oklab, var(--accent) 45%, var(--bg-elev))'
    border = '1px solid var(--accent)'
  } else {
    background = 'var(--bg-elev)'
    border = '1px solid var(--rule)'
  }

  const style: React.CSSProperties = {
    width: size,
    height: size,
    borderRadius: 3,
    color: '#fff',
    fontSize: size === 16 ? 9 : 8,
    fontWeight: 700,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
    userSelect: 'none',
    background,
    border,
    ...(onToggle && total > 0 ? { cursor: 'pointer' } : {}),
  }

  const handleClick = onToggle && total > 0
    ? (e: React.MouseEvent) => { e.stopPropagation(); onToggle(e) }
    : undefined

  return (
    <span style={style} title={title} onClick={handleClick}>
      {mark}
    </span>
  )
}
