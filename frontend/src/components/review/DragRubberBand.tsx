import { createPortal } from 'react-dom'

interface Point { x: number; y: number }

interface Props {
  from: Point
  to: Point
}

export default function DragRubberBand({ from, to }: Props) {
  if (!from || !to) return null
  const dx = to.x - from.x
  const dy = to.y - from.y
  if (Math.hypot(dx, dy) < 8) return null
  const cp1y = from.y + dy * 0.35
  const cp2y = from.y + dy * 0.65
  return createPortal(
    <svg
      className="rc-rubber"
      style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 90, width: '100vw', height: '100vh' }}
    >
      <defs>
        <marker
          id="rc-rubber-arrow"
          viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="6" markerHeight="6"
          orient="auto"
        >
          <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent)" />
        </marker>
      </defs>
      <path
        d={`M ${from.x} ${from.y} C ${from.x} ${cp1y}, ${to.x} ${cp2y}, ${to.x} ${to.y}`}
        fill="none"
        stroke="var(--accent)"
        strokeWidth={2}
        strokeDasharray="6 4"
        markerEnd="url(#rc-rubber-arrow)"
      />
      <circle cx={from.x} cy={from.y} r={5} fill="var(--accent)" />
    </svg>,
    document.body,
  )
}
