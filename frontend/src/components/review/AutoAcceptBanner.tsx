import { useReadOnly } from './readOnly'

interface Props {
  count: number
  threshold: number
  onUndo: () => void
}

export default function AutoAcceptBanner({ count, threshold, onUndo }: Props) {
  const readOnly = useReadOnly()
  if (count === 0) return null
  return (
    <div className="auto-banner">
      <span className="auto-icon">⚡</span>
      <span className="auto-text">
        <strong>{count} high-confidence entities</strong> auto-accepted (≥ {threshold}% confidence).
        Review the ambiguous middle below.
      </span>
      {!readOnly && <button className="link" onClick={onUndo}>Undo all</button>}
    </div>
  )
}
