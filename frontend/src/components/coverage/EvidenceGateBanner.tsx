import { ShieldCheck } from 'lucide-react'

/**
 * ADR-0030: The coverage panel now serves only rules backed by report evidence.
 * The rarity of the result is the result, not a failure.
 */
export default function EvidenceGateBanner({
  ruleTotal,
  tagTotal,
  untaggedCount,
  corroboratedCount,
  brandCount,
}: {
  ruleTotal: number
  tagTotal: number
  untaggedCount: number
  corroboratedCount: number
  /** Rules admitted only because their title names what the report targets. */
  brandCount: number
}) {
  if (ruleTotal === 0) {
    const body =
      tagTotal === 0
        ? 'This report yielded neither an ATT&CK technique nor a usable observable.'
        : `The ATT&CK tag join proposed ${tagTotal}, none of which contains a value from the report. On a recent campaign that is the expected answer — the indicators are, by construction, absent from public corpora.`

    return (
      <div
        style={{
          border: '1px solid var(--rule)',
          borderRadius: 8,
          padding: '12px 14px',
          background: 'var(--bg-soft)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <ShieldCheck size={15} style={{ color: 'var(--ink-3)', flexShrink: 0 }} />
          <span style={{ fontWeight: 600, color: 'var(--ink)' }}>
            No public rule holds anything this report contains.
          </span>
        </div>
        <p style={{ margin: 0, color: 'var(--ink-2)', fontSize: 13, lineHeight: 1.5 }}>
          {body}
        </p>
        <p style={{ margin: '8px 0 0', color: 'var(--ink-4)', fontSize: 11.5 }}>
          This list is a detection-engineering backlog, not a failure.
        </p>
      </div>
    )
  }

  const segments: React.ReactNode[] = []
  const ruleWord = ruleTotal === 1 ? 'rule' : 'rules'
  segments.push(
    <span key="rules">
      <strong>{ruleTotal}</strong> {ruleWord} with evidence
    </span>,
  )

  if (tagTotal > ruleTotal) {
    segments.push(<span key="sep1" style={{ color: 'var(--ink-4)' }}> · </span>)
    segments.push(<span key="tagged">of {tagTotal} ATT&CK-tagged</span>)
  }

  if (untaggedCount > 0) {
    segments.push(<span key="sep2" style={{ color: 'var(--ink-4)' }}> · </span>)
    segments.push(
      <span
        key="untagged"
        style={{ color: 'var(--accent)' }}
        title="Reached by evidence alone — no YARA rule carries an ATT&CK tag"
      >
        {untaggedCount} untagged
      </span>,
    )
  }

  if (corroboratedCount > 0) {
    segments.push(<span key="sep3" style={{ color: 'var(--ink-4)' }}> · </span>)
    segments.push(
      <span
        key="corroborated"
        style={{ color: 'var(--accent)' }}
        title="At least two distinct report values"
      >
        {corroboratedCount} corroborated
      </span>,
    )
  }

  if (brandCount > 0) {
    segments.push(<span key="sep4" style={{ color: 'var(--ink-4)' }}> · </span>)
    segments.push(
      <span
        key="brand"
        style={{ color: 'var(--ink-3)' }}
        title={
          'Admitted because the rule is ABOUT what this report targets, not because ' +
          'it holds one of its values — the weaker tier, which never corroborates'
        }
      >
        {brandCount} by name
      </span>,
    )
  }

  const pct = tagTotal > 0 ? Math.round((ruleTotal / tagTotal) * 100) : null

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        background: 'var(--bg-soft)',
        border: '1px solid var(--rule)',
        borderRadius: 8,
        padding: '9px 12px',
        fontSize: 13,
        color: 'var(--ink)',
      }}
    >
      {segments}
      {pct !== null && (
        <span
          style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--ink-3)' }}
          title="Share of tagged rules that hold evidence"
        >
          {pct}%
        </span>
      )}
    </div>
  )
}
