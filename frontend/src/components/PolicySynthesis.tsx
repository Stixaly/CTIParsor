import type { LastRun, PinRuleStat } from '../types'


const MONO = "'JetBrains Mono', ui-monospace, monospace"
const SERIF = "'Source Serif 4', Georgia, serif"

/**
 * Build a join index keyed by rule string.
 * Returns an empty Map for undefined/null runs, null pin, non-array rules,
 * or entries with a non-string/empty rule. First occurrence wins on duplicates.
 */
export function pinStatIndex(run: LastRun | undefined): Map<string, PinRuleStat> {
  const map = new Map<string, PinRuleStat>()
  if (run === undefined || run === null) return map
  const pin = run.pin
  if (pin === null || pin === undefined) return map
  const rules = pin.rules
  if (!Array.isArray(rules)) return map
  for (const entry of rules) {
    if (entry === null || entry === undefined) continue
    const rule = entry.rule
    if (typeof rule !== 'string' || rule.length === 0) continue
    if (map.has(rule)) continue
    map.set(rule, entry)
  }
  return map
}

/**
 * Compact badge showing what a rule produced on the last run.
 * Returns null when stat is undefined (rule not measured).
 */
export function RuleRunBadge({ stat }: { stat?: PinRuleStat }) {
  if (stat === undefined || stat === null) return null

  const truncated = stat.truncated > 0
  const blocked = stat.blocked ?? 0
  const color = truncated ? 'var(--warn)' : 'var(--accent)'
  const pct = stat.candidates > 0 ? (stat.emitted / stat.candidates) * 100 : 0
  const title = [
    `Last run: ${stat.emitted} of ${stat.candidates} candidate pairs emitted`,
    truncated ? ` (${stat.truncated} cut by the budget)` : '',
    blocked > 0
      ? ` · ${blocked} more blocked by the evidence gate — the report never links those pairs`
      : '',
  ].join('')

  return (
    <div
      title={title}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        fontFamily: MONO,
        fontSize: 11,
        color,
      }}
    >
      <span>
        {stat.emitted} / {stat.candidates}
      </span>
      <div
        style={{
          width: 44,
          height: 3,
          borderRadius: 2,
          background: 'var(--rule)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${pct}%`,
            height: '100%',
            background: color,
            borderRadius: 2,
          }}
        />
      </div>
      {blocked > 0 && (
        <span
          style={{ color: 'var(--ink-3)' }}
          title="Pairs the evidence gate refused"
        >
          ⊘{blocked}
        </span>
      )}
    </div>
  )
}

/** Segmented control — the shape the rest of the Policy page already uses. */
function SegmentGroup({ options, disabled = false }: {
  options: { label: string; active: boolean; onClick: () => void; title?: string }[]
  disabled?: boolean
}) {
  return (
    <div
      style={{
        display: 'inline-flex',
        border: '1px solid var(--rule)',
        borderRadius: 9,
        overflow: 'hidden',
        opacity: disabled ? 0.4 : 1,
        pointerEvents: disabled ? 'none' : 'auto',
      }}
    >
      {options.map((o) => (
        <button
          key={o.label}
          type="button"
          title={o.title}
          onClick={o.onClick}
          style={{
            padding: '4px 12px',
            fontSize: 12,
            fontFamily: MONO,
            border: 'none',
            cursor: 'pointer',
            background: o.active ? 'var(--accent)' : 'transparent',
            color: o.active ? '#fff' : 'var(--ink-3)',
          }}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

/** Named window steps.  A free number field invites typing 50 without
 *  realising that switches the gate off in practice; three steps make the
 *  trade-off legible. */
export const WINDOW_STEPS: { label: string; value: number; hint: string }[] = [
  { label: 'Strict', value: 1, hint: 'same or adjacent sentence' },
  { label: 'Normal', value: 3, hint: 'within three sentences — measured default' },
  { label: 'Wide', value: 10, hint: 'same passage; filters very little' },
]

interface LastRunPanelProps {
  run: LastRun | undefined
  /** How the internal safety ceiling is split across rules. */
  mode: 'fair-share' | 'sequential'
  /** ADR-0027 evidence gate. */
  evidenceOn: boolean
  windowSize: number
  onSelectBudgetMode: (m: 'fair-share' | 'sequential') => void
  onToggleEvidence: (on: boolean) => void
  onSelectWindow: (n: number) => void
}

/**
 * Panel showing the evidence-gate controls and the last run's accounting.
 * No network calls — receives `run` as a prop.
 *
 * `max_pinned_edges` is deliberately NOT exposed: an analyst cannot know the
 * right total ahead of a report they have not read, and the number scales with
 * report size rather than with anything they can judge.  It stays a safety
 * ceiling in the policy.  The evidence window replaces it as the knob, because
 * "how close must two things be in the text before I link them?" is answerable
 * without knowing how big the report is.
 */
export function LastRunPanel({
  run,
  mode,
  evidenceOn,
  windowSize,
  onSelectBudgetMode,
  onToggleEvidence,
  onSelectWindow,
}: LastRunPanelProps) {
  // Provenance label
  let provenance: string
  if (run === undefined || run === null) {
    provenance = 'no run measured yet'
  } else if (run.available === false) {
    provenance = 'last run predates this feature'
  } else {
    const name = run.filename ?? ''
    // A measured run whose job has no filename would otherwise render the
    // dangling label "last run · ".
    provenance = name === ''
      ? 'last run'
      : `last run · ${name.length > 40 ? name.slice(0, 40) + '…' : name}`
  }

  // Mode description
  const modeDesc =
    mode === 'fair-share'
      ? 'Every rule gets an equal share of the budget; small rules are served in full.'
      : 'Rules are served in list order — the first rules can consume the whole budget.'

  const pin = run?.pin ?? null
  const completion = run?.completion ?? null

  // Totals section
  let totalsPct: number | null = null
  if (pin !== null && pin.total_candidates > 0) {
    totalsPct = Math.round((pin.total_emitted / pin.total_candidates) * 100)
  }

  return (
    <div
      style={{
        background: 'var(--bg-elev)',
        border: '1px solid var(--rule)',
        borderRadius: 14,
        padding: 16,
      }}
    >
      {/* a) Title + provenance */}
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          marginBottom: 12,
        }}
      >
        <span
          style={{
            fontFamily: SERIF,
            fontSize: 15,
            fontWeight: 700,
            color: 'var(--ink)',
          }}
        >
          Evidence gate
        </span>
        <span style={{ fontSize: 11, color: 'var(--ink-3)' }}>{provenance}</span>
      </div>

      {/* b) Evidence gate — on/off + window */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <SegmentGroup
          options={[
            { label: 'On', active: evidenceOn, onClick: () => onToggleEvidence(true) },
            { label: 'Off', active: !evidenceOn, onClick: () => onToggleEvidence(false) },
          ]}
        />
        <SegmentGroup
          disabled={!evidenceOn}
          options={WINDOW_STEPS.map((s) => ({
            label: s.label,
            title: s.hint,
            active: windowSize === s.value,
            onClick: () => onSelectWindow(s.value),
          }))}
        />
        <span style={{ fontSize: 11, color: 'var(--ink-3)', fontFamily: MONO }}>
          {evidenceOn ? `±${windowSize} sentence${windowSize > 1 ? 's' : ''}` : ''}
        </span>
      </div>
      <div style={{ fontSize: 11, color: 'var(--ink-3)', marginBottom: 12 }}>
        {evidenceOn
          ? 'A pinned rule only links two objects the report mentions close together. Techniques and mitigations are never gated — they come from ATT&CK mapping, not the text.'
          : 'Every pair of the two types is materialised, whether or not the report links them.'}
      </div>

      {/* c) How the safety ceiling is split */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 11, color: 'var(--ink-3)' }}>Split the ceiling</span>
        <div
          style={{
            display: 'inline-flex',
            border: '1px solid var(--rule)',
            borderRadius: 9,
            overflow: 'hidden',
          }}
        >
          <button
            type="button"
            onClick={() => onSelectBudgetMode('fair-share')}
            style={{
              padding: '4px 12px',
              fontSize: 12,
              fontFamily: MONO,
              border: 'none',
              cursor: 'pointer',
              background: mode === 'fair-share' ? 'var(--accent)' : 'transparent',
              color: mode === 'fair-share' ? '#fff' : 'var(--ink-3)',
            }}
          >
            Fair share
          </button>
          <button
            type="button"
            onClick={() => onSelectBudgetMode('sequential')}
            style={{
              padding: '4px 12px',
              fontSize: 12,
              fontFamily: MONO,
              border: 'none',
              cursor: 'pointer',
              background: mode === 'sequential' ? 'var(--accent)' : 'transparent',
              color: mode === 'sequential' ? '#fff' : 'var(--ink-3)',
            }}
          >
            Sequential
          </button>
        </div>
      </div>
      <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 6 }}>
        {modeDesc}
      </div>

      {/* c) Totals — only if run?.pin exists */}
      {pin !== null ? (
        <div style={{ marginTop: 14 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start' }}>
            <div style={{ paddingRight: 16 }}>
              <div
                style={{
                  fontFamily: SERIF,
                  fontSize: 24,
                  fontWeight: 700,
                  color: 'var(--ink)',
                }}
              >
                {pin.total_emitted}
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>Edges emitted</div>
            </div>
            <div
              style={{
                borderLeft: '1px solid var(--rule-soft)',
                paddingLeft: 16,
                paddingRight: 16,
              }}
            >
              <div
                style={{
                  fontFamily: SERIF,
                  fontSize: 24,
                  fontWeight: 700,
                  color: 'var(--ink-3)',
                }}
              >
                {pin.total_candidates}
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>Candidate pairs</div>
            </div>
            <div style={{ borderLeft: '1px solid var(--rule-soft)', paddingLeft: 16,
                          paddingRight: 16 }}>
              <div
                style={{
                  fontFamily: SERIF,
                  fontSize: 24,
                  fontWeight: 700,
                  color: pin.total_truncated > 0 ? 'var(--warn)' : 'var(--ink-3)',
                }}
              >
                {pin.total_truncated}
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>Cut by budget</div>
            </div>
            {/* Blocked is reported apart from truncated on purpose: "the budget
                ran out" and "the report never links this pair" are different
                verdicts (ADR-0027). */}
            <div style={{ borderLeft: '1px solid var(--rule-soft)', paddingLeft: 16 }}>
              <div
                style={{
                  fontFamily: SERIF,
                  fontSize: 24,
                  fontWeight: 700,
                  color: 'var(--ink-3)',
                }}
                title="Pairs the report never links within the evidence window"
              >
                {pin.total_blocked ?? 0}
              </div>
              <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>Unevidenced</div>
            </div>
          </div>
          {pin.total_candidates > 0 && totalsPct !== null && (
            <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 6 }}>
              {pin.total_emitted} of {pin.total_candidates} candidate pairs materialised (
              {totalsPct}%)
            </div>
          )}
        </div>
      ) : null}

      {/* d) Completion — only if run?.completion exists */}
      {completion !== null ? (
        <div
          style={{
            borderTop: '1px solid var(--rule-soft)',
            marginTop: 12,
            paddingTop: 10,
            fontSize: 11,
            color: 'var(--ink-3)',
          }}
        >
          <span>
            Graph completion: +{completion.transitive_added} transitive, +
            {completion.reference_added} reference, {completion.aliases_merged} aliases
            merged
          </span>
          {completion.capped === true && (
            <span style={{ color: 'var(--warn)' }}> — capped</span>
          )}
        </div>
      ) : null}

      {/* e) Empty state */}
      {(run === undefined || run === null || run.pin === null) && (
        <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 10 }}>
          Run a report to see what each rule produces.
        </div>
      )}
    </div>
  )
}
