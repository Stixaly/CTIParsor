/**
 * Side panel that displays the body of a single rule.
 * The body is loaded only on open (`include_body` is opt-in because bodies
 * weigh 219 MB on a real report). The license is displayed prominently
 * because a `none` license forbids redistribution.
 */
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { X, ExternalLink } from 'lucide-react'
import { lookupRules } from '../../api/client'

/** Rule bodies are not all small: the mthcht corpus averages ~176 KB per rule,
 *  and one measured 825,817 characters. Rendering that in a single <pre> on
 *  open is what this cap avoids — the rest is one click away. */
const BODY_PREVIEW_CHARS = 20000

export default function RuleBodyDrawer({
  ruleId,
  onClose,
}: {
  ruleId: string | null
  onClose: () => void
}) {
  const [showFull, setShowFull] = useState(false)
  const { data, isLoading, isError } = useQuery({
    queryKey: ['rule-body', ruleId],
    // `enabled` already gates on ruleId, but the closure cannot narrow it —
    // the empty array is unreachable and keeps the call type-safe.
    queryFn: () => lookupRules(ruleId ? [ruleId] : [], true),
    enabled: !!ruleId,
  })

  // Collapse again on every new rule, or the second rule opens expanded because
  // the first one was.
  useEffect(() => { setShowFull(false) }, [ruleId])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  if (ruleId === null) {
    return null
  }

  const rule = data?.rules?.[0]

  const metaSegments: string[] = []
  if (rule) {
    metaSegments.push(rule.corpus)
    metaSegments.push(rule.format)
    metaSegments.push(rule.severity)
    if (rule.platform) {
      metaSegments.push(rule.platform)
    }
  }
  const metaLine = metaSegments.join(' · ')

  const isNoneLicense = rule?.license === 'none'

  return (
    <>
      <div
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 59,
          background: 'rgba(0,0,0,0.28)',
        }}
        onClick={onClose}
      />
      <div
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 'min(680px, 92vw)',
          zIndex: 60,
          background: 'var(--bg)',
          borderLeft: '1px solid var(--rule)',
          boxShadow: '-8px 0 24px rgba(0,0,0,0.18)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '16px 20px 12px',
            borderBottom: '1px solid var(--rule-soft)',
            flexShrink: 0,
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 12,
            }}
          >
            <div style={{ minWidth: 0, flex: 1 }}>
              <div
                style={{
                  fontSize: 15,
                  fontWeight: 600,
                  color: 'var(--ink)',
                  lineHeight: 1.3,
                  wordBreak: 'break-word',
                }}
              >
                {rule ? rule.title || rule.id : ruleId}
              </div>
              {rule && (
                <div
                  style={{
                    fontSize: 11.5,
                    color: 'var(--ink-3)',
                    marginTop: 4,
                    lineHeight: 1.4,
                  }}
                >
                  {metaLine}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                padding: 4,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--ink-2)',
                flexShrink: 0,
              }}
              aria-label="Close"
            >
              <X size={16} />
            </button>
          </div>

          {rule && (
            <div style={{ marginTop: 10 }}>
              <div
                style={{
                  padding: '6px 10px',
                  borderRadius: 6,
                  fontSize: 11.5,
                  ...(isNoneLicense
                    ? {
                        color: 'var(--ink)',
                        border: '1px solid var(--warn)',
                        background: 'transparent',
                      }
                    : {
                        border: '1px solid var(--rule)',
                        color: 'var(--ink-2)',
                      }),
                }}
              >
                {isNoneLicense
                  ? 'Licence: none — ALL RIGHTS RESERVED. Local coverage only, do not redistribute.'
                  : `Licence: ${rule.license}`}
              </div>
            </div>
          )}

          {rule && rule.source_ref.startsWith('http') && (
            <a
              href={rule.source_ref}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                marginTop: 8,
                fontSize: 12,
                color: 'var(--accent)',
                textDecoration: 'none',
              }}
            >
              <ExternalLink size={12} />
              Open source
            </a>
          )}

          {rule && rule.techniques.length > 0 && (
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 4,
                marginTop: 10,
              }}
            >
              {rule.techniques.map((t) => (
                <span
                  key={t}
                  style={{
                    fontFamily: 'monospace',
                    fontSize: 10.5,
                    color: 'var(--accent)',
                    background: 'var(--accent-soft)',
                    padding: '1px 6px',
                    borderRadius: 4,
                  }}
                >
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>

        <div style={{ flex: 1, overflow: 'auto' }}>
          {isLoading ? (
            <div
              style={{
                padding: '16px 20px',
                fontSize: 13,
                color: 'var(--ink-3)',
              }}
            >
              Loading rule…
            </div>
          ) : isError ? (
            <div
              style={{
                padding: '16px 20px',
                fontSize: 13,
                color: 'var(--no)',
              }}
            >
              Could not load this rule.
            </div>
          ) : rule === undefined ? (
            <div
              style={{
                padding: '16px 20px',
                fontSize: 13,
                color: 'var(--ink-3)',
              }}
            >
              This rule is no longer in the store.
            </div>
          ) : rule.raw === '' ? (
            <div
              style={{
                padding: '16px 20px',
                fontSize: 13,
                color: 'var(--ink-4)',
              }}
            >
              (this rule has no stored body)
            </div>
          ) : (
            <pre
              style={{
                fontSize: 12,
                fontFamily: 'monospace',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                lineHeight: 1.5,
                margin: 0,
                padding: '12px 16px',
                background: 'var(--bg-soft)',
              }}
            >
              {showFull || rule.raw.length <= BODY_PREVIEW_CHARS
                ? rule.raw
                : rule.raw.slice(0, BODY_PREVIEW_CHARS)}
              {!showFull && rule.raw.length > BODY_PREVIEW_CHARS && (
                <>
                  {'\n\n'}
                  <button
                    onClick={() => setShowFull(true)}
                    style={{
                      fontFamily: 'inherit', fontSize: 11.5, cursor: 'pointer',
                      background: 'var(--bg-elev)', color: 'var(--ink-2)',
                      border: '1px solid var(--rule)', borderRadius: 6,
                      padding: '4px 10px',
                    }}
                  >
                    Show the remaining {(rule.raw.length - BODY_PREVIEW_CHARS).toLocaleString()}
                    {' '}characters
                  </button>
                </>
              )}
            </pre>
          )}
        </div>
      </div>
    </>
  )
}
