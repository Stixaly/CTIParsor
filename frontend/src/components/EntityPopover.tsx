import { useEffect, useRef, useState, useMemo } from 'react'
import { Check, X, Trash2, Search, AlertTriangle } from 'lucide-react'
import type { Entity } from '../types'
import { ENTITY_TYPE_LABELS } from '../types'
import { TYPE_GROUPS, typeSoft, typeInk } from './review/tokens'

// ── constants ─────────────────────────────────────────────────────────────────

const POP_W      = 300
const BODY_MAX_H = 360
const MONO       = "'JetBrains Mono', ui-monospace, monospace"

const APPROX_H_CREATE = 68  + 48 + BODY_MAX_H + 8
const APPROX_H_EDIT   = 110 + 48 + BODY_MAX_H + 8

// ── IoC format validators ─────────────────────────────────────────────────────
// Only covers types that have a strict machine-readable format.
// Named entity types (malware, threat_actor, tool, campaign, …) return null
// — any text is acceptable for those.

interface ValidationResult {
  valid: boolean
  /** Short explanation of the expected format, shown in the warning dialog. */
  hint: string
}

function validateIoC(text: string, type: string): ValidationResult | null {
  const v = text.trim()
  switch (type) {
    case 'ipv4': {
      const parts = v.split('.')
      const ok = parts.length === 4 && parts.every(p => {
        const n = parseInt(p, 10)
        return /^\d+$/.test(p) && n >= 0 && n <= 255
      })
      return { valid: ok, hint: 'Expected format: 192.168.1.1  (four numbers, each 0–255)' }
    }
    case 'ipv6':
      return {
        valid: /^[0-9a-fA-F:]{2,39}$/.test(v) && v.includes(':'),
        hint: 'Expected format: 2001:db8::1  (hex groups separated by :)',
      }
    case 'domain':
      return {
        valid: /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v),
        hint: 'Expected format: example.com  (hostname with a valid TLD)',
      }
    case 'url':
      return {
        valid: /^https?:\/\/.{3,}/.test(v),
        hint: 'Expected format: https://example.com/path',
      }
    case 'email':
      return {
        valid: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v),
        hint: 'Expected format: user@example.com',
      }
    case 'md5':
      return {
        valid: /^[0-9a-fA-F]{32}$/.test(v),
        hint: 'Expected: 32 hexadecimal characters',
      }
    case 'sha1':
      return {
        valid: /^[0-9a-fA-F]{40}$/.test(v),
        hint: 'Expected: 40 hexadecimal characters',
      }
    case 'sha256':
      return {
        valid: /^[0-9a-fA-F]{64}$/.test(v),
        hint: 'Expected: 64 hexadecimal characters',
      }
    case 'cve':
      return {
        valid: /^CVE-\d{4}-\d{4,7}$/i.test(v),
        hint: 'Expected format: CVE-2021-12345',
      }
    case 'asn':
      return {
        valid: /^AS\d{1,10}$/i.test(v),
        hint: 'Expected format: AS15169  (AS followed by digits)',
      }
    case 'mac_addr':
      return {
        valid: /^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$/.test(v),
        hint: 'Expected format: 00:1A:2B:3C:4D:5E',
      }
    case 'registry_key':
      return {
        valid: /^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\/i.test(v),
        hint: 'Expected format: HKLM\\SOFTWARE\\Microsoft\\...',
      }
    case 'mutex':
      return {
        valid: v.length >= 2 && !/^\d+$/.test(v),
        hint: 'Mutex name must not be a plain number',
      }
    case 'user_account':
      return {
        valid: v.length >= 1 && !v.includes('\n'),
        hint: 'User account name must be a single non-empty line',
      }
    default:
      // Named entity types — no strict format required
      return null
  }
}

// ── types ─────────────────────────────────────────────────────────────────────

export interface PopoverState {
  mode: 'create' | 'edit'
  x: number
  y: number
  text?: string
  entity?: Entity
}

interface Props {
  state: PopoverState
  onClose: () => void
  onCreate?: (value: string, entityType: string, mitreId?: string) => void
  onChangeType?: (entityId: string, entityType: string) => void
  onAccept?: (entityId: string) => void
  onReject?: (entityId: string) => void
  onDelete?: (entityId: string) => void
}

// ── component ─────────────────────────────────────────────────────────────────

export default function EntityPopover({
  state, onClose, onCreate, onChangeType, onAccept, onReject, onDelete,
}: Props) {
  const [query,          setQuery]          = useState('')
  const [pendingConfirm, setPendingConfirm] = useState<{
    type: string
    validation: ValidationResult
  } | null>(null)

  const inputRef = useRef<HTMLInputElement>(null)
  const bodyRef  = useRef<HTMLDivElement>(null)

  // The text value to validate against (create = selected text, edit = entity value)
  const textToValidate = state.mode === 'create'
    ? (state.text ?? '')
    : (state.entity?.value ?? '')

  // Reset state every time the popover opens
  useEffect(() => {
    setQuery('')
    setPendingConfirm(null)
    const id = requestAnimationFrame(() => inputRef.current?.focus())
    return () => cancelAnimationFrame(id)
  }, [state])

  // ── search filtering ───────────────────────────────────────────────────────

  const filteredGroups = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return TYPE_GROUPS
    return TYPE_GROUPS
      .map(grp => ({
        ...grp,
        types: grp.types.filter(t =>
          (ENTITY_TYPE_LABELS[t] ?? t).toLowerCase().includes(q)
        ),
      }))
      .filter(grp => grp.types.length > 0)
  }, [query])

  const firstMatch = filteredGroups[0]?.types[0] ?? null

  // ── pick ───────────────────────────────────────────────────────────────────

  const pick = (type: string) => {
    const validation = validateIoC(textToValidate, type)

    // If the type has a strict format and the text doesn't match, ask for confirmation
    if (validation && !validation.valid) {
      setPendingConfirm({ type, validation })
      return
    }

    // Validation passed (or type has no validator) — proceed immediately
    confirmPick(type)
  }

  const confirmPick = (type: string) => {
    if (state.mode === 'create' && state.text) {
      onCreate?.(state.text, type)
    } else if (state.mode === 'edit' && state.entity) {
      onChangeType?.(state.entity.id, type)
    }
    onClose()
  }

  // ── keyboard ───────────────────────────────────────────────────────────────

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') { e.preventDefault(); onClose() }
    if (e.key === 'Enter' && firstMatch) { e.preventDefault(); pick(firstMatch) }
  }

  // ── position (clamped to viewport) ────────────────────────────────────────

  const approxH = state.mode === 'create' ? APPROX_H_CREATE : APPROX_H_EDIT
  const left    = Math.max(8, Math.min(state.x - POP_W / 2, window.innerWidth  - POP_W - 8))
  const top     = Math.max(8, Math.min(state.y + 12,        window.innerHeight - approxH - 8))

  // ── shared divider style ───────────────────────────────────────────────────

  const divider: React.CSSProperties = {
    borderBottom: '1px solid var(--rule)',
    padding: '10px 12px',
  }

  // ── render ─────────────────────────────────────────────────────────────────

  return (
    <>
      {/* Backdrop */}
      <div
        aria-hidden
        style={{
          position: 'fixed', inset: 0, zIndex: 99990,
          background: 'rgba(0,0,0,0.22)',
        }}
        onClick={onClose}
      />

      {/* Popover */}
      <div
        role="dialog"
        aria-modal="true"
        style={{
          position: 'fixed', left, top, width: POP_W, zIndex: 99999,
          background: 'var(--bg-elev)',
          border: '1px solid var(--rule)',
          borderRadius: 14,
          boxShadow: 'var(--shadow-card)',
          overflow: 'hidden',
          fontSize: 12,
          color: 'var(--ink)',
        }}
        onClick={e => e.stopPropagation()}
      >

        {/* ── CREATE header ─────────────────────────────────────────────── */}
        {state.mode === 'create' && state.text && (
          <div style={divider}>
            <p style={{
              fontSize: 10, fontWeight: 600, letterSpacing: '0.1em',
              textTransform: 'uppercase', color: 'var(--ink-3)',
              margin: '0 0 6px',
            }}>
              Add as entity
            </p>
            <p style={{
              margin: 0,
              fontFamily: MONO, fontSize: 11.5,
              color: 'var(--ink)',
              background: 'var(--bg-soft)',
              border: '1px solid var(--rule-soft)',
              borderRadius: 6,
              padding: '4px 8px',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              &ldquo;{state.text}&rdquo;
            </p>
          </div>
        )}

        {/* ── EDIT header ───────────────────────────────────────────────── */}
        {state.mode === 'edit' && state.entity && (
          <div style={divider}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, marginBottom: 4 }}>
              <span style={{
                padding: '2px 7px', borderRadius: 6, flexShrink: 0, fontSize: 11,
                background: typeSoft(state.entity.entity_type),
                color: typeInk(state.entity.entity_type),
              }}>
                {ENTITY_TYPE_LABELS[state.entity.entity_type] ?? state.entity.entity_type}
              </span>
              <span style={{
                fontFamily: MONO, fontSize: 11, color: 'var(--ink)',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>
                {state.entity.value}
              </span>
            </div>

            {state.entity.mitre_id && (
              <p style={{ margin: '0 0 8px', fontFamily: MONO, fontSize: 10.5, color: 'var(--ink-3)' }}>
                {state.entity.mitre_id}
              </p>
            )}

            <div style={{ display: 'flex', gap: 5, marginBottom: 8 }}>
              <button
                onClick={() => { onAccept?.(state.entity!.id); onClose() }}
                style={{
                  flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4,
                  padding: '4px 8px', borderRadius: 6, fontSize: 11, cursor: 'pointer', border: 'none',
                  background: 'color-mix(in oklab, var(--ok) 14%, var(--bg-soft))', color: 'var(--ok)',
                }}
              >
                <Check size={10} /> Accept
              </button>
              <button
                onClick={() => { onReject?.(state.entity!.id); onClose() }}
                style={{
                  flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4,
                  padding: '4px 8px', borderRadius: 6, fontSize: 11, cursor: 'pointer', border: 'none',
                  background: 'color-mix(in oklab, var(--no) 12%, var(--bg-soft))', color: 'var(--no)',
                }}
              >
                <X size={10} /> Reject
              </button>
              <button
                onClick={() => { onDelete?.(state.entity!.id); onClose() }}
                title="Delete entity"
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  padding: '4px 8px', borderRadius: 6, fontSize: 11, cursor: 'pointer', border: 'none',
                  background: 'var(--bg-soft)', color: 'var(--ink-3)',
                }}
              >
                <Trash2 size={10} />
              </button>
            </div>

            <p style={{ margin: 0, fontSize: 10, fontWeight: 600, letterSpacing: '0.1em',
                        textTransform: 'uppercase', color: 'var(--ink-3)' }}>
              Change type
            </p>
          </div>
        )}

        {/* ── Validation confirmation overlay ───────────────────────────── */}
        {pendingConfirm && (
          <div style={{
            padding: '14px 14px 12px',
            background: 'color-mix(in oklab, var(--warn) 6%, var(--bg-elev))',
            borderBottom: '1px solid var(--rule)',
          }}>
            {/* Warning header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
              <AlertTriangle size={14} style={{ color: 'var(--warn)', flexShrink: 0 }} />
              <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--ink)' }}>
                Format does not match
              </span>
            </div>

            {/* Warning body */}
            <p style={{ margin: '0 0 4px', fontSize: 11, color: 'var(--ink-2)', lineHeight: 1.5 }}>
              <span style={{ fontFamily: MONO, color: 'var(--ink)' }}>
                &ldquo;{textToValidate.length > 40 ? textToValidate.slice(0, 38) + '…' : textToValidate}&rdquo;
              </span>
              {' '}does not look like a valid{' '}
              <strong>{ENTITY_TYPE_LABELS[pendingConfirm.type] ?? pendingConfirm.type}</strong>.
            </p>
            <p style={{ margin: '0 0 10px', fontSize: 10.5, color: 'var(--ink-3)',
                        fontFamily: MONO, lineHeight: 1.5 }}>
              {pendingConfirm.validation.hint}
            </p>

            {/* Action buttons */}
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => { setPendingConfirm(null) }}
                className="btn-ghost"
                style={{ flex: 1, fontSize: 11, padding: '5px 0', justifyContent: 'center' }}
              >
                ← Back
              </button>
              <button
                onClick={() => { setPendingConfirm(null); confirmPick(pendingConfirm.type) }}
                style={{
                  flex: 1, fontSize: 11, padding: '5px 0',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4,
                  background: 'color-mix(in oklab, var(--warn) 15%, var(--bg-soft))',
                  color: 'var(--warn)', border: '1px solid color-mix(in oklab, var(--warn) 30%, var(--rule))',
                  borderRadius: 6, cursor: 'pointer', fontWeight: 600,
                }}
              >
                Add anyway
              </button>
            </div>
          </div>
        )}

        {/* ── Search ────────────────────────────────────────────────────── */}
        {!pendingConfirm && (
          <div style={{ ...divider, padding: '8px 12px' }}>
            <div style={{ position: 'relative' }}>
              <Search
                size={11}
                style={{
                  position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)',
                  color: 'var(--ink-4)', pointerEvents: 'none',
                }}
              />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Filter types…"
                style={{
                  width: '100%', boxSizing: 'border-box',
                  paddingLeft: 26, paddingRight: 8, paddingTop: 6, paddingBottom: 6,
                  background: 'var(--bg-soft)',
                  border: '1px solid var(--rule)',
                  borderRadius: 7,
                  fontSize: 12, color: 'var(--ink)',
                  outline: 'none', fontFamily: 'inherit',
                }}
                onFocus={e => (e.target.style.borderColor = 'var(--accent)')}
                onBlur={e  => (e.target.style.borderColor = 'var(--rule)')}
              />
            </div>
            {query && firstMatch && (
              <p style={{ margin: '4px 0 0 2px', fontSize: 10, color: 'var(--ink-3)', fontFamily: MONO }}>
                ↵ pick <span style={{ color: 'var(--ink)' }}>
                  {ENTITY_TYPE_LABELS[firstMatch] ?? firstMatch}
                </span>
              </p>
            )}
          </div>
        )}

        {/* ── Type list ─────────────────────────────────────────────────── */}
        {!pendingConfirm && (
          <div
            ref={bodyRef}
            style={{ maxHeight: BODY_MAX_H, overflowY: 'auto', padding: '8px 10px 10px' }}
          >
            {filteredGroups.length === 0 && (
              <p style={{ margin: 0, padding: '20px 0', textAlign: 'center', color: 'var(--ink-4)' }}>
                No matches for &ldquo;{query}&rdquo;
              </p>
            )}

            {filteredGroups.map(grp => (
              <div key={grp.label} style={{ marginBottom: 10 }}>
                <p style={{
                  margin: '0 0 5px 2px', fontSize: 10, fontWeight: 600,
                  letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-4)',
                }}>
                  {grp.label}
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
                  {grp.types.map(t => {
                    const isFirst  = t === firstMatch && !!query
                    const disabled = state.mode === 'edit' && t === state.entity?.entity_type

                    // Run validator for visual feedback (only in create mode)
                    const validation = state.mode === 'create'
                      ? validateIoC(textToValidate, t)
                      : null
                    const hasBadFormat = validation !== null && !validation.valid

                    return (
                      <button
                        key={t}
                        onClick={() => !disabled && pick(t)}
                        disabled={disabled}
                        title={hasBadFormat ? `⚠ Format mismatch — ${validation.hint}` : undefined}
                        style={{
                          background: typeSoft(t),
                          color: typeInk(t),
                          textAlign: 'left',
                          padding: '5px 9px',
                          borderRadius: 6,
                          fontSize: 11.5,
                          fontWeight: 500,
                          border: isFirst
                            ? '1.5px solid var(--accent)'
                            : hasBadFormat
                              ? '1px solid color-mix(in oklab, var(--warn) 35%, transparent)'
                              : '1px solid transparent',
                          cursor: disabled ? 'not-allowed' : 'pointer',
                          opacity: disabled ? 0.3 : 1,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          transition: 'opacity .1s, filter .1s',
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4,
                        }}
                        onMouseEnter={e => {
                          if (!disabled) (e.currentTarget as HTMLButtonElement).style.filter = 'brightness(0.93)'
                        }}
                        onMouseLeave={e => {
                          (e.currentTarget as HTMLButtonElement).style.filter = ''
                        }}
                      >
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', flex: 1 }}>
                          {ENTITY_TYPE_LABELS[t] ?? t}
                        </span>
                        {/* Validation badge — only for IoC types in create mode */}
                        {hasBadFormat && (
                          <span
                            style={{
                              fontSize: 9, flexShrink: 0,
                              color: 'var(--warn)', fontStyle: 'normal',
                            }}
                            title={validation.hint}
                          >
                            ⚠
                          </span>
                        )}
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        )}

      </div>
    </>
  )
}
