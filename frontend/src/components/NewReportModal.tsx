import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X, Loader2, AlertTriangle, Upload } from 'lucide-react'
import { uploadFile, ingestText, ingestUrl, errorDetail } from '../api/client'
import { MARKING_LEVELS } from '../types'
import type { MarkingLevel } from '../types'

const MONO  = "'JetBrains Mono', ui-monospace, monospace"
const SERIF = "'Source Serif 4', Georgia, serif"

// Display order is WHITE → RED, the reverse of MARKING_LEVELS, which is declared
// RED-first in types/index.ts.  The constant is the source of truth for the API
// and must not be reordered; this is a presentation concern only.
const MARKING_DISPLAY_ORDER = [...MARKING_LEVELS].reverse()

// Tone per marking level.  Used by the pills here and by the TLP chip on the
// kanban card, so any change has to stay in sync with Dashboard.tsx.
const MARKING_TONE: Record<MarkingLevel, string> = {
  WHITE: 'var(--ink-3)',
  GREEN: 'var(--ok)',
  AMBER: 'var(--warn)',
  RED:   'var(--no)',
}

// One derived mode, no tabs and no user toggle: the field works out what was
// pasted.  A bare URL on its own line is a capture; anything else is prose.
const URL_RE = /^(https?:\/\/|www\.)\S+$/i

// Below this a paste is a mis-click, not a report — the API rejects it too.
const MIN_TEXT_CHARS = 20

const MODE_META = {
  empty: { label: 'nothing yet',  tone: 'var(--ink-3)',  bg: 'var(--bg-soft)',     border: 'var(--rule-soft)' },
  file:  { label: 'file upload',  tone: 'var(--accent)', bg: 'var(--accent-soft)', border: 'color-mix(in oklab, var(--accent) 30%, transparent)' },
  url:   { label: 'url capture',  tone: 'var(--accent)', bg: 'var(--accent-soft)', border: 'color-mix(in oklab, var(--accent) 30%, transparent)' },
  text:  { label: 'pasted text',  tone: 'var(--accent)', bg: 'var(--accent-soft)', border: 'color-mix(in oklab, var(--accent) 30%, transparent)' },
} as const

interface Props {
  open: boolean
  /** A file dropped on the page, handed in when the modal opens. */
  initialFile?: File | null
  onClose: () => void
  onJobCreated: (jobId: string, filename: string) => void
}

export default function NewReportModal({ open, initialFile, onClose, onJobCreated }: Props) {
  const [value, setValue]       = useState('')
  const [title, setTitle]       = useState('')
  const [file, setFile]         = useState<File | null>(null)
  const [enableJs, setEnableJs] = useState(false)
  const [tlp, setTlp]           = useState<MarkingLevel | null>(null)
  const [pap, setPap]           = useState<MarkingLevel | null>(null)
  const [error, setError]       = useState<string | null>(null)
  const [modalDrag, setModalDrag] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  const taRef   = useRef<HTMLTextAreaElement>(null)
  const qc = useQueryClient()

  const trimmed = value.trim()
  const mode: 'empty' | 'file' | 'url' | 'text' =
    file ? 'file' : !trimmed ? 'empty' : URL_RE.test(trimmed) ? 'url' : 'text'

  const sourceReady = mode === 'file' || mode === 'url' || (mode === 'text' && trimmed.length >= MIN_TEXT_CHARS)
  const marksSet = tlp !== null && pap !== null
  const canSubmit = sourceReady && marksSet
  const chars = value.length
  const tooShort = mode === 'text' && trimmed.length < MIN_TEXT_CHARS

  const submitLabel = sourceReady && !marksSet ? 'Set TLP & PAP to continue' : 'Create job'

  const statusText =
    mode === 'empty' ? 'nothing pasted yet'
    : mode === 'url' ? 'link detected — no typing needed, just paste'
    : tooShort ? 'need at least 20 characters'
    : `${chars.toLocaleString()} chars`
  const statusTone =
    mode === 'empty' || mode === 'url' || !tooShort ? 'var(--ink-4)' : 'var(--warn)'

  const summary =
    mode === 'empty' ? 'awaiting a file, some text, or a link'
    : mode === 'file' ? 'will be parsed server-side, then queued for extraction'
    : mode === 'url' ? (enableJs ? 'page rendered to PDF with scripts enabled' : 'page rendered to PDF, scripts blocked')
    : `${chars.toLocaleString()} chars → stored as a reviewable source`

  const resetAll = useCallback(() => {
    setValue('')
    setTitle('')
    setFile(null)
    setEnableJs(false)
    setTlp(null)
    setPap(null)
  }, [])

  // 1. Opening resets the markings, and attaches a dropped file if there is one.
  //
  // Markings never carry over between jobs.  They govern how the bundle may be
  // shared, so a level left from a cancelled job is exactly the silent
  // mis-marking this modal exists to prevent — and resetting only on success
  // would leave TLP/PAP set after a Cancel, so the next report would open with
  // the submit button already armed.
  //
  // The pasted text is deliberately NOT cleared here: an accidental Escape
  // must not destroy a long paste.
  useEffect(() => {
    if (!open) return
    setTlp(null)
    setPap(null)
    setError(null)
    if (initialFile) {
      setFile(initialFile)
      setValue('')
    }
  }, [open, initialFile])

  // 2. Autofocus
  useEffect(() => {
    if (open && mode !== 'file') {
      const t = setTimeout(() => { taRef.current?.focus() }, 0)
      return () => clearTimeout(t)
    }
  }, [open, mode])

  // 3. Escape
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, onClose])

  const onDone = (d: { job_id: string; filename: string }) => {
    setError(null)
    qc.invalidateQueries({ queryKey: ['jobs'] })
    resetAll()
    onClose()
    onJobCreated(d.job_id, d.filename)
  }
  const onFail = (e: unknown) => setError(errorDetail(e))

  const fileMut = useMutation({
    mutationFn: (f: File) => uploadFile(f, { tlpLevel: tlp ?? undefined, papLevel: pap ?? undefined }),
    onSuccess: onDone,
    onError: onFail,
  })
  const textMut = useMutation({
    mutationFn: () => ingestText({ text: value, title: title.trim() || null, tlp_level: tlp, pap_level: pap }),
    onSuccess: onDone,
    onError: onFail,
  })
  const urlMut = useMutation({
    mutationFn: () => ingestUrl({ url: trimmed, enable_js: enableJs, tlp_level: tlp, pap_level: pap }),
    onSuccess: onDone,
    onError: onFail,
  })

  const busy = fileMut.isPending || textMut.isPending || urlMut.isPending

  const handleSubmit = () => {
    if (!canSubmit) return
    if (mode === 'file') { if (file) fileMut.mutate(file) }
    else if (mode === 'url') urlMut.mutate()
    else if (mode === 'text') textMut.mutate()
  }

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) { setFile(f); setValue('') }
    e.target.value = ''
  }

  const handleBackdropMouseDown = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose()
  }
  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setModalDrag(true) }
  const handleDragLeave = (e: React.DragEvent) => { e.preventDefault(); if (e.relatedTarget === null) setModalDrag(false) }
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); setModalDrag(false)
    const f = e.dataTransfer.files[0]
    if (f) { setFile(f); setValue('') }
  }

  const renderMarkingRow = (
    label: string,
    selected: MarkingLevel | null,
    onPick: (l: MarkingLevel) => void,
    ariaLabel: string,
  ) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }} role="radiogroup" aria-label={ariaLabel}>
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--ink-2)', width: 26, flexShrink: 0 }}>{label}</span>
      {MARKING_DISPLAY_ORDER.map((level) => {
        const tone = MARKING_TONE[level]
        const isSel = selected === level
        return (
          <button
            key={level}
            type="button"
            role="radio"
            aria-checked={isSel}
            disabled={busy}
            onClick={() => onPick(level)}
            style={{
              fontFamily: MONO, fontSize: 10.5, fontWeight: 600, letterSpacing: '.04em',
              padding: '4px 11px', borderRadius: 6, cursor: 'pointer',
              transition: 'background 120ms ease, color 120ms ease, border-color 120ms ease',
              background: isSel ? `color-mix(in oklab, ${tone} 16%, var(--bg-elev))` : 'var(--bg)',
              color: isSel ? tone : 'var(--ink-3)',
              border: isSel ? `1px solid ${tone}` : '1px solid var(--rule)',
            }}
          >
            {level}
          </button>
        )
      })}
    </div>
  )

  if (!open) return null

  const ext = file ? (file.name.split('.').pop()?.toUpperCase() ?? '') : ''
  const meta = MODE_META[mode]

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 90, background: 'rgba(20,12,4,.5)',
        backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center',
        justifyContent: 'center', padding: 28,
        animation: 'dashFadeIn .12s ease',
      }}
      onMouseDown={handleBackdropMouseDown}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="New report"
        style={{
          width: 'min(940px, 100%)', height: 'min(700px, 100%)',
          display: 'flex', flexDirection: 'column',
          background: 'var(--bg-elev)', border: '1px solid var(--rule)',
          borderRadius: 16, boxShadow: 'var(--shadow-pop)', overflow: 'hidden',
          animation: 'dashModalIn .16s ease-out',
          ...(modalDrag ? { outline: '2px dashed var(--accent)', outlineOffset: -6 } : {}),
        }}
      >
        {/* Header */}
        <div style={{ padding: '14px 18px 12px', borderBottom: '1px solid var(--rule)', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: SERIF, fontSize: 18, fontWeight: 600, color: 'var(--ink)' }}>New report</div>
            <div style={{ fontSize: 11.5, color: 'var(--ink-3)', marginTop: 3 }}>
              Drop a file, paste the text, or paste a link — one field takes all three.
            </div>
          </div>
          <button
            type="button"
            aria-label="Close"
            title="Close"
            onClick={onClose}
            style={{
              width: 26, height: 26, border: '1px solid var(--rule)', borderRadius: 6,
              color: 'var(--ink-3)', background: 'transparent',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: 'pointer', flexShrink: 0,
            }}
          >
            <X size={14} />
          </button>
        </div>

        {/* Error banner */}
        {error && (
          <div style={{
            margin: '10px 18px 0', display: 'flex', alignItems: 'flex-start', gap: 6,
            background: 'color-mix(in oklab, var(--no) 10%, transparent)',
            border: '1px solid color-mix(in oklab, var(--no) 35%, transparent)',
            borderRadius: 8, padding: '8px 10px', fontSize: 12, color: 'var(--no)',
          }}>
            <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Body */}
        <div style={{ flex: 1, minHeight: 0, padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Source row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '.1em', textTransform: 'uppercase' as const, color: 'var(--ink-3)' }}>Source</span>
            <span style={{
              fontFamily: MONO, fontSize: 10.5, padding: '2px 8px', borderRadius: 20,
              color: meta.tone, background: meta.bg, border: `1px solid ${meta.border}`,
            }}>{meta.label}</span>
            <div style={{ flex: 1 }} />
            <button type="button" className="btn-ghost" style={{ padding: '4px 10px', fontSize: 11 }} onClick={() => fileRef.current?.click()}>
              Browse files…
            </button>
            <input
              type="file"
              ref={fileRef}
              style={{ display: 'none' }}
              accept=".pdf,.docx,.html,.htm,.txt,.md"
              onChange={handleFileInput}
            />
          </div>

          {/* File state */}
          {mode === 'file' && file && (
            <div style={{
              flex: 1, minHeight: 0, border: '1px solid var(--rule)', borderRadius: 12,
              background: 'var(--bg-soft)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <div style={{
                background: 'var(--bg-elev)', border: '1px solid var(--rule)', borderRadius: 12,
                padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14, boxShadow: 'var(--shadow-card)',
              }}>
                <div style={{
                  width: 38, height: 46, border: '1px solid var(--rule)', borderRadius: 4,
                  background: 'var(--bg)', display: 'flex', alignItems: 'flex-end',
                  justifyContent: 'center', paddingBottom: 4, flexShrink: 0,
                }}>
                  <span style={{ fontFamily: MONO, fontSize: 9, color: 'var(--ink-3)' }}>{ext}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--ink)', maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</div>
                  <div style={{ fontFamily: MONO, fontSize: 11, color: 'var(--ink-3)', marginTop: 2 }}>
                    {(file.size / 1048576).toFixed(2)} MB · {ext}
                  </div>
                </div>
                <button type="button" className="btn-ghost" style={{ fontSize: 11 }} onClick={() => { setFile(null); setValue('') }}>
                  Remove
                </button>
              </div>
            </div>
          )}

          {/* Composer state */}
          {mode !== 'file' && (
            <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {mode === 'text' && (
                <input
                  type="text"
                  value={title}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTitle(e.target.value)}
                  placeholder="Title (optional) — defaults to the first line"
                  style={{
                    width: '100%', boxSizing: 'border-box', padding: '8px 10px', borderRadius: 8,
                    border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)', fontSize: 13,
                  }}
                />
              )}
              <textarea
                ref={taRef}
                value={value}
                onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setValue(e.target.value)}
                placeholder="Paste the report text here, or paste a URL — plain text, Markdown, or a link. You can also drop a file anywhere in this window."
                style={{
                  flex: 1, minHeight: 0, resize: 'none', padding: '12px 14px', borderRadius: 12,
                  border: '1px solid var(--rule)', background: 'var(--bg)', color: 'var(--ink)',
                  fontFamily: MONO, fontSize: 12.5, lineHeight: 1.6, boxSizing: 'border-box',
                }}
              />
              <div style={{ minHeight: 20, fontFamily: MONO, fontSize: 11, color: statusTone }}>{statusText}</div>
              {mode === 'url' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={enableJs}
                    onClick={() => setEnableJs(v => !v)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 7,
                      borderRadius: 20, padding: '3px 10px 3px 4px', fontSize: 11,
                      border: `1px solid ${enableJs ? 'var(--warn)' : 'var(--rule)'}`,
                      background: 'transparent', color: 'var(--ink)', cursor: 'pointer',
                      transition: 'border-color 120ms ease',
                    }}
                  >
                    <span style={{
                      position: 'relative', width: 26, height: 15, borderRadius: 20, flexShrink: 0,
                      background: enableJs ? 'var(--warn)' : 'var(--rule)',
                      transition: 'background 140ms ease',
                    }}>
                      <span style={{
                        position: 'absolute', top: 2, left: enableJs ? 13 : 2,
                        width: 11, height: 11, borderRadius: '50%',
                        background: 'var(--bg-elev)', transition: 'left 140ms ease',
                      }} />
                    </span>
                    Run page JavaScript
                  </button>
                  <span style={{ fontSize: 10.5, color: 'var(--ink-4)' }}>
                    {enableJs ? 'the page will execute scripts — use only when it renders nothing otherwise' : 'off by default'}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Markings band */}
        <div style={{
          padding: '12px 18px', borderTop: '1px solid var(--rule)',
          display: 'flex', flexDirection: 'column', gap: 9,
          background: marksSet ? 'var(--bg-elev)' : 'color-mix(in oklab, var(--warn) 6%, var(--bg-soft))',
          transition: 'background 120ms ease',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '.1em', textTransform: 'uppercase' as const, color: 'var(--ink-3)' }}>MARKINGS</span>
            <span style={{
              fontFamily: MONO, fontSize: 10, padding: '1px 6px', borderRadius: 4,
              color: marksSet ? 'var(--ok)' : 'var(--warn)',
              background: marksSet ? 'color-mix(in oklab, var(--ok) 12%, transparent)' : 'color-mix(in oklab, var(--warn) 15%, transparent)',
            }}>{marksSet ? 'set' : 'required'}</span>
            <div style={{ flex: 1 }} />
            <span style={{ fontSize: 10.5, color: 'var(--ink-4)' }}>Applied to every object in the bundle</span>
          </div>
          {renderMarkingRow('TLP', tlp, setTlp, 'TLP marking')}
          {renderMarkingRow('PAP', pap, setPap, 'PAP marking')}
        </div>

        {/* Footer */}
        <div style={{
          padding: '11px 18px', borderTop: '1px solid var(--rule)',
          background: 'var(--bg-elev)', display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <div style={{ flex: 1, fontFamily: MONO, fontSize: 11, color: 'var(--ink-3)' }}>{summary}</div>
          <button type="button" className="btn-ghost" style={{ padding: '7px 13px', fontSize: 12, borderRadius: 7 }} disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn-primary"
            style={{
              padding: '7px 15px', fontSize: 12.5, borderRadius: 7,
              display: 'flex', alignItems: 'center', gap: 6,
              opacity: (!canSubmit || busy) ? 0.45 : 1,
              cursor: (!canSubmit || busy) ? 'not-allowed' : 'pointer',
            }}
            disabled={!canSubmit || busy}
            onClick={handleSubmit}
          >
            {busy && <Loader2 size={12} className="animate-spin" />}
            {submitLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
