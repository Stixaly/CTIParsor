import { useState, useEffect, useRef, useCallback } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X, Loader2, AlertTriangle } from 'lucide-react'
import { uploadFile, ingestText, ingestUrl, inspectBaseline, fetchBaselineStatus, errorDetail } from '../api/client'
import { TLP_LEVELS, PAP_LEVELS, BASELINE_REASON_LABEL } from '../types'
import type { MarkingLevel, TlpLevel, PapLevel, PipelineMode, BaselineIntake } from '../types'
import { splitDrop } from './dropFiles'
import type { IgnoredFile } from './dropFiles'

const MONO  = "'JetBrains Mono', ui-monospace, monospace"
const SERIF = "'Source Serif 4', Georgia, serif"

// Display order is CLEAR/WHITE → RED, the reverse of the constants, which are
// declared RED-first in types/index.ts.  The constants are the source of truth
// for the API and must not be reordered; this is a presentation concern only.
const TLP_DISPLAY_ORDER = [...TLP_LEVELS].reverse()
const PAP_DISPLAY_ORDER = [...PAP_LEVELS].reverse()

// Tone per marking level.  Used by the pills here and by the TLP chip on the
// kanban card, so any change has to stay in sync with KanbanCard.tsx.
const MARKING_TONE: Record<MarkingLevel, string> = {
  WHITE: 'var(--ink-3)',
  CLEAR: 'var(--ink-3)',
  GREEN: 'var(--ok)',
  AMBER: 'var(--warn)',
  'AMBER+STRICT': 'var(--warn)',
  RED:   'var(--no)',
}

// One derived mode, no tabs and no user toggle: the field works out what was
// pasted.  A bare URL on its own line is a capture; anything else is prose.
const URL_RE = /^(https?:\/\/|www\.)\S+$/i

// Display hint only — the server owns the real detection (api/routes/ingest.py).
// Deliberately looser than the server's rule: it is fine for this to say "HTML"
// on something the server files as text, but not fine for markup to reach the
// analyst looking like it went in raw.
const HTML_HINT_RE = /<!DOCTYPE\s+html|<html[\s>]|<(div|p|table|tr|td|h[1-6]|ul|li|span|body)[\s>]/i

// Below this a paste is a mis-click, not a report — the API rejects it too.
const MIN_TEXT_CHARS = 20
/** A bundle is often a few KB: "0.00 MB" said nothing. */
const fileSize = (bytes: number) =>
  bytes < 102400 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / 1048576).toFixed(2)} MB`

// The warning every preview carries (/baselines/inspect never runs the JSON schemas).
const SCHEMAS_LATER = 'the STIX schemas were not checked'

const MODE_META = {
  empty: { label: 'nothing yet',  tone: 'var(--ink-3)',  bg: 'var(--bg-soft)',     border: 'var(--rule-soft)' },
  file:  { label: 'file upload',  tone: 'var(--accent)', bg: 'var(--accent-soft)', border: 'color-mix(in oklab, var(--accent) 30%, transparent)' },
  url:   { label: 'url capture',  tone: 'var(--accent)', bg: 'var(--accent-soft)', border: 'color-mix(in oklab, var(--accent) 30%, transparent)' },
  text:  { label: 'pasted text',  tone: 'var(--accent)', bg: 'var(--accent-soft)', border: 'color-mix(in oklab, var(--accent) 30%, transparent)' },
} as const

// The two pipelines (ADR-0090).  Enrich merges the report into a STIX 2.1 bundle
// the analyst already holds; the mode selector is shown only when the server has it on.
const PIPELINE_MODES: { value: PipelineMode; label: string; hint: string }[] = [
  { value: 'full', label: 'Full extraction', hint: 'CTIParsor builds the bundle from the report alone' },
  { value: 'enrich', label: 'Enrich an existing STIX 2.1 bundle', hint: 'Merge what the report adds into your bundle; what it already holds is shown, not duplicated' },
]

// Display order runs weakest first.  While a bundle is in, its minimum raises a
// missing or weaker marking to itself and never lowers one.  The raise is the
// bundle's: it ends with the bundle, and a mark the analyst picked is kept.
function raiseTo<L extends MarkingLevel>(order: readonly L[], current: L | null, min: L): L {
  return current === null || order.indexOf(current) < order.indexOf(min) ? min : current
}

// A pick weaker than the bundle's minimum is what the bundle replaces.
function isWeaker<L extends MarkingLevel>(order: readonly L[], mark: L | null, min: L): boolean {
  return mark !== null && order.indexOf(mark) < order.indexOf(min)
}

const countOf = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`

// The uuid part of a STIX id, shortened for a list line.
const shortId = (id: string) => (id.split('--')[1] ?? id).slice(0, 8)

interface Props {
  open: boolean
  /** A file dropped on the page, handed in when the modal opens. */
  initialFile?: File | null
  /** A STIX bundle dropped with it: enrich mode, when the flag is on (ADR-0090). */
  initialBundle?: File | null
  /** Dropped .json files that are not used, named when the modal opens (ADR-0090). */
  initialIgnored?: IgnoredFile[]
  onClose: () => void
  onJobCreated: (jobId: string, filename: string) => void
}

export default function NewReportModal({ open, initialFile, initialBundle, initialIgnored, onClose, onJobCreated }: Props) {
  const [value, setValue]       = useState('')
  const [title, setTitle]       = useState('')
  const [file, setFile]         = useState<File | null>(null)
  const [enableJs, setEnableJs] = useState(false)
  // The analyst's own picks.  The marks in force are these, raised to the bundle's minimum.
  const [pickedTlp, setPickedTlp] = useState<TlpLevel | null>(null)
  const [pickedPap, setPickedPap] = useState<PapLevel | null>(null)
  const [error, setError]       = useState<string | null>(null)
  const [modalDrag, setModalDrag] = useState(false)
  const [pipelineMode, setPipelineMode] = useState<PipelineMode>('full')
  const [stixFile, setStixFile] = useState<File | null>(null)
  const [intake, setIntake]     = useState<BaselineIntake | null>(null)
  const [intakeError, setIntakeError] = useState<string | null>(null)
  // A bundle that was dropped while the flag is off: not used, and the modal says so.
  const [bundleOff, setBundleOff] = useState(false)
  // The dropped .json files that are not used, and why: named, and not used.
  const [notUsed, setNotUsed] = useState<IgnoredFile[]>([])
  // A bundle dropped on the modal while the status is still loading: it waits, as initialBundle does.
  const [heldBundle, setHeldBundle] = useState<File | null>(null)
  const [reportId, setReportId] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const bundleRef = useRef<HTMLInputElement>(null)
  const taRef   = useRef<HTMLTextAreaElement>(null)
  // Every bundle pick, removal and reset takes a new ticket.  An inspect answer
  // for an older ticket is dropped, so a bundle still being read when the modal
  // closed cannot set the markings of the next job.
  const inspectTicket = useRef(0)
  const qc = useQueryClient()

  // Without the flag, or if its status cannot be read, only full mode is offered.
  const { data: baselineStatus, isPending: statusPending, isError: statusFailed } = useQuery({
    queryKey: ['baselineStatus'],
    queryFn: fetchBaselineStatus,
  })
  const flagOn = baselineStatus?.enabled === true
  const maxBytes = baselineStatus?.max_bytes ?? 0
  const maxMb = Math.round(maxBytes / 1048576)
  const enriching = pipelineMode === 'enrich'

  const inspectMut = useMutation({
    mutationFn: (args: { file: File; reportId?: string; ticket: number }) => inspectBaseline(args.file, args.reportId),
    onSuccess: (data, vars) => {
      if (vars.ticket !== inspectTicket.current) return
      setIntake(data)
      setIntakeError(null)
      // A pick under the bundle's minimum is dropped here: the bundle sets that
      // mark, so it goes back to null with the bundle.  Picks at or above stay.
      const bundleTlp = data.min_tlp
      const bundlePap = data.min_pap
      if (bundleTlp) setPickedTlp(cur => isWeaker(TLP_DISPLAY_ORDER, cur, bundleTlp) ? null : cur)
      if (bundlePap) setPickedPap(cur => isWeaker(PAP_DISPLAY_ORDER, cur, bundlePap) ? null : cur)
    },
    onError: (e, vars) => {
      if (vars.ticket === inspectTicket.current) setIntakeError(errorDetail(e))
    },
  })
  const inspecting = inspectMut.isPending
  // The mutate function is stable across renders, so the memoised pickBundle below can depend on it.
  const startInspect = inspectMut.mutate

  // The bundle's minimum markings, once a scope is known.  A marking below one
  // would weaken what the bundle already says, so those levels are disabled.
  const minTlp = enriching ? (intake?.min_tlp ?? null) : null
  const minPap = enriching ? (intake?.min_pap ?? null) : null
  const floor = [minTlp ? `TLP:${minTlp}` : null, minPap ? `PAP:${minPap}` : null].filter(Boolean).join(' and ')
  // The marks in force: the analyst's pick, raised to the bundle's minimum while it is in.
  const tlp = minTlp ? raiseTo(TLP_DISPLAY_ORDER, pickedTlp, minTlp) : pickedTlp
  const pap = minPap ? raiseTo(PAP_DISPLAY_ORDER, pickedPap, minPap) : pickedPap
  const marksSet = tlp !== null && pap !== null

  const trimmed = value.trim()
  const mode: 'empty' | 'file' | 'url' | 'text' =
    file ? 'file' : !trimmed ? 'empty' : URL_RE.test(trimmed) ? 'url' : 'text'

  const sourceReady = mode === 'file' || mode === 'url' || (mode === 'text' && trimmed.length >= MIN_TEXT_CHARS)
  // A bundle is usable once it is read for the report choice the analyst made.
  const bundleReady = stixFile !== null && intake !== null && !intake.needs_report_choice && !inspecting && intakeError === null
  const canSubmit = sourceReady && marksSet && (!enriching || bundleReady)
  const chars = value.length
  const tooShort = mode === 'text' && trimmed.length < MIN_TEXT_CHARS

  // A bundle that was read and refused is still the one the analyst picked: fix it.
  const submitLabel =
    enriching && !bundleReady ? (
      stixFile && intakeError ? 'Fix the STIX bundle to continue'
      : intake?.needs_report_choice ? 'Choose the report to enrich'
      : 'Add the STIX bundle to continue'
    )
    : sourceReady && !marksSet ? 'Set TLP & PAP to continue'
    : 'Create job'

  // Pasted markup is a real case — "view source" is the fallback when a page is
  // behind bot protection the URL capture cannot get past.  The server does the
  // authoritative detection and strips the tags; this only tells the analyst
  // their paste was recognised, so markup does not look like it went in raw.
  const looksLikeHtml = mode === 'text' && HTML_HINT_RE.test(trimmed)

  const statusText =
    mode === 'empty' ? 'nothing pasted yet'
    : mode === 'url' ? 'link detected — no typing needed, just paste'
    : tooShort ? 'need at least 20 characters'
    : looksLikeHtml ? `${chars.toLocaleString()} chars of HTML — tags stripped server-side`
    : `${chars.toLocaleString()} chars`
  const statusTone =
    mode === 'empty' || mode === 'url' || !tooShort ? 'var(--ink-4)' : 'var(--warn)'

  const summary =
    mode === 'empty' ? 'awaiting a file, some text, or a link'
    : mode === 'file' ? 'will be parsed server-side, then queued for extraction'
    : mode === 'url' ? (enableJs ? 'page rendered to PDF with scripts enabled' : 'page rendered to PDF, scripts blocked')
    : `${chars.toLocaleString()} chars → stored as a reviewable source`
  const footer = enriching && stixFile ? `${summary}, merged into ${stixFile.name}` : summary

  // Drops the bundle, its report choice, its error and the flag note.  The ticket goes with it,
  // so an inspect still in flight for it is ignored when it answers.
  const clearBundle = useCallback(() => {
    inspectTicket.current += 1
    setStixFile(null)
    setIntake(null)
    setIntakeError(null)
    setReportId(null)
    setBundleOff(false)
  }, [])

  const resetAll = useCallback(() => {
    setValue('')
    setTitle('')
    setFile(null)
    setEnableJs(false)
    setPickedTlp(null)
    setPickedPap(null)
    setPipelineMode('full')
    clearBundle()
  }, [clearBundle])

  // 1. Opening resets the markings, and attaches a dropped file if there is one.
  //
  // Markings never carry over between jobs.  They govern how the bundle may be
  // shared, so a level left from a cancelled job is exactly the silent
  // mis-marking this modal exists to prevent — and resetting only on success
  // would leave TLP/PAP set after a Cancel, so the next report would open with
  // the submit button already armed.  The pipeline and its bundle reset the same way.
  //
  // The pasted text is deliberately NOT cleared here: an accidental Escape
  // must not destroy a long paste.
  useEffect(() => {
    if (!open) return
    setPickedTlp(null)
    setPickedPap(null)
    setError(null)
    setPipelineMode('full')
    clearBundle()
    setNotUsed(initialIgnored ?? [])
    if (initialFile) {
      setFile(initialFile)
      setValue('')
    }
  }, [open, initialFile, initialIgnored, clearBundle])

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

  // Enrich mode only: the bundle travels with the job request, because the
  // inspect call keeps nothing (ADR-0090).  Full mode sends none of these keys.
  const bundleOptions = enriching && stixFile ? { baselineStix: stixFile, baselineReportId: reportId ?? undefined } : {}
  const bundleBody = async () => (enriching && stixFile
    ? { baseline_bundle: await stixFile.text(), baseline_report_id: reportId }
    : {})

  const fileMut = useMutation({
    mutationFn: (f: File) => uploadFile(f, { tlpLevel: tlp ?? undefined, papLevel: pap ?? undefined, ...bundleOptions }),
    onSuccess: onDone,
    onError: onFail,
  })
  const textMut = useMutation({
    mutationFn: async () => ingestText({ text: value, title: title.trim() || null, tlp_level: tlp, pap_level: pap, ...(await bundleBody()) }),
    onSuccess: onDone,
    onError: onFail,
  })
  const urlMut = useMutation({
    mutationFn: async () => ingestUrl({ url: trimmed, enable_js: enableJs, tlp_level: tlp, pap_level: pap, ...(await bundleBody()) }),
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

  // A bundle that is too large is refused here, before anything is read.
  // Memoised: the effect that takes a bundle from the drop depends on it.
  const pickBundle = useCallback((f: File) => {
    clearBundle()
    if (f.size > maxBytes) {
      setIntakeError(`The STIX bundle is larger than ${maxMb} MB`)
      return
    }
    setStixFile(f)
    startInspect({ file: f, ticket: inspectTicket.current })
  }, [clearBundle, maxBytes, maxMb, startInspect])
  const pickReport = (id: string) => {
    // The report picked last is read again only when that read failed: it is the retry.
    if (!stixFile || (id === reportId && intakeError === null)) return
    setReportId(id)
    setIntakeError(null)
    inspectMut.mutate({ file: stixFile, reportId: id, ticket: inspectTicket.current })
  }
  const pickMode = (m: PipelineMode) => {
    if (m === 'full') clearBundle()
    setPipelineMode(m)
  }
  // A bundle is picked once the flag is known: the status may still be loading when
  // the modal opens.  With the flag off it is not used.
  const takeBundle = useCallback((f: File) => {
    if (flagOn) { setPipelineMode('enrich'); pickBundle(f) }
    else setBundleOff(true)
  }, [flagOn, pickBundle])
  useEffect(() => {
    if (!open || !initialBundle || statusPending) return
    takeBundle(initialBundle)
  }, [open, initialBundle, statusPending, takeBundle])
  // A bundle dropped on the modal while the status is loading waits here too.  It is
  // forgotten when the modal closes, so a later opening cannot pick it up.
  useEffect(() => {
    if (!open) { setHeldBundle(null); return }
    if (!heldBundle || statusPending) return
    setHeldBundle(null)
    takeBundle(heldBundle)
  }, [open, heldBundle, statusPending, takeBundle])

  const handleBundleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) pickBundle(f)
    e.target.value = ''
  }
  const handleBackdropMouseDown = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose()
  }
  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setModalDrag(true) }
  const handleDragLeave = (e: React.DragEvent) => { e.preventDefault(); if (e.relatedTarget === null) setModalDrag(false) }
  // A report goes to the report zone, a STIX bundle to the bundle zone, on the modal
  // and on the bundle zone alike.  A bundle alone leaves the pasted text and a chosen
  // report as they are.  The drop stops here, so the page's own drop does not reopen
  // the modal with the same files.
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation(); setModalDrag(false)
    splitDrop(Array.from(e.dataTransfer.files)).then(({ report, bundle, ignored }) => {
      setNotUsed(ignored)
      if (bundle) {
        // Until the status answers, the flag is unknown: the bundle waits for it.
        if (statusPending) setHeldBundle(bundle)
        else takeBundle(bundle)
      }
      if (report) { setFile(report); setValue('') }
    })
  }

  const renderMarkingRow = <L extends MarkingLevel>(
    label: string,
    levels: readonly L[],
    selected: L | null,
    onPick: (l: L) => void,
    ariaLabel: string,
    minLevel?: L,
  ) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }} role="radiogroup" aria-label={ariaLabel}>
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--ink-2)', width: 26, flexShrink: 0 }}>{label}</span>
      {levels.map((level) => {
        const tone = MARKING_TONE[level]
        const isSel = selected === level
        // Levels run weakest first, so one before the bundle's minimum is weaker than it.
        const isWeak = minLevel !== undefined && levels.indexOf(level) < levels.indexOf(minLevel)
        return (
          <button
            key={level}
            type="button"
            role="radio"
            aria-checked={isSel}
            disabled={busy || isWeak}
            title={isWeak ? `The supplied STIX bundle carries ${label}:${minLevel}; a lower marking would weaken it` : undefined}
            onClick={() => onPick(level)}
            style={{
              fontFamily: MONO, fontSize: 10.5, fontWeight: 600, letterSpacing: '.04em',
              padding: '4px 11px', borderRadius: 6, cursor: isWeak ? 'not-allowed' : 'pointer',
              opacity: isWeak ? 0.35 : 1,
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

  // The bundle's summary, once its scope is known: no counts while a report is still
  // to be chosen, nor after a read failed (the last counts were another report's).
  const scoped = intake !== null && !intake.needs_report_choice && intakeError === null ? intake : null
  const importedTypes = scoped
    ? Object.entries(scoped.counts).filter(([type]) => type !== 'out_of_scope' && type !== 'dangling_refs')
    : []
  const importedTotal = importedTypes.reduce((n, [, c]) => n + c, 0)

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

        {/* Everything between the header and the actions scrolls.  The dialog
            is capped at the window's height and clips, so on a short window
            (or at 200 % zoom) an error or a wrapped line used to squeeze the
            text field to nothing, or push the markings over it. */}
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>

        {/* Error banner */}
        {error && (
          <div style={{
            margin: '10px 18px 0', display: 'flex', alignItems: 'flex-start', gap: 6, flexShrink: 0,
            background: 'color-mix(in oklab, var(--no) 10%, transparent)',
            border: '1px solid color-mix(in oklab, var(--no) 35%, transparent)',
            borderRadius: 8, padding: '8px 10px', fontSize: 12, color: 'var(--no)',
          }}>
            <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Body */}
        <div style={{ flex: '1 0 auto', padding: '14px 18px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Pipeline mode — shown only when the server has the enrich flag on */}
          {baselineStatus?.enabled && (
            <div role="radiogroup" aria-label="Pipeline mode" style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              {PIPELINE_MODES.map((m) => {
                const isSel = pipelineMode === m.value
                return (
                  <button
                    key={m.value}
                    type="button"
                    role="radio"
                    aria-checked={isSel}
                    aria-label={m.label}
                    disabled={busy || inspecting}
                    onClick={() => pickMode(m.value)}
                    style={{
                      flex: 1, minWidth: 0, textAlign: 'left', cursor: 'pointer',
                      padding: '9px 12px', borderRadius: 8,
                      transition: 'background 120ms ease, border-color 120ms ease',
                      background: isSel ? 'color-mix(in oklab, var(--accent) 10%, var(--bg-elev))' : 'var(--bg)',
                      border: isSel ? '1px solid var(--accent)' : '1px solid var(--rule)',
                    }}
                  >
                    <div style={{ fontSize: 12.5, fontWeight: 600, color: isSel ? 'var(--accent)' : 'var(--ink)' }}>{m.label}</div>
                    <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 2 }}>{m.hint}</div>
                  </button>
                )
              })}
            </div>
          )}

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

          {bundleOff && (
            <div style={{ fontSize: 11.5, color: 'var(--ink-3)', flexShrink: 0 }}>
              {statusFailed
                ? 'Could not read the server’s STIX enrichment status: the bundle was not used'
                : 'STIX enrichment is off on this server: the bundle was not used'}
            </div>
          )}
          {notUsed.map(({ file: f, why }, i) => (
            <div key={i} style={{ fontSize: 11.5, color: 'var(--ink-3)', flexShrink: 0 }}>
              {why === 'second_bundle'
                ? `${f.name}: only one STIX bundle per job, not used`
                : `${f.name} is not a STIX 2.1 bundle: not used`}
            </div>
          ))}

          {/* File state */}
          {mode === 'file' && file && (
            <div style={{
              flex: 1, minHeight: 120, border: '1px solid var(--rule)', borderRadius: 12,
              background: 'var(--bg-soft)', display: 'flex', alignItems: 'center', justifyContent: 'center',
              padding: 12,
            }}>
              <div style={{
                background: 'var(--bg-elev)', border: '1px solid var(--rule)', borderRadius: 12,
                padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14, boxShadow: 'var(--shadow-card)',
                maxWidth: '100%', minWidth: 0, boxSizing: 'border-box',
              }}>
                <div style={{
                  width: 38, height: 46, border: '1px solid var(--rule)', borderRadius: 4,
                  background: 'var(--bg)', display: 'flex', alignItems: 'flex-end',
                  justifyContent: 'center', paddingBottom: 4, flexShrink: 0,
                }}>
                  <span style={{ fontFamily: MONO, fontSize: 9, color: 'var(--ink-3)' }}>{ext}</span>
                </div>
                {/* minWidth 0 lets a long name shrink to its ellipsis instead
                    of pushing Remove out of the card on a narrow window. */}
                <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                  <div title={file.name} style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--ink)', maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</div>
                  <div style={{ fontFamily: MONO, fontSize: 11, color: 'var(--ink-3)', marginTop: 2 }}>
                    {(file.size / 1048576).toFixed(2)} MB · {ext}
                  </div>
                </div>
                <button type="button" className="btn-ghost" style={{ fontSize: 11, flexShrink: 0 }} onClick={() => { setFile(null); setValue('') }}>
                  Remove
                </button>
              </div>
            </div>
          )}

          {/* Composer state */}
          {mode !== 'file' && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
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
                  flex: 1, minHeight: 140, resize: 'none', padding: '12px 14px', borderRadius: 12,
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

          {/* STIX bundle — enrich mode only (ADR-0090) */}
          {enriching && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0 }}>
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '.1em', textTransform: 'uppercase' as const, color: 'var(--ink-3)' }}>STIX bundle</span>
              <input
                type="file"
                ref={bundleRef}
                aria-label="STIX bundle file"
                style={{ display: 'none' }}
                accept=".json,application/json"
                onChange={handleBundleInput}
              />
              {stixFile ? (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10, minWidth: 0,
                  border: '1px solid var(--rule)', borderRadius: 10, padding: '9px 12px', background: 'var(--bg)',
                }}>
                  <div title={stixFile.name} style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{stixFile.name}</div>
                  <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--ink-3)', flexShrink: 0 }}>{fileSize(stixFile.size)}</span>
                  {inspecting && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11.5, color: 'var(--ink-3)', flexShrink: 0 }}>
                      <Loader2 size={12} className="animate-spin" />
                      reading the bundle…
                    </span>
                  )}
                  <div style={{ flex: 1 }} />
                  <button type="button" className="btn-ghost" style={{ fontSize: 11, flexShrink: 0 }} disabled={busy || inspecting} onClick={() => bundleRef.current?.click()}>
                    Change
                  </button>
                  <button type="button" className="btn-ghost" style={{ fontSize: 11, flexShrink: 0 }} disabled={busy || inspecting} onClick={clearBundle}>
                    Remove
                  </button>
                </div>
              ) : (
                <div
                  onDrop={handleDrop}
                  style={{
                    display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 10,
                    border: '1px dashed var(--rule)', borderRadius: 10, padding: '14px 16px',
                    background: 'var(--bg-soft)', fontSize: 12, color: 'var(--ink-3)',
                  }}
                >
                  <span>Drop the bundle here, or</span>
                  <button type="button" className="btn-ghost" style={{ fontSize: 11 }} disabled={busy} onClick={() => bundleRef.current?.click()}>
                    Browse bundle…
                  </button>
                  <span style={{ fontFamily: MONO, fontSize: 10.5, color: 'var(--ink-4)' }}>JSON · up to {maxMb} MB</span>
                </div>
              )}
              {intakeError && (
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 12, color: 'var(--no)' }}>
                  <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                  <span>{intakeError}</span>
                </div>
              )}
              {intake && intake.reports.length > 1 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <span style={{ fontSize: 11.5, color: intake.needs_report_choice ? 'var(--warn)' : 'var(--ink-3)' }}>
                    {intake.needs_report_choice ? 'This bundle holds several reports: choose the one to enrich' : 'Report to enrich'}
                  </span>
                  <div role="radiogroup" aria-label="Report to enrich" style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    {intake.reports.map((r) => {
                      const isSel = reportId === r.id
                      return (
                        <button
                          key={r.id}
                          type="button"
                          role="radio"
                          aria-checked={isSel}
                          aria-label={r.name}
                          disabled={busy || inspecting}
                          onClick={() => pickReport(r.id)}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 10, textAlign: 'left',
                            padding: '6px 10px', borderRadius: 7, fontSize: 12, cursor: 'pointer', color: 'var(--ink)',
                            background: isSel ? 'color-mix(in oklab, var(--accent) 10%, var(--bg-elev))' : 'var(--bg)',
                            border: isSel ? '1px solid var(--accent)' : '1px solid var(--rule)',
                          }}
                        >
                          <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 600 }}>{r.name}</span>
                          <span style={{ fontFamily: MONO, fontSize: 10.5, color: 'var(--ink-3)', flexShrink: 0 }}>{r.published ? r.published.slice(0, 10) : 'no date'}</span>
                          <span style={{ fontFamily: MONO, fontSize: 10.5, color: 'var(--ink-3)', flexShrink: 0 }}>{r.refs} refs</span>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}
              {scoped && (
                <div style={{
                  display: 'flex', flexDirection: 'column', gap: 7, padding: '10px 12px',
                  border: '1px solid var(--rule-soft)', borderRadius: 10, background: 'var(--bg-soft)',
                  fontSize: 12, color: 'var(--ink-2)',
                }}>
                  <div style={{ fontFamily: MONO, fontSize: 11.5, color: 'var(--ink)' }}>{countOf(importedTotal, 'object')} kept from the bundle</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {importedTypes.map(([type, n]) => (
                      <span key={type} style={{
                        fontFamily: MONO, fontSize: 10.5, padding: '2px 8px', borderRadius: 4,
                        border: '1px solid var(--rule)', background: 'var(--bg-elev)',
                      }}>
                        {type} {n}
                      </span>
                    ))}
                  </div>
                  {(scoped.counts.out_of_scope ?? 0) > 0 && (
                    <div>{countOf(scoped.counts.out_of_scope ?? 0, 'object')} outside the report&apos;s scope, left out</div>
                  )}
                  {(scoped.counts.dangling_refs ?? 0) > 0 && (
                    <div>
                      {countOf(scoped.counts.dangling_refs ?? 0, 'reference')} {(scoped.counts.dangling_refs ?? 0) === 1 ? 'points' : 'point'} at ids the bundle does not hold
                    </div>
                  )}
                  {scoped.excluded.length > 0 && (
                    <details>
                      <summary style={{ cursor: 'pointer', color: 'var(--warn)' }}>
                        {countOf(scoped.excluded.length, 'invalid object')} will be ignored
                      </summary>
                      <ul style={{ margin: '6px 0 0', paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 3, fontFamily: MONO, fontSize: 11, color: 'var(--ink-3)' }}>
                        {scoped.excluded.map((e, i) => (
                          <li key={i} title={e.detail}>
                            {e.type} {shortId(e.id)} · {BASELINE_REASON_LABEL[e.reason] ?? e.reason}
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                  {scoped.warnings.filter(w => !w.startsWith(SCHEMAS_LATER)).map((w, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, color: 'var(--warn)' }}>
                      <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 2 }} />
                      <span>{w}</span>
                    </div>
                  ))}
                  {/* The preview never runs the JSON schemas (seconds per thousand
                      objects): the server's note about it is said plainly here. */}
                  <div style={{ color: 'var(--ink-4)' }}>
                    The STIX schemas are checked when the job starts: an object they refuse is left out then, and the job's log names it.
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Markings band */}
        <div style={{
          padding: '12px 18px', borderTop: '1px solid var(--rule)', flexShrink: 0,
          display: 'flex', flexDirection: 'column', gap: 9,
          background: marksSet ? 'var(--bg-elev)' : 'color-mix(in oklab, var(--warn) 6%, var(--bg-soft))',
          transition: 'background 120ms ease',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '.1em', textTransform: 'uppercase' as const, color: 'var(--ink-3)' }}>MARKINGS</span>
            <span style={{
              fontFamily: MONO, fontSize: 10, padding: '1px 6px', borderRadius: 4,
              // Ink, not --warn, on the amber tint: --warn there read at 3.6:1 (axe, WCAG 1.4.3).
              color: marksSet ? 'var(--ok)' : 'var(--ink-2)',
              background: marksSet ? 'color-mix(in oklab, var(--ok) 12%, transparent)' : 'color-mix(in oklab, var(--warn) 15%, transparent)',
            }}>{marksSet ? 'set' : 'required'}</span>
            <div style={{ flex: 1 }} />
            {/* --ink-3: the band's amber tint took --ink-4 below 4.5:1. */}
            <span style={{ fontSize: 10.5, color: 'var(--ink-3)' }}>{floor ? `at least ${floor}, from the bundle` : 'Applied to every object in the bundle'}</span>
          </div>
          {renderMarkingRow('TLP', TLP_DISPLAY_ORDER, tlp, setPickedTlp, 'TLP marking', minTlp ?? undefined)}
          {renderMarkingRow('PAP', PAP_DISPLAY_ORDER, pap, setPickedPap, 'PAP marking', minPap ?? undefined)}
        </div>

        </div>{/* end scrolling region */}

        {/* Footer — outside the scroll: Cancel and Submit stay on screen */}
        <div style={{
          padding: '11px 18px', borderTop: '1px solid var(--rule)', flexShrink: 0,
          background: 'var(--bg-elev)', display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <div style={{ flex: 1, fontFamily: MONO, fontSize: 11, color: 'var(--ink-3)' }}>{footer}</div>
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
