import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchCorpora, fetchFormats, addCorpus, setCorpusEnabled, removeCorpus, syncCorpus, rebuildCorpora } from '../api/client'
import type { CorpusConfig, FormatInfo } from '../types'

const inp: React.CSSProperties = {
  padding: '6px 8px',
  border: '1px solid var(--rule)',
  borderRadius: 4,
  background: 'var(--bg-soft)',
  color: 'var(--ink)',
  fontSize: 13,
}

const btn: React.CSSProperties = {
  padding: '5px 10px',
  border: '1px solid var(--rule)',
  borderRadius: 4,
  background: 'var(--bg-elev)',
  color: 'var(--ink)',
  fontSize: 12,
  cursor: 'pointer',
}

export default function Settings() {
  const qc = useQueryClient()
  const { data: corporaData } = useQuery({ queryKey: ['corpora'], queryFn: fetchCorpora })
  const { data: formatsData } = useQuery({ queryKey: ['formats'], queryFn: fetchFormats })

  const corpora: CorpusConfig[] = corporaData?.corpora ?? []
  const formats: FormatInfo[] = formatsData?.formats ?? []

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['corpora'] })
    qc.invalidateQueries({ queryKey: ['formats'] })
  }

  const add = useMutation({
    mutationFn: (body: { name: string; adapter: string; git?: string; tarball?: string; subdir?: string; license?: string; priority?: number; private?: boolean }) => addCorpus(body),
    onSuccess: invalidate,
  })
  const remove = useMutation({
    mutationFn: (name: string) => removeCorpus(name),
    onSuccess: invalidate,
  })
  const sync = useMutation({
    mutationFn: (name: string) => syncCorpus(name),
    onSuccess: invalidate,
  })
  const rebuild = useMutation({
    mutationFn: () => rebuildCorpora(),
    onSuccess: invalidate,
  })
  const toggle = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) => setCorpusEnabled(v.name, v.enabled),
    onSuccess: invalidate,
  })

  const [name, setName] = useState<string>('')
  const [adapter, setAdapter] = useState<string>('sigma')
  const [srcType, setSrcType] = useState<string>('git')
  const [url, setUrl] = useState<string>('')
  const [subdir, setSubdir] = useState<string>('')
  const [license, setLicense] = useState<string>('unknown')
  const [priority, setPriority] = useState<string>('')
  const [msg, setMsg] = useState<string>('')

  const firstAvailable = formats.find((f) => f.available)?.format ?? 'sigma'
  const selectedFormat = formats.find((f) => f.format === adapter)
  const formatAvailable = selectedFormat ? selectedFormat.available : false

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const body: { name: string; adapter: string; git?: string; tarball?: string; subdir?: string; license?: string; priority?: number; private?: boolean } = {
      name: name.trim(),
      adapter,
      license: license.trim() || 'unknown',
    }
    if (srcType === 'git') body.git = url.trim()
    else body.tarball = url.trim()
    if (subdir.trim()) body.subdir = subdir.trim()
    const p = Number(priority)
    if (priority.trim() !== '' && Number.isFinite(p)) body.priority = p
    add.mutate(body, {
      onSuccess: () => {
        setName('')
        setUrl('')
        setSubdir('')
        setLicense('unknown')
        setPriority('')
      },
    })
  }

  const orderedFormats: FormatInfo[] = [...formats]
  const known = new Set(orderedFormats.map((f) => f.format))
  // Deduplicate: `corpora.map(c => c.adapter)` yields one entry PER CORPUS, not per
  // distinct format. Without the Set, any format missing from `formats` — which is
  // every format while the query is loading, or if /settings/formats is unreachable —
  // produced one group per corpus: sigma rendered 8 times, yara 5, suricata 2.
  const extra = [...new Set(corpora.map((c) => c.adapter))]
    .filter((a) => !known.has(a))
    .sort()
    .map((a) => ({ format: a, available: false, corpora: 0, rules: 0 }))
  const allFormats = [...orderedFormats, ...extra]

  const groups = allFormats.map((f) => {
    const items = corpora.filter((c) => c.adapter === f.format)
    return { format: f.format, available: f.available, items, totalRules: items.reduce((s, c) => s + c.rules, 0) }
  })

  const gridCols: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '1.5fr 2fr 0.9fr 0.4fr 0.5fr 190px',
    gap: '8px',
    alignItems: 'center',
    padding: '8px 0',
    borderBottom: '1px solid var(--rule-soft)',
  }

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: '24px 16px' }}>
      <h1 style={{ margin: 0, fontSize: 22, color: 'var(--ink)' }}>Settings</h1>
      <p style={{ margin: '6px 0 16px', color: 'var(--ink-3)', fontSize: 13 }}>
        Manage detection-rule corpora used for coverage and proposals.
      </p>

      {formats.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 20 }}>
          {formats.map((f) => (
            <div
              key={f.format}
              title={
                f.available
                  ? undefined
                  : 'No parser for this format in this build — repos can be configured but will not ingest until the adapter ships.'
              }
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '5px 10px',
                border: '1px solid var(--rule)',
                borderRadius: 999,
                background: 'var(--bg-elev)',
                opacity: f.available ? 1 : 0.55,
                fontSize: 12,
                color: 'var(--ink-2)',
              }}
            >
              <strong style={{ color: 'var(--ink)' }}>{f.format}</strong>
              <span>
                {f.corpora} repos · {f.rules} rules
              </span>
              {!f.available && (
                <span style={{ color: 'var(--warn)', fontSize: 11 }}>adapter unavailable</span>
              )}
            </div>
          ))}
        </div>
      )}

      {groups.map((g) => (
        <div key={g.format} style={{ marginBottom: 24 }}>
          <h3 style={{ margin: '0 0 4px', fontSize: 13, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--ink-2)' }}>
            {g.format}
            <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--ink-4)', textTransform: 'none', letterSpacing: 0 }}>
              {g.items.length} repos · {g.totalRules} rules
            </span>
          </h3>
          <div style={gridCols}>
            <span style={{ color: 'var(--ink-3)', fontSize: 11 }}>Name</span>
            <span style={{ color: 'var(--ink-3)', fontSize: 11 }}>Source</span>
            <span style={{ color: 'var(--ink-3)', fontSize: 11 }}>License</span>
            <span style={{ color: 'var(--ink-3)', fontSize: 11 }}>Prio</span>
            <span style={{ color: 'var(--ink-3)', fontSize: 11 }}>Rules</span>
            <span />
          </div>
          {g.items.map((c) => (
            <div key={c.name} style={{ ...gridCols, opacity: c.enabled ? 1 : 0.5 }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
                <strong style={{ color: 'var(--ink)', fontSize: 13 }}>{c.name}</strong>
                {c.private && (
                  <span style={{ fontSize: 10, color: 'var(--warn)', border: '1px solid var(--warn)', borderRadius: 3, padding: '1px 4px' }}>
                    private
                  </span>
                )}
                {!c.enabled && (
                  <span style={{ fontSize: 10, color: 'var(--ink-4)', border: '1px solid var(--ink-4)', borderRadius: 3, padding: '1px 4px' }}>
                    disabled
                  </span>
                )}
                {!c.adapter_available && (
                  <span style={{ fontSize: 10, color: 'var(--warn)', border: '1px solid var(--warn)', borderRadius: 3, padding: '1px 4px' }}>
                    adapter unavailable
                  </span>
                )}
                {c.subdir && (
                  <span style={{ fontSize: 10, color: 'var(--ink-4)', fontFamily: 'monospace' }}>/
                    {c.subdir}
                  </span>
                )}
              </div>
              <div
                style={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  fontFamily: 'monospace',
                  fontSize: 11.5,
                  color: 'var(--ink-2)',
                }}
              >
                {c.tarball && (
                  <span style={{ color: 'var(--ink-4)', marginRight: 6, fontSize: 10 }}>tarball</span>
                )}
                {c.git ?? c.tarball ?? c.path ?? '—'}
              </div>
              <span style={{ fontSize: 12, color: 'var(--ink-2)' }}>{c.license}</span>
              <span style={{ fontSize: 12, color: 'var(--ink-2)' }}>{c.priority ?? '—'}</span>
              <span style={{ fontSize: 12, color: 'var(--ink-2)' }}>{c.rules}</span>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <button
                  type="button"
                  style={btn}
                  onClick={() => toggle.mutate({ name: c.name, enabled: !c.enabled })}
                >
                  {c.enabled ? 'Disable' : 'Enable'}
                </button>
                {c.git && !c.private && (
                  <button
                    type="button"
                    style={btn}
                    disabled={sync.isPending}
                    onClick={() => sync.mutate(c.name)}
                  >
                    {sync.isPending && sync.variables === c.name ? 'Downloading…' : 'Redownload'}
                  </button>
                )}
                <button
                  type="button"
                  style={{ ...btn, color: 'var(--no)', borderColor: 'var(--no)' }}
                  onClick={() => remove.mutate(c.name)}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>
      ))}

      <form
        onSubmit={submit}
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 10,
          alignItems: 'flex-end',
          padding: 16,
          border: '1px solid var(--rule)',
          borderRadius: 6,
          background: 'var(--bg-elev)',
          marginBottom: 24,
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>Name</label>
          <input style={inp} value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>Format</label>
          <select style={inp} value={adapter} onChange={(e) => setAdapter(e.target.value)}>
            {formats.map((f) => (
              <option key={f.format} value={f.format} disabled={!f.available}>
                {f.format}
                {f.available ? '' : ' (adapter unavailable)'}
              </option>
            ))}
          </select>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>Source type</label>
          <select style={inp} value={srcType} onChange={(e) => setSrcType(e.target.value)}>
            <option value="git">git</option>
            <option value="tarball">tarball</option>
          </select>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>URL</label>
          <input
            style={inp}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={srcType === 'git' ? 'https://github.com/org/rules.git' : 'https://example.com/rules.tar.gz'}
          />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>Subdir</label>
          <input style={{ ...inp, width: 90 }} value={subdir} onChange={(e) => setSubdir(e.target.value)} placeholder="yara" />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>License</label>
          <input style={{ ...inp, width: 110 }} value={license} onChange={(e) => setLicense(e.target.value)} />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>Priority</label>
          <input
            style={{ ...inp, width: 70 }}
            type="number"
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
            placeholder="100"
          />
        </div>
        <button
          type="submit"
          className="btn-primary"
          disabled={!name.trim() || !formatAvailable || add.isPending}
        >
          Add
        </button>
      </form>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button
          type="button"
          className="btn-primary"
          disabled={rebuild.isPending}
          onClick={() =>
            rebuild.mutate(undefined, {
              onSuccess: (r) => setMsg(`Rebuilt: ${r.total} total, ${Object.values(r.written).reduce((s, n) => s + n, 0)} written, ${r.skipped.length} skipped.`),
            })
          }
        >
          {rebuild.isPending ? 'Rebuilding…' : 'Rebuild index'}
        </button>
        {msg && <span style={{ fontSize: 12, color: 'var(--ink-3)' }}>{msg}</span>}
      </div>

      <p style={{ marginTop: 16, fontSize: 12, color: 'var(--ink-3)', lineHeight: 1.6 }}>
        Each corpus is cloned into a gitignored overlay directory; <span className="link">Redownload</span> re-fetches the
        remote without touching local edits. Bulk refresh is available via{' '}
        <code style={{ fontFamily: 'monospace', fontSize: 11 }}>scripts/sync_corpora.py</code>. Private corpora are
        managed through the CLI and cannot be added or removed from this panel. Formats marked{' '}
        <span style={{ color: 'var(--warn)' }}>adapter unavailable</span> can be configured now but will not ingest any
        rules until their parser ships.
      </p>
    </div>
  )
}
