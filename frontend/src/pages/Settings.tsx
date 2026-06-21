import { useState } from 'react'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { addCorpus, fetchCorpora, rebuildCorpora, removeCorpus, syncCorpus } from '../api/client'
import type { CorpusConfig } from '../types'

export default function Settings() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({ queryKey: ['corpora'], queryFn: fetchCorpora })
  const [name, setName] = useState('')
  const [git, setGit] = useState('')
  const [license, setLicense] = useState('DRL-1.1')
  const [msg, setMsg] = useState<string | null>(null)

  const invalidate = () => qc.invalidateQueries({ queryKey: ['corpora'] })

  const add = useMutation({
    mutationFn: () => addCorpus({ name: name.trim(), git: git.trim() || undefined, license }),
    onSuccess: () => { setName(''); setGit(''); setMsg('Added. Run `python scripts/sync_corpora.py`, then Rebuild.'); invalidate() },
    onError: (e: Error) => setMsg(`Add failed: ${e.message}`),
  })
  const remove = useMutation({
    mutationFn: (n: string) => removeCorpus(n),
    onSuccess: invalidate,
  })
  const sync = useMutation({
    mutationFn: (n: string) => syncCorpus(n),
    onSuccess: () => { setMsg('Downloaded & re-ingested.'); invalidate() },
    onError: (e: Error) => setMsg(`Download failed: ${e.message}`),
  })
  const rebuild = useMutation({
    mutationFn: rebuildCorpora,
    onSuccess: r => { setMsg(`Ingested ${r.total} rules${r.skipped.length ? ` · skipped (no clone): ${r.skipped.join(', ')}` : ''}.`); invalidate() },
    onError: (e: Error) => setMsg(`Rebuild failed: ${e.message}`),
  })

  const corpora: CorpusConfig[] = data?.corpora ?? []
  const cell: React.CSSProperties = { padding: '7px 10px', borderBottom: '1px solid var(--rule-soft)', fontSize: 13 }

  return (
    <div style={{ padding: '22px 28px', maxWidth: 880, color: 'var(--ink)' }}>
      <h1 style={{ fontSize: 19, margin: '0 0 2px' }}>Settings</h1>
      <p style={{ color: 'var(--ink-3)', fontSize: 13, marginTop: 0 }}>Manage detection-rule corpora used for coverage.</p>

      <h2 style={{ fontSize: 14, marginTop: 22, marginBottom: 8 }}>Detection Corpora (Sigma)</h2>

      <div style={{ background: 'var(--bg-elev)', border: '1px solid var(--rule)', borderRadius: 9, overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 2fr 0.9fr 70px 150px', background: 'var(--bg-soft)', fontSize: 11, fontWeight: 600, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: 0.3 }}>
          <div style={cell}>Name</div><div style={cell}>Repo</div><div style={cell}>License</div><div style={cell}>Rules</div><div style={cell} />
        </div>
        {isLoading && <div style={{ ...cell, color: 'var(--ink-3)' }}>Loading…</div>}
        {!isLoading && corpora.length === 0 && <div style={{ ...cell, color: 'var(--ink-3)' }}>No corpora configured.</div>}
        {corpora.map(c => (
          <div key={c.name} style={{ display: 'grid', gridTemplateColumns: '1.4fr 2fr 0.9fr 70px 150px', alignItems: 'center', opacity: c.enabled ? 1 : 0.5 }}>
            <div style={cell}>
              <strong>{c.name}</strong>
              {c.private && <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--warn)' }}>private</span>}
              {!c.enabled && <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--ink-4)' }}>disabled</span>}
            </div>
            <div style={{ ...cell, color: 'var(--ink-3)', fontFamily: 'monospace', fontSize: 11.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.git ?? c.path ?? '—'}</div>
            <div style={cell}>{c.license}</div>
            <div style={cell}>{c.rules}</div>
            <div style={{ ...cell, display: 'flex', gap: 12 }}>
              {c.git && !c.private && (
                <button
                  onClick={() => sync.mutate(c.name)}
                  disabled={sync.isPending}
                  title="git clone/pull this corpus, then re-ingest"
                  className="link"
                  style={{ color: 'var(--accent)', background: 'none', border: 'none', cursor: sync.isPending ? 'default' : 'pointer', fontSize: 12 }}
                >
                  {sync.isPending && sync.variables === c.name ? 'Downloading…' : 'Redownload'}
                </button>
              )}
              <button onClick={() => remove.mutate(c.name)} className="link" style={{ color: 'var(--no)', background: 'none', border: 'none', cursor: 'pointer', fontSize: 12 }}>Remove</button>
            </div>
          </div>
        ))}
      </div>

      {/* Add a corpus */}
      <div style={{ marginTop: 16, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>Name<br />
          <input value={name} onChange={e => setName(e.target.value)} placeholder="my-sigma" style={inp} />
        </label>
        <label style={{ fontSize: 12, color: 'var(--ink-3)', flex: 1, minWidth: 240 }}>Git URL (public or SSH)<br />
          <input value={git} onChange={e => setGit(e.target.value)} placeholder="https://github.com/org/sigma.git" style={{ ...inp, width: '100%' }} />
        </label>
        <label style={{ fontSize: 12, color: 'var(--ink-3)' }}>License<br />
          <input value={license} onChange={e => setLicense(e.target.value)} style={{ ...inp, width: 110 }} />
        </label>
        <button onClick={() => add.mutate()} disabled={!name.trim() || add.isPending} className="btn-primary" style={btn}>Add</button>
      </div>

      <div style={{ marginTop: 18, display: 'flex', alignItems: 'center', gap: 12 }}>
        <button onClick={() => rebuild.mutate()} disabled={rebuild.isPending} className="btn-primary" style={btn}>
          {rebuild.isPending ? 'Rebuilding…' : 'Rebuild index'}
        </button>
        {msg && <span style={{ fontSize: 12.5, color: 'var(--ink-2)' }}>{msg}</span>}
      </div>

      <p style={{ fontSize: 11.5, color: 'var(--ink-4)', marginTop: 14, lineHeight: 1.5 }}>
        New repos are written to <code>detection_corpora.local.yaml</code> (gitignored). Click <strong>Redownload</strong>
        {' '}on a public corpus to <code>git clone/pull</code> and ingest it in place, or fetch every clone at once with
        {' '}<code>python scripts/sync_corpora.py</code> then <strong>Rebuild index</strong>. Private corpora are
        {' '}CLI-only (keeps git credentials out of the app). Coverage is then available on each report's Coverage view.
      </p>
    </div>
  )
}

const inp: React.CSSProperties = {
  marginTop: 3, padding: '6px 9px', borderRadius: 6, border: '1px solid var(--rule)',
  background: 'var(--bg-elev)', color: 'var(--ink)', fontSize: 13,
}
const btn: React.CSSProperties = { padding: '7px 16px', borderRadius: 7, fontSize: 13, cursor: 'pointer' }
