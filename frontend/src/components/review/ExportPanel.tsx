import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchExportFacets, buildExportUrl } from '../../api/client'
import type { ExportFacet, ExportFacets, ExportAxis, ExportSelection } from '../../types'

const AXES: ExportAxis[] = ['format', 'severity', 'license', 'corpus']

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
    padding: 20,
    backgroundColor: 'var(--bg-elev)',
    border: '1px solid var(--rule-soft)',
    borderRadius: 8,
  } as React.CSSProperties,
  header: {
    margin: 0,
    fontSize: 16,
    fontWeight: 600,
    color: 'var(--ink)',
  } as React.CSSProperties,
  subtitle: {
    margin: 0,
    fontSize: 12,
    color: 'var(--ink-3)',
  } as React.CSSProperties,
  axisTitle: {
    margin: 0,
    fontSize: 11,
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: 'var(--ink-3)',
    marginBottom: 8,
  } as React.CSSProperties,
  chip: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '4px 10px',
    margin: '0 6px 6px 0',
    border: '1px solid var(--rule)',
    borderRadius: 4,
    backgroundColor: 'var(--bg-soft)',
    color: 'var(--ink-2)',
    cursor: 'pointer',
    fontSize: 13,
    transition: 'border-color 0.15s, color 0.15s',
  } as React.CSSProperties,
  chipSelected: {
    borderColor: 'var(--accent)',
    color: 'var(--accent)',
  } as React.CSSProperties,
  chipCount: {
    fontSize: 11,
    color: 'var(--ink-4)',
  } as React.CSSProperties,
  chipCountSelected: {
    fontSize: 11,
    color: 'var(--accent)',
    opacity: 0.8,
  } as React.CSSProperties,
  warnLabel: {
    fontSize: 10,
    color: 'var(--warn)',
    fontWeight: 500,
  } as React.CSSProperties,
  actionRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    marginTop: 8,
  } as React.CSSProperties,
  downloadBtn: {
    display: 'inline-block',
    padding: '8px 16px',
    backgroundColor: 'var(--accent)',
    color: '#fff',
    borderRadius: 4,
    textDecoration: 'none',
    fontSize: 14,
    fontWeight: 500,
    cursor: 'pointer',
  } as React.CSSProperties,
  selectedLabel: {
    fontSize: 12,
    color: 'var(--ink-3)',
  } as React.CSSProperties,
  resetLink: {
    fontSize: 12,
    color: 'var(--ink-3)',
    cursor: 'pointer',
    textDecoration: 'underline',
    background: 'none',
    border: 'none',
    padding: 0,
  } as React.CSSProperties,
  footer: {
    margin: 0,
    fontSize: 11.5,
    color: 'var(--ink-4)',
    lineHeight: 1.5,
  } as React.CSSProperties,
  empty: {
    fontSize: 14,
    color: 'var(--ink-3)',
    padding: '12px 0',
  } as React.CSSProperties,
  loading: {
    fontSize: 14,
    color: 'var(--ink-3)',
    padding: '12px 0',
  } as React.CSSProperties,
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KB`
  return `${(n / 1024 ** 2).toFixed(1)} MB`
}

function selectedLabel(facets: ExportFacets, sel: ExportSelection): string {
  const activeAxes = AXES.filter((axis) => sel[axis].length > 0)
  if (activeAxes.length === 0) return String(facets.total)
  let min = Infinity
  for (const axis of activeAxes) {
    const sum = sel[axis].reduce((acc: number, val: string) => {
      const facet = facets[axis].find((f: ExportFacet) => f.value === val)
      return acc + (facet ? facet.rules : 0)
    }, 0)
    if (sum < min) min = sum
  }
  return `≤ ${min}`
}

export default function ExportPanel({ jobId }: { jobId: string }) {
  const { data: facets, isLoading } = useQuery({
    queryKey: ['export-facets', jobId],
    queryFn: () => fetchExportFacets(jobId),
  })

  const [sel, setSel] = useState<ExportSelection>({
    format: [],
    corpus: [],
    license: [],
    severity: [],
  })

  const toggle = (axis: ExportAxis, value: string) => {
    setSel((prev: ExportSelection) => {
      const current = prev[axis]
      const next = current.includes(value)
        ? current.filter((v: string) => v !== value)
        : [...current, value]
      return { ...prev, [axis]: next }
    })
  }

  const reset = () => {
    setSel({ format: [], corpus: [], license: [], severity: [] })
  }

  if (isLoading) {
    return (
      <div style={styles.container}>
        <p style={styles.loading}>Loading…</p>
      </div>
    )
  }

  if (!facets) {
    return (
      <div style={styles.container}>
        <p style={styles.empty}>No detection rules match this report.</p>
      </div>
    )
  }

  if (facets.total === 0) {
    return (
      <div style={styles.container}>
        <h3 style={styles.header}>Export detection rules</h3>
        <p style={styles.empty}>No detection rules match this report.</p>
      </div>
    )
  }

  const hasSelection = AXES.some((axis) => sel[axis].length > 0)
  const label = selectedLabel(facets, sel)
  const titleAttr = hasSelection
    ? 'Axes combine with AND; the actual total may be lower than this upper bound.'
    : undefined

  return (
    <div style={styles.container}>
      <h3 style={styles.header}>Export detection rules</h3>
      <p style={styles.subtitle}>
        {facets.total} rules · {fmtBytes(facets.bytes)} available
      </p>

      {AXES.map((axis) => {
        const values = facets[axis]
        if (values.length === 0) return null
        return (
          <div key={axis}>
            <p style={styles.axisTitle}>{axis}</p>
            <div>
              {values.map((f: ExportFacet) => {
                const isSelected = sel[axis].includes(f.value)
                const isLicenseNone = axis === 'license' && f.value === 'none'
                return (
                  <button
                    key={f.value}
                    type="button"
                    style={{
                      ...styles.chip,
                      ...(isSelected ? styles.chipSelected : {}),
                    }}
                    onClick={() => toggle(axis, f.value)}
                    title={
                      isLicenseNone
                        ? 'These rules are all rights reserved and must not be redistributed.'
                        : undefined
                    }
                  >
                    <span>{f.value}</span>
                    <span style={isSelected ? styles.chipCountSelected : styles.chipCount}>
                      {f.rules}
                    </span>
                    {isLicenseNone && (
                      <span style={styles.warnLabel}>all rights reserved</span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        )
      })}

      <div style={styles.actionRow}>
        <a
          href={buildExportUrl(jobId, sel)}
          download
          style={styles.downloadBtn}
          className="btn-primary"
        >
          Download ZIP
        </a>
        <span style={styles.selectedLabel} title={titleAttr}>
          {label} rules selected
        </span>
        {hasSelection && (
          <button type="button" style={styles.resetLink} className="link" onClick={reset}>
            Reset
          </button>
        )}
      </div>

      <p style={styles.footer}>
        Each rule retains its original license. The MANIFEST lists the license and source per
        rule. Rules marked <em>all rights reserved</em> must not be redistributed.
      </p>
    </div>
  )
}
