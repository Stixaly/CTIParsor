import { useState, useLayoutEffect } from 'react'
import type { Relationship } from '../../types'
import { hashHue } from './tokens'

interface Props {
  rels: Relationship[]
  show: boolean
  focusedRelId?: string | null
}

interface PathInfo {
  id: string
  d: string
  hue: number
  focused: boolean
}

export default function RelationshipOverlay({ rels, show, focusedRelId }: Props) {
  const [paths, setPaths] = useState<PathInfo[]>([])
  const [box, setBox] = useState({ w: 0, h: 0 })

  useLayoutEffect(() => {
    if (!show) { setPaths([]); return }

    const compute = () => {
      const doc = document.querySelector('.doc')
      if (!doc) return
      const docRect = doc.getBoundingClientRect()
      setBox({ w: docRect.width, h: (doc as HTMLElement).scrollHeight })

      const marks = document.querySelectorAll<HTMLElement>('.doc mark[data-eid]')
      const valueRect: Record<string, DOMRect> = {}
      marks.forEach(m => {
        const txt = (m.textContent ?? '').toLowerCase()
        if (!valueRect[txt]) valueRect[txt] = m.getBoundingClientRect()
      })

      const relevant = rels.filter(r => r.accepted !== false)
      const newPaths: PathInfo[] = []

      for (const r of relevant) {
        const srcRect = valueRect[r.source_value.toLowerCase()]
        const tgtRect = valueRect[r.target_value.toLowerCase()]
        if (!srcRect || !tgtRect) continue

        const x1 = srcRect.left + srcRect.width / 2 - docRect.left
        const y1 = srcRect.bottom - docRect.top + 2
        const x2 = tgtRect.left + tgtRect.width / 2 - docRect.left
        const y2 = tgtRect.top - docRect.top - 2

        const dy = y2 - y1
        const dx = x2 - x1
        const sideways = Math.abs(dy) < 24
        let d: string

        if (sideways) {
          const lift = 14 + Math.abs(dx) * 0.08
          d = `M ${x1} ${y1} C ${x1} ${y1 + lift}, ${x2} ${y2 + lift}, ${x2} ${y2}`
        } else {
          const gutterX = Math.max(-32, Math.min(x1, x2) - 28)
          d = `M ${x1} ${y1}
               C ${x1} ${y1 + 14}, ${gutterX} ${y1 + 14}, ${gutterX} ${y1 + 18}
               L ${gutterX} ${y2 - 18}
               C ${gutterX} ${y2 - 14}, ${x2} ${y2 - 14}, ${x2} ${y2}`
        }
        newPaths.push({
          id: r.id,
          d,
          hue: hashHue(r.relationship_type),
          focused: focusedRelId === r.id,
        })
      }
      setPaths(newPaths)
    }

    compute()
    const docEl = document.querySelector('.doc')
    if (!docEl) return
    const ro = new ResizeObserver(compute)
    ro.observe(docEl)
    window.addEventListener('scroll', compute, true)
    window.addEventListener('resize', compute)
    return () => {
      ro.disconnect()
      window.removeEventListener('scroll', compute, true)
      window.removeEventListener('resize', compute)
    }
  }, [rels, show, focusedRelId])

  if (!show) return null

  return (
    <svg className="rel-overlay" style={{ width: box.w, height: box.h }}>
      <defs>
        {paths.map(p => (
          <marker
            key={`m-${p.id}`}
            id={`arrowhead-${p.id}`}
            viewBox="0 0 10 10" refX="9" refY="5"
            markerWidth="6" markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill={`oklch(0.58 0.16 ${p.hue})`} />
          </marker>
        ))}
      </defs>
      {paths.map(p => (
        <g key={p.id} className={`rel-arrow ${p.focused ? 'focused' : ''}`}>
          <path
            d={p.d}
            fill="none"
            stroke={`oklch(0.58 0.16 ${p.hue})`}
            strokeWidth={p.focused ? 2.4 : 1.4}
            strokeOpacity={p.focused ? 1 : 0.55}
            strokeLinecap="round"
            markerEnd={`url(#arrowhead-${p.id})`}
          />
        </g>
      ))}
    </svg>
  )
}
