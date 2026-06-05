/**
 * GraphCanvas — SVG renderer with d3-force simulation.
 *
 * Design goals:
 *  - Pan/zoom written directly to the <g> transform (no React state per frame)
 *  - Simulation ticks update a posRef and increment a counter to re-render
 *  - Drag-to-pin: node.fx/fy during drag, released on pointerup
 *  - Neighbor-tracing: hovered/selected node + adjacency → everything else dims
 */
import { useRef, useState, useEffect, useCallback, useMemo, useImperativeHandle, forwardRef } from 'react'
// d3-force v3 is ESM-only; @types/d3-force doesn't resolve reliably through
// "moduleResolution: bundler".  All d3-force API calls are contained in
// makeSimulation() which accesses functions via `unknown` casts to avoid
// TypeScript's broken overload-resolution for this package.
import * as d3f from 'd3-force' // runtime import — types accessed via makeSimulation()
import { typeDot } from '../review/tokens'
import {
  type GraphNode, type GraphEdge, type PosMap,
  nodeRadius, getTier, layoutHierarchical, layoutRadial,
  typeStixIcon, typeIconPath,
} from './graphLayout'

// ── Simulation node / link shapes (minimal — only what d3 mutates) ──────────

export interface SimNode {
  id:   string
  x?:   number; y?:  number
  vx?:  number; vy?: number
  fx?:  number | null
  fy?:  number | null
  index?: number
}

interface SimLink {
  source: SimNode | string
  target: SimNode | string
}

// ── Build + configure a d3-force simulation (d3 types isolated here) ─────────
// All d3-force method calls are cast via `unknown` to avoid TypeScript's
// overload-resolution issues with this ESM-only package.

function makeSimulation(
  sNodes: SimNode[],
  sLinks: SimLink[],
  radii:  Record<string, number>,
): {
  on:          (event: string, fn: (nodes?: unknown) => void) => unknown
  tick:        (n: number) => unknown
  alpha:       (a: number) => { restart: () => void }
  alphaTarget: (a: number) => { restart?: () => void }
  restart:     () => void
  stop:        () => void
  nodes:       () => SimNode[]
  velocityDecay: (d: number) => unknown
  alphaDecay:    (d: number) => unknown
} {
  // Wrap each d3 factory call through `unknown` so TypeScript doesn't try to
  // narrow the return types through the broken overload resolution.
  const d = d3f as unknown as Record<string, (...args: unknown[]) => unknown>

  const charge  = d['forceManyBody']() as Record<string, (...a: unknown[]) => unknown>
  charge['strength'](-780)
  charge['distanceMax'](640)

  const link = d['forceLink'](sLinks) as Record<string, (...a: unknown[]) => unknown>
  link['id']((n: unknown) => (n as SimNode).id)
  link['distance'](92)
  link['strength'](() => 0.4)

  const collide = d['forceCollide'](
    (n: unknown) => (radii[(n as SimNode).id] || 12) + 16,
  ) as Record<string, (...a: unknown[]) => unknown>
  collide['iterations'](2)
  collide['strength'](0.9)

  const fx = d['forceX'](0) as Record<string, (...a: unknown[]) => unknown>
  fx['strength'](0.045)

  const fy = d['forceY'](0) as Record<string, (...a: unknown[]) => unknown>
  fy['strength'](0.045)

  const sim = d['forceSimulation'](sNodes) as Record<string, (...a: unknown[]) => unknown>
  sim['force']('charge',  charge)
  sim['force']('link',    link)
  sim['force']('collide', collide)
  sim['force']('x', fx)
  sim['force']('y', fy)
  sim['velocityDecay'](0.34)
  sim['alphaDecay'](0.026)

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return sim as any
}

// ── Helpers ────────────────────────────────────────────────────────────────

function bounds(pos: PosMap) {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const id in pos) {
    const p = pos[id]
    if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x
    if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y
  }
  return { minX, minY, maxX, maxY, w: maxX - minX, h: maxY - minY }
}

function phyllotaxis(i: number, scale = 30) {
  const a = i * 2.399963229
  const r = scale * Math.sqrt(i + 0.5)
  return { x: r * Math.cos(a), y: r * Math.sin(a) }
}

// ── Public handle exposed via ref ──────────────────────────────────────────

export interface GraphCanvasHandle {
  fit: (animate?: boolean) => void
}

// ── Props ──────────────────────────────────────────────────────────────────

interface Props {
  nodes:        GraphNode[]
  edges:        GraphEdge[]
  byId:         Map<string, GraphNode>
  deg:          Record<string, number>
  adj:          Record<string, Set<string>>
  layout:       'force' | 'hierarchical' | 'radial'
  visibleTypes: Set<string>
  selectedId:   string | null
  hoverId:      string | null
  showLabels:   boolean
  onSelect:     (id: string | null) => void
  onHover:      (id: string | null) => void
  focusSignal:  { id: string; seq: number } | null
}

// ── Component ──────────────────────────────────────────────────────────────

const GraphCanvas = forwardRef<GraphCanvasHandle, Props>(function GraphCanvas(
  { nodes, edges, byId, deg, adj, layout, visibleTypes, selectedId, hoverId,
    showLabels, onSelect, onHover, focusSignal },
  ref,
) {
  const svgRef    = useRef<SVGSVGElement>(null)
  const gRef      = useRef<SVGGElement>(null)
  const simRef    = useRef<ReturnType<typeof makeSimulation> | null>(null)
  const posRef    = useRef<PosMap>({})
  const [tick, setTick] = useState(0)
  const view      = useRef({ x: 0, y: 0, k: 1 })

  const repaint   = useCallback(() => setTick(t => t + 1), [])

  // ── Apply transform to <g> (direct DOM write — no React state) ─────────

  const applyView = useCallback(() => {
    const g = gRef.current; if (!g) return
    const { x, y, k } = view.current
    g.setAttribute('transform', `translate(${x} ${y}) scale(${k})`)
  }, [])

  // ── Fit to content ──────────────────────────────────────────────────────

  const fit = useCallback((animate = true) => {
    const svg = svgRef.current; if (!svg) return
    const b = bounds(posRef.current)
    if (!isFinite(b.w) || !isFinite(b.h) || b.w < 1) return
    const rect = svg.getBoundingClientRect()
    const pad  = 80
    const kRaw = Math.min((rect.width - pad * 2) / b.w, (rect.height - pad * 2) / b.h, 1.4)
    const kk   = Math.max(0.15, Math.min(kRaw, 1.4))
    const cx   = (b.minX + b.maxX) / 2
    const cy   = (b.minY + b.maxY) / 2
    const target = {
      x: rect.width  / 2 - cx * kk,
      y: rect.height / 2 - cy * kk,
      k: kk,
    }
    if (!animate) { view.current = target; applyView(); repaint(); return }
    const start = { ...view.current }, t0 = performance.now(), dur = 420
    const ease  = (t: number) => 1 - Math.pow(1 - t, 3)
    const step  = (now: number) => {
      const t = Math.min(1, (now - t0) / dur), e = ease(t)
      view.current = {
        x: start.x + (target.x - start.x) * e,
        y: start.y + (target.y - start.y) * e,
        k: start.k + (target.k - start.k) * e,
      }
      applyView()
      if (t < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [applyView, repaint])

  useImperativeHandle(ref, () => ({ fit }), [fit])

  // ── (Re)build layout / simulation when nodes, edges, or mode change ────

  useEffect(() => {
    if (simRef.current) { simRef.current.stop(); simRef.current = null }

    if (nodes.length === 0) return

    if (layout === 'force') {
      // Seed positions on a phyllotaxis spiral
      const prevPos = posRef.current
      const sNodes: SimNode[] = nodes.map((n, i) => {
        const seed = prevPos[n.id] ?? phyllotaxis(i)
        return { id: n.id, x: seed.x, y: seed.y }
      })
      const nodeById = new Map(sNodes.map(n => [n.id, n]))
      const sLinks: SimLink[] = edges
        .filter(e => nodeById.has(e.source) && nodeById.has(e.target))
        .map(e => ({
          source: e.source as unknown as SimNode,
          target: e.target as unknown as SimNode,
        }))

      const radii: Record<string, number> = {}
      nodes.forEach(n => { radii[n.id] = nodeRadius(n.type, deg[n.id] || 0) })

      // All d3-force API calls go through makeSimulation() which uses
      // unknown-cast wrappers to avoid TypeScript's overload-resolution
      // issues with this ESM-only package.
      const sim = makeSimulation(sNodes, sLinks, radii)

      sim.on('tick', () => {
        sNodes.forEach(d => { posRef.current[d.id] = { x: d.x ?? 0, y: d.y ?? 0 } })
        repaint()
      })

      simRef.current = sim

      // Light pre-spread so the opening frame isn't a clump
      sim.tick(60)
      sNodes.forEach(d => { posRef.current[d.id] = { x: d.x ?? 0, y: d.y ?? 0 } })
      repaint()
      sim.alpha(0.9).restart()

      const f1 = setTimeout(() => fit(true),  900)
      const f2 = setTimeout(() => fit(true), 1900)
      return () => { clearTimeout(f1); clearTimeout(f2); sim.stop() }
    } else {
      // Static layout
      posRef.current = layout === 'hierarchical'
        ? layoutHierarchical(nodes, edges, deg, adj)
        : layoutRadial(nodes, edges, deg, adj)
      repaint()
      const t = setTimeout(() => fit(false), 60)
      return () => clearTimeout(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout, nodes, edges])

  // ── Animate to a focused node on search pick ────────────────────────────

  useEffect(() => {
    if (!focusSignal?.id) return
    const p   = posRef.current[focusSignal.id]
    const svg = svgRef.current
    if (!p || !svg) return
    const rect   = svg.getBoundingClientRect()
    const k      = Math.max(view.current.k, 0.9)
    const target = { x: rect.width / 2 - p.x * k, y: rect.height / 2 - p.y * k, k }
    const start  = { ...view.current }, t0 = performance.now(), dur = 480
    const ease   = (t: number) => 1 - Math.pow(1 - t, 3)
    const step   = (now: number) => {
      const t = Math.min(1, (now - t0) / dur), e = ease(t)
      view.current = {
        x: start.x + (target.x - start.x) * e,
        y: start.y + (target.y - start.y) * e,
        k: start.k + (target.k - start.k) * e,
      }
      applyView()
      if (t < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
  }, [focusSignal, applyView])

  // ── Wheel zoom + background-drag pan ────────────────────────────────────

  useEffect(() => {
    const svg = svgRef.current; if (!svg) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const rect   = svg.getBoundingClientRect()
      const px = e.clientX - rect.left, py = e.clientY - rect.top
      const v  = view.current
      const nk = Math.max(0.15, Math.min(3.5, v.k * Math.exp(-e.deltaY * 0.0014)))
      const kr = nk / v.k
      v.x = px - (px - v.x) * kr
      v.y = py - (py - v.y) * kr
      v.k = nk
      applyView()
    }
    let drag: { x: number; y: number } | null = null
    const onDown = (e: PointerEvent) => {
      if ((e.target as Element).closest('[data-node]')) return
      drag = { x: e.clientX, y: e.clientY }
      svg.style.cursor = 'grabbing'
      onSelect(null)
    }
    const onMove = (e: PointerEvent) => {
      if (!drag) return
      view.current.x += e.clientX - drag.x
      view.current.y += e.clientY - drag.y
      drag.x = e.clientX; drag.y = e.clientY
      applyView()
    }
    const onUp = () => { drag = null; svg.style.cursor = '' }

    svg.addEventListener('wheel', onWheel, { passive: false })
    svg.addEventListener('pointerdown', onDown)
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
    return () => {
      svg.removeEventListener('wheel', onWheel)
      svg.removeEventListener('pointerdown', onDown)
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
    }
  }, [applyView, onSelect])

  // ── Node drag-to-pin ────────────────────────────────────────────────────

  const screenToWorld = useCallback((cx: number, cy: number) => {
    // svgRef.current can be null during unmount — guard before accessing
    const svg = svgRef.current
    if (!svg) return { x: 0, y: 0 }
    const rect = svg.getBoundingClientRect()
    const v    = view.current
    return { x: (cx - rect.left - v.x) / v.k, y: (cy - rect.top - v.y) / v.k }
  }, [])

  const onNodeDown = useCallback((e: React.PointerEvent, id: string) => {
    e.stopPropagation()
    const w  = screenToWorld(e.clientX, e.clientY)
    const p  = posRef.current[id] ?? { x: 0, y: 0 }
    const di = { id, dx: p.x - w.x, dy: p.y - w.y, moved: false }

    const move = (ev: PointerEvent) => {
      const w2 = screenToWorld(ev.clientX, ev.clientY)
      const nx = w2.x + di.dx, ny = w2.y + di.dy
      di.moved = true
      posRef.current[id] = { x: nx, y: ny }
      const sim = simRef.current
      if (sim) {
        const sn = sim.nodes().find((n: SimNode) => n.id === id)
        if (sn) { sn.fx = nx; sn.fy = ny; sim.alphaTarget(0.3).restart?.() }
      }
      repaint()
    }
    const up = () => {
      const sim = simRef.current
      if (sim) {
        const sn = sim.nodes().find((n: SimNode) => n.id === id)
        if (sn) { sn.fx = null; sn.fy = null; sim.alphaTarget(0) }
      }
      if (!di.moved) onSelect(id)
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }, [screenToWorld, repaint, onSelect])

  // ── Neighbor tracing ────────────────────────────────────────────────────

  const focusId = hoverId ?? selectedId
  const neighborSet = useMemo(() => {
    if (!focusId) return null
    const s = new Set([focusId])
    adj[focusId]?.forEach(n => s.add(n))
    return s
  }, [focusId, adj])

  // ── Render ──────────────────────────────────────────────────────────────

  const pos = posRef.current

  const validEdges = useMemo(
    () => edges.filter(e => byId.has(e.source) && byId.has(e.target) && e.accepted !== false),
    [edges, byId],
  )

  return (
    <svg
      ref={svgRef}
      style={{ display: 'block', width: '100%', height: '100%', cursor: 'grab', touchAction: 'none' }}
    >
      <defs>
        <marker id="gv-arrow" viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M0 0 L10 5 L0 10 z" fill="var(--rule)" />
        </marker>
        <marker id="gv-arrow-hot" viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 L10 5 L0 10 z" fill="var(--accent)" />
        </marker>
        <marker id="gv-arrow-dim" viewBox="0 0 10 10" refX="9" refY="5"
          markerWidth="5" markerHeight="5" orient="auto-start-reverse">
          <path d="M0 0 L10 5 L0 10 z" fill="var(--rule-soft)" />
        </marker>
      </defs>

      {/* Dotted grid background */}
      <defs>
        <pattern id="gv-grid" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="0.8" fill="var(--rule-soft)" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#gv-grid)" />

      <g ref={gRef}>
        {/* ── Edges ────────────────────────────────────────────────── */}
        {validEdges.map(e => {
          const a = pos[e.source], b = pos[e.target]
          if (!a || !b) return null
          const hot     = !!neighborSet && (e.source === focusId || e.target === focusId)
          const dim     = !!neighborSet && !hot
          const pending = e.accepted === null
          const hidden  = visibleTypes.size > 0 && (
            !visibleTypes.has(byId.get(e.source)?.type ?? '') ||
            !visibleTypes.has(byId.get(e.target)?.type ?? '')
          )
          if (hidden) return null
          return (
            <line
              key={e.id}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={hot ? 'var(--accent)' : dim ? 'var(--rule-soft)' : 'var(--rule)'}
              strokeWidth={hot ? 2 : 1.2}
              strokeDasharray={pending ? '5 4' : undefined}
              strokeOpacity={dim ? 0.25 : 1}
              markerEnd={hot ? 'url(#gv-arrow-hot)' : dim ? 'url(#gv-arrow-dim)' : 'url(#gv-arrow)'}
            />
          )
        })}

        {/* ── Nodes ────────────────────────────────────────────────── */}
        {nodes.map(n => {
          const p = pos[n.id]; if (!p) return null
          const r     = nodeRadius(n.type, deg[n.id] || 0)
          const fill  = typeDot(n.type)
          const dim   = (visibleTypes.size > 0 && !visibleTypes.has(n.type))
                     || (!!neighborSet && !neighborSet.has(n.id))
          const sel   = n.id === selectedId
          const hov   = n.id === hoverId
          const tier  = getTier(n.type)
          const showLbl = showLabels || tier <= 1 || sel || hov
                       || (!!neighborSet && neighborSet.has(n.id))
          const label = n.name.length > 26 ? n.name.slice(0, 24) + '…' : n.name

          return (
            <g
              key={n.id}
              data-node={n.id}
              transform={`translate(${p.x} ${p.y})`}
              style={{ opacity: dim ? 0.18 : 1, transition: 'opacity .18s', cursor: 'pointer' }}
              onPointerDown={ev => onNodeDown(ev, n.id)}
              onMouseEnter={() => onHover(n.id)}
              onMouseLeave={() => onHover(null)}
            >
              {/* Selection ring */}
              {sel && (
                <circle r={r + 6} fill="none"
                  stroke="var(--accent)" strokeWidth={2} opacity={0.85} />
              )}
              {/* Node circle */}
              <circle
                r={r}
                fill={fill}
                stroke={sel ? 'var(--accent)' : hov ? 'var(--ink-3)' : 'rgba(0,0,0,0.12)'}
                strokeWidth={sel ? 2.5 : 1.2}
              />
              {/* ── STIX type icon ─────────────────────────────────────────
                  Priority order:
                  1. Official OASIS STIX 2.1 inline paths (85×85 viewBox)
                     — path data extracted from White/normal/SVG/ of the
                       official stix-icons repository — rendered fill-based,
                       no external file load, works in all SVG contexts.
                  2. Lucide stroke path (24×24 viewBox)
                     — SCO types: ipv4, domain, url, email, file, …
                  3. First-letter glyph — last-resort fallback             */}
              {(() => {
                // ── Tier 1: official STIX SDO icon (inline paths) ───────────
                const stixIcon = typeStixIcon(n.type)
                if (stixIcon) {
                  // The paths live in an 85×85 space centred at (42.5, 42.5).
                  // Scale so the icon's own bounding radius (42.5) maps to
                  // r * 0.80, leaving a 20 % colour ring visible around it.
                  const s = (r * 0.80) / 42.5
                  return (
                    <g
                      transform={`scale(${s.toFixed(4)}) translate(-42.5 -42.5)`}
                      style={{ pointerEvents: 'none' }}
                    >
                      {stixIcon.d.map((d, i) => (
                        <path
                          key={i}
                          d={d}
                          fill="rgba(255,255,255,0.90)"
                          fillRule={stixIcon.evenodd ? 'evenodd' : 'nonzero'}
                        />
                      ))}
                    </g>
                  )
                }

                // ── Tier 2: lucide stroke path for SCOs ─────────────────────
                const iconPath = typeIconPath(n.type)
                if (iconPath) {
                  // Scale the 24×24 path so half-width 12 maps to r * 0.70.
                  const s  = (r * 0.70) / 12
                  const sw = Math.min(3.5, 1.5 / s)
                  return (
                    <path
                      d={iconPath}
                      fill="none"
                      stroke="rgba(255,255,255,0.88)"
                      strokeWidth={sw}
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      transform={`scale(${s.toFixed(4)}) translate(-12 -12)`}
                      style={{ pointerEvents: 'none' }}
                    />
                  )
                }

                // ── Tier 3: first-letter glyph (fallback) ──────────────────
                if (r >= 14) {
                  return (
                    <text
                      textAnchor="middle" dominantBaseline="central"
                      fill="rgba(255,255,255,0.90)"
                      style={{ fontSize: Math.round(r * 0.72), fontWeight: 700,
                               pointerEvents: 'none',
                               fontFamily: "'Source Serif 4', Georgia, serif" }}
                    >
                      {n.name[0]?.toUpperCase()}
                    </text>
                  )
                }
                return null
              })()}
              {/* Label */}
              {showLbl && (
                <text
                  y={r + 11}
                  textAnchor="middle"
                  fill={sel ? 'var(--accent)' : 'var(--ink-2)'}
                  style={{ fontSize: 10.5, pointerEvents: 'none',
                           fontFamily: 'Inter, system-ui, sans-serif',
                           paintOrder: 'stroke',
                           stroke: 'var(--bg)', strokeWidth: 3 }}
                >
                  {label}
                </text>
              )}
            </g>
          )
        })}
      </g>

      {/* Invisible tick-counter sink so React knows about `tick` */}
      {tick > 0 && null}
    </svg>
  )
})

export default GraphCanvas
