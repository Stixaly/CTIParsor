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
  typeStixIcon, typeIconPath, parallelOffsets, edgePath,
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
  /** Types switched off in the legend — dimmed.  Empty = every type shown;
   *  every type in it = none shown (an empty "visible" set used to mean both). */
  hiddenTypes:  Set<string>
  selectedId:   string | null
  hoverId:      string | null
  showLabels:   boolean
  onSelect:     (id: string | null) => void
  onHover:      (id: string | null) => void
  focusSignal:  { id: string; seq: number } | null
}

// ── Component ──────────────────────────────────────────────────────────────

const GraphCanvas = forwardRef<GraphCanvasHandle, Props>(function GraphCanvas(
  { nodes, edges, byId, deg, adj, layout, hiddenTypes, selectedId, hoverId,
    showLabels, onSelect, onHover, focusSignal },
  ref,
) {
  const svgRef    = useRef<SVGSVGElement>(null)
  const gRef      = useRef<SVGGElement>(null)
  const simRef    = useRef<ReturnType<typeof makeSimulation> | null>(null)
  const posRef    = useRef<PosMap>({})
  const [tick, setTick] = useState(0)
  const view      = useRef({ x: 0, y: 0, k: 1 })
  // Set once the user pans, zooms, drags a node or picks a search result:
  // automatic fits (the settle-in fits, a resize, a data refresh) then leave
  // the view alone.  Cleared by a layout change and by the Fit button.
  const userMoved = useRef(false)
  // Bumped to cancel a running view animation when the user takes over.
  const animSeq   = useRef(0)
  const lastLayout = useRef<Props['layout'] | null>(null)

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
    if (!isFinite(b.minX) || !isFinite(b.minY)) return
    const rect = svg.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return
    // A lone node, or nodes in one row or column, has no extent on an axis —
    // it used to abort the fit and leave the node in the top-left corner.
    // Give each axis a node's worth so the scale stays finite and centred.
    const w    = Math.max(b.w, 60), h = Math.max(b.h, 60)
    const pad  = Math.min(80, rect.width / 6, rect.height / 6)
    const kRaw = Math.min((rect.width - pad * 2) / w, (rect.height - pad * 2) / h, 1.4)
    const kk   = Math.max(0.15, Math.min(kRaw, 1.4))
    const cx   = (b.minX + b.maxX) / 2
    const cy   = (b.minY + b.maxY) / 2
    const target = {
      x: rect.width  / 2 - cx * kk,
      y: rect.height / 2 - cy * kk,
      k: kk,
    }
    const seq = ++animSeq.current
    if (!animate) { view.current = target; applyView(); repaint(); return }
    const start = { ...view.current }, t0 = performance.now(), dur = 420
    const ease  = (t: number) => 1 - Math.pow(1 - t, 3)
    const step  = (now: number) => {
      if (seq !== animSeq.current) return
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

  // An explicit Fit hands the view back to the automatic fits.
  useImperativeHandle(ref, () => ({
    fit: (animate = true) => { userMoved.current = false; fit(animate) },
  }), [fit])

  // Edges the graph actually draws, and that the layout pulls on: resolved
  // endpoints, not rejected.  A rejected link used to keep pulling its nodes
  // together (and count towards their size) after it was no longer drawn.
  const activeEdges = useMemo(
    () => edges.filter(e => byId.has(e.source) && byId.has(e.target) && e.accepted !== false),
    [edges, byId],
  )

  // ── (Re)build layout / simulation when nodes, edges, or mode change ────

  useEffect(() => {
    if (simRef.current) { simRef.current.stop(); simRef.current = null }

    // A layout change is a request for a fresh view; a data refresh (an
    // accepted or rejected link refetches everything) is not.
    if (lastLayout.current !== layout) { userMoved.current = false; lastLayout.current = layout }
    const autoFit = (animate: boolean) => { if (!userMoved.current) fit(animate) }

    // Keep only the current nodes' positions: removed entities used to stay
    // in posRef and pull Fit towards where they had been.
    const prevPos = posRef.current
    const kept: PosMap = {}
    for (const n of nodes) if (prevPos[n.id]) kept[n.id] = prevPos[n.id]
    posRef.current = kept

    if (nodes.length === 0) return

    if (layout === 'force') {
      // Seed positions on a phyllotaxis spiral
      const allSeeded = nodes.every(n => kept[n.id])
      const sNodes: SimNode[] = nodes.map((n, i) => {
        const seed = kept[n.id] ?? phyllotaxis(i)
        return { id: n.id, x: seed.x, y: seed.y }
      })
      const nodeById = new Map(sNodes.map(n => [n.id, n]))
      const sLinks: SimLink[] = activeEdges
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

      // Light pre-spread so the opening frame isn't a clump.  When every node
      // already has a place (a refresh), only nudge them: a full restart
      // reshuffled the whole graph after each accepted or rejected link.
      if (!allSeeded) sim.tick(60)
      sNodes.forEach(d => { posRef.current[d.id] = { x: d.x ?? 0, y: d.y ?? 0 } })
      repaint()
      sim.alpha(allSeeded ? 0.3 : 0.9).restart()

      // Frame the opening layout at once (it used to sit around the canvas's
      // top-left corner until the first fit), then follow it as it settles.
      autoFit(false)
      const f1 = setTimeout(() => autoFit(true),  900)
      const f2 = setTimeout(() => autoFit(true), 1900)
      return () => { clearTimeout(f1); clearTimeout(f2); sim.stop() }
    } else {
      // Static layout
      posRef.current = layout === 'hierarchical'
        ? layoutHierarchical(nodes, activeEdges, deg, adj)
        : layoutRadial(nodes, activeEdges, deg, adj)
      repaint()
      const t = setTimeout(() => autoFit(false), 60)
      return () => clearTimeout(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout, nodes, activeEdges])

  // ── Keep the content framed when the canvas is resized ─────────────────
  // (window resize, a side panel opening).  If the user has placed the view,
  // keep what was at the centre at the centre instead of refitting.

  useEffect(() => {
    const svg = svgRef.current
    if (!svg || typeof ResizeObserver === 'undefined') return
    let last = { w: svg.clientWidth, h: svg.clientHeight }
    const ro = new ResizeObserver(() => {
      const w = svg.clientWidth, h = svg.clientHeight
      if (w === last.w && h === last.h) return
      if (userMoved.current) {
        view.current.x += (w - last.w) / 2
        view.current.y += (h - last.h) / 2
        applyView()
      } else {
        fit(false)
      }
      last = { w, h }
    })
    ro.observe(svg)
    return () => ro.disconnect()
  }, [fit, applyView])

  // ── Animate to a focused node on search pick ────────────────────────────

  useEffect(() => {
    if (!focusSignal?.id) return
    const p   = posRef.current[focusSignal.id]
    const svg = svgRef.current
    if (!p || !svg) return
    userMoved.current = true
    const seq    = ++animSeq.current
    const rect   = svg.getBoundingClientRect()
    const k      = Math.max(view.current.k, 0.9)
    const target = { x: rect.width / 2 - p.x * k, y: rect.height / 2 - p.y * k, k }
    const start  = { ...view.current }, t0 = performance.now(), dur = 480
    const ease   = (t: number) => 1 - Math.pow(1 - t, 3)
    const step   = (now: number) => {
      if (seq !== animSeq.current) return
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
    // Any hands-on move of the view cancels the pending automatic fits and
    // any animation still running — they used to snap the view back.
    const takeOver = () => { userMoved.current = true; animSeq.current++ }
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      takeOver()
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
      if (e.clientX !== drag.x || e.clientY !== drag.y) takeOver()
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
      if (!di.moved) { userMoved.current = true; animSeq.current++ }
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

  const offsets = useMemo(() => parallelOffsets(activeEdges), [activeEdges])
  const radiusOf = (id: string) => {
    const n = byId.get(id)
    return n ? nodeRadius(n.type, deg[id] || 0) : 12
  }

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
        {activeEdges.map(e => {
          const a = pos[e.source], b = pos[e.target]
          if (!a || !b) return null
          const hot     = !!neighborSet && (e.source === focusId || e.target === focusId)
          const dim     = !!neighborSet && !hot
          const pending = e.accepted === null
          const hidden  = hiddenTypes.has(byId.get(e.source)?.type ?? '')
                       || hiddenTypes.has(byId.get(e.target)?.type ?? '')
          if (hidden) return null
          // Ends on the target's rim (outside its selection ring, r + 7, when
          // selected) so the arrow head shows; parallel and reciprocal links
          // bow apart.  The marker scales with the stroke and its tip overhangs
          // the path's end by 1/10 of its size (≤ 1.4 px): hence the margin.
          const d = edgePath(
            a, b, e.source, e.target,
            radiusOf(e.source), radiusOf(e.target),
            offsets[e.id] ?? 0,
            e.target === selectedId ? 9 : 2.5,
          )
          return (
            <path
              key={e.id}
              data-edge={e.id}
              d={d}
              fill="none"
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
          const dim   = hiddenTypes.has(n.type)
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
