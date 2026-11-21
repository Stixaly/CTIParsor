import { useEffect, useState } from 'react'

// Decorative backdrop of the sign-in page: the report's graph as the world tree Yggdrasil,
// with a rune on each realm and two ravens, Huginn (thought) and Muninn (memory).

type Pt = [number, number]
type Curve = [Pt, Pt, Pt, Pt]

const TOP: Pt = [720, 250]
const MID: Pt = [720, 330]
const ROOT: Pt = [720, 640]

const BRANCHES: Curve[] = [
  [TOP, [640, 200], [420, 230], [250, 120]],
  [TOP, [690, 150], [520, 90], [420, 60]],
  [TOP, [750, 150], [920, 90], [1020, 60]],
  [TOP, [800, 200], [1020, 230], [1190, 120]],
  [MID, [900, 330], [1150, 330], [1300, 300]],
  [MID, [540, 330], [300, 330], [140, 300]],
]

const ROOTS: Curve[] = [
  [ROOT, [660, 720], [400, 760], [220, 820]],
  [ROOT, [690, 760], [560, 840], [470, 880]],
  [ROOT, [750, 760], [880, 840], [980, 880]],
  [ROOT, [780, 720], [1040, 760], [1230, 820]],
]

const LINKS: [Pt, Pt][] = [
  [[250, 120], [420, 60]],
  [[1020, 60], [1190, 120]],
  [[140, 300], [220, 820]],
  [[1300, 300], [1230, 820]],
  [[470, 880], [980, 880]],
]

// Elder Futhark, in a 12 x 20 box.
const RUNES = [
  'M6 0 L6 20 M6 8 L0 0 M6 8 L12 0', // algiz
  'M6 0 L6 20 M6 0 L0 7 M6 0 L12 7', // tiwaz
  'M6 0 L12 6 L1 18 M6 0 L0 6 L11 18', // othala
  'M1 0 L1 20 M11 0 L11 20 M1 0 L11 9 M11 0 L1 9', // mannaz
  'M9 0 L3 8 L9 12 L3 20', // sowilo
  'M2 0 L2 20 M2 6 L10 0 M2 12 L10 6', // fehu
  'M2 0 L2 20 M2 0 L10 5 L2 10 L10 15 L2 20', // berkano
  'M0 0 L0 20 L12 0 L12 20 L0 0', // dagaz
  'M1 0 L1 20 M11 0 L11 20 M1 6 L11 13', // hagalaz
  'M1 0 L1 20 M11 0 L11 20 M1 0 L6 6 L11 0', // ehwaz
]

const RAVEN = 'M-12 1 C-8 -4 -4 -5 0 0 C4 -5 8 -4 12 1 C8 -1 4 -1 0 3 C-4 -1 -8 -1 -12 1 Z'
const HUGINN = 'M220 820 C400 760 660 720 720 640 C720 540 720 350 720 250 C640 200 420 230 250 120'
const MUNINN = 'M1190 120 C1020 230 800 200 720 250 C720 350 720 540 720 640 C780 720 1040 760 1230 820'

const d = (s: number) => ({ '--d': `${s}s` }) as React.CSSProperties

const curve = ([p0, p1, p2, p3]: Curve) =>
  `M${p0[0]} ${p0[1]} C${p1[0]} ${p1[1]} ${p2[0]} ${p2[1]} ${p3[0]} ${p3[1]}`

function bezier([p0, p1, p2, p3]: Curve, t: number): Pt {
  const u = 1 - t
  const at = (i: 0 | 1) => u ** 3 * p0[i] + 3 * u * u * t * p1[i] + 3 * u * t * t * p2[i] + t ** 3 * p3[i]
  return [at(0), at(1)]
}

const QUERY = '(prefers-reduced-motion: reduce)'

/** SMIL cannot be stopped from CSS, so the ravens are only rendered when motion is welcome. */
function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() =>
    typeof window.matchMedia !== 'function' ? true : window.matchMedia(QUERY).matches)
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return
    const mq = window.matchMedia(QUERY)
    const onChange = () => setReduced(mq.matches)
    onChange()
    // Safari before 14 only has the older addListener / removeListener pair.
    if (typeof mq.addEventListener === 'function') {
      mq.addEventListener('change', onChange)
      return () => mq.removeEventListener('change', onChange)
    }
    mq.addListener(onChange)
    return () => mq.removeListener(onChange)
  }, [])
  return reduced
}

function Raven({ path }: { path: string }) {
  return (
    <g className="ygg-raven-fly">
      <animateMotion dur="12s" repeatCount="indefinite" path={path} keyPoints="0;1;0" keyTimes="0;0.5;1" calcMode="linear" />
      <path className="ygg-raven" d={RAVEN}>
        <animateTransform attributeName="transform" type="scale" values="1 1;1 0.55;1 1" dur="0.5s" repeatCount="indefinite" />
      </path>
    </g>
  )
}

export default function YggdrasilBackdrop() {
  const reduced = useReducedMotion()
  const realms = [...BRANCHES, ...ROOTS].map(c => c[3])
  const twigs = [bezier(BRANCHES[0], 0.55), bezier(BRANCHES[3], 0.55), bezier(ROOTS[0], 0.6), bezier(ROOTS[3], 0.6)]
  return (
    <svg className="ygg" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice" aria-hidden="true" focusable="false">
      <path d="M720 880 L720 200" className="ygg-line ygg-grow" strokeWidth={4} pathLength={1} style={d(0)} />
      {BRANCHES.map((c, i) => (
        <path key={`b${i}`} d={curve(c)} className="ygg-line ygg-grow" strokeWidth={2.2} pathLength={1} style={d(0.6 + i * 0.12)} />
      ))}
      {ROOTS.map((c, i) => (
        <path key={`r${i}`} d={curve(c)} className="ygg-line ygg-grow" strokeWidth={2.2} pathLength={1} style={d(0.7 + i * 0.12)} />
      ))}
      {LINKS.map(([a, b], i) => (
        <path key={`l${i}`} d={`M${a[0]} ${a[1]} L${b[0]} ${b[1]}`} className="ygg-link ygg-fade" style={d(2.2 + i * 0.25)} />
      ))}
      {twigs.map(([cx, cy], i) => (
        <circle key={`t${i}`} cx={cx} cy={cy} r={5} className="ygg-twig ygg-fade" style={d(1.6)} />
      ))}
      {realms.map(([cx, cy], i) => (
        <g key={`n${i}`} className="ygg-node" style={{ '--d': `${1.4 + i * 0.12}s`, '--b': `${5 + i * 0.6}s` } as React.CSSProperties}>
          <circle r={18} cx={cx} cy={cy} className="ygg-realm" />
          <path d={RUNES[i]} className="ygg-rune" transform={`translate(${cx - 4.8} ${cy - 8}) scale(0.8)`} />
        </g>
      ))}
      {!reduced && (
        <>
          <Raven path={HUGINN} />
          <Raven path={MUNINN} />
        </>
      )}
    </svg>
  )
}
