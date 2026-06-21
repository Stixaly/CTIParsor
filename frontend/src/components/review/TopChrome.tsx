import { ArrowLeft, GitGraph, ShieldCheck } from 'lucide-react'

interface Props {
  title: string
  pendingCount: number
  finalizing: boolean
  theme: string
  onBack: () => void
  onGraph: () => void
  onCoverage: () => void
  onFinalize: () => void
  onThemeToggle: () => void
  /** True while any entity/relationship mutation has fired but the bundle
   *  has not yet been regenerated. */
  bundleStale: boolean
  /** True while the background quick-finalize API call is in-flight. */
  autoFinalizing: boolean
}

export default function TopChrome({
  title, pendingCount, finalizing, theme,
  onBack, onGraph, onCoverage, onFinalize, onThemeToggle,
  bundleStale, autoFinalizing,
}: Props) {
  const isDark = theme === 'dark'

  return (
    <header className="top-chrome">
      <button className="back" onClick={onBack} aria-label="Back to dashboard">
        <ArrowLeft size={16} />
      </button>

      <div className="breadcrumb">
        <span className="crumb-dim">Dashboard</span>
        <span className="crumb-sep">›</span>
        <span className="crumb-dim">For review</span>
        <span className="crumb-sep">›</span>
        <span className="crumb-strong">{title}</span>
      </div>

      <div className="top-actions">
        <span className="kbd-hint">
          Press <kbd>?</kbd> for shortcuts
        </span>

        <button
          className="theme-toggle"
          onClick={onThemeToggle}
          title={isDark ? 'Switch to warm' : 'Switch to dark'}
          aria-label="Toggle theme"
        >
          <span className={`theme-knob ${isDark ? 'dark' : 'warm'}`}>
            {isDark ? (
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                <path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" />
              </svg>
            ) : (
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round">
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
              </svg>
            )}
          </span>
          <span className="theme-toggle-label">{isDark ? 'Dark · amber' : 'Warm · oxblood'}</span>
        </button>

        <button className="btn-ghost" onClick={onGraph}>
          <GitGraph size={14} />
          Graph
        </button>

        <button className="btn-ghost" onClick={onCoverage} title="Sigma detection coverage for this report's techniques">
          <ShieldCheck size={14} />
          Coverage
        </button>

        {/* ── Bundle status indicator ─────────────────────────────────────── */}
        {autoFinalizing ? (
          <span
            className="bundle-status bundle-status-syncing"
            title="Regenerating STIX bundle in the background…"
          >
            <span className="bundle-status-spin">↻</span>
            Syncing
          </span>
        ) : bundleStale ? (
          <span
            className="bundle-status bundle-status-stale"
            title="The bundle is out of date. It will update automatically, or click Finalize."
          >
            ⚠ Bundle outdated
          </span>
        ) : (
          <span
            className="bundle-status bundle-status-ok"
            title="The STIX bundle reflects all current accepted entities and relationships."
          >
            ✓ Bundle current
          </span>
        )}

        <button
          className="btn-primary"
          onClick={onFinalize}
          disabled={finalizing}
          title={pendingCount > 0
            ? `${pendingCount} entities still unreviewed — they will be included in the bundle. Click to complete the review and generate the final STIX file.`
            : 'Generate the final STIX 2.1 bundle and mark this report as completed.'
          }
        >
          {finalizing
            ? 'Completing…'
            : pendingCount > 0
              ? `Complete Review · ${pendingCount} unreviewed`
              : 'Complete Review'}
        </button>
      </div>
    </header>
  )
}
