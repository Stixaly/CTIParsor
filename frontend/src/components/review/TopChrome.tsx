import { ArrowLeft, GitGraph, ShieldCheck, Download, FileCode, Loader2 } from 'lucide-react'
import { useAppTheme, themeLabel, THEME_LABELS } from '../../context/ThemeContext'
import { JOB_STATUS_LABEL } from '../jobStatus'
import type { JobStatus } from '../../types'

interface Props {
  title: string
  /** The report's status, as the Dashboard shows it; unknown → "Reports". */
  status?: JobStatus
  pendingCount: number
  finalizing: boolean
  onBack: () => void
  onGraph: () => void
  onCoverage: () => void
  onFinalize: () => void
  onDownload: () => void
  /** Download a ZIP of every detected rule for this report, in every format.
   *  (The `sigma*` prop names predate the multi-format store — ADR-0015/0022.) */
  onDownloadSigma: () => void
  /** Number of detected (linkable) rules — labels the button and gates it. */
  sigmaRuleCount: number
  /** True while the archive is being built/streamed — shows a spinner. */
  sigmaDownloading: boolean
  /** True after a successful finalize, until the next mutation. When true the
   *  primary button is "Download STIX"; otherwise it is "Complete Review". */
  reviewCompleted: boolean
  /** True while any entity/relationship mutation has fired but the bundle
   *  has not yet been regenerated. */
  bundleStale: boolean
  /** True while the background quick-finalize API call is in-flight. */
  autoFinalizing: boolean
}

export default function TopChrome({
  title, status, pendingCount, finalizing,
  onBack, onGraph, onCoverage, onFinalize, onDownload, onDownloadSigma,
  sigmaRuleCount, sigmaDownloading, reviewCompleted,
  bundleStale, autoFinalizing,
}: Props) {
  // The label says what is applied — it used to know only "dark" and
  // "everything else", so Cool + indigo read "Warm · oxblood".
  const { theme, accentKey, isDark, lightTheme, toggleDark } = useAppTheme()

  return (
    <header className="top-chrome">
      <button className="back" onClick={onBack} aria-label="Back to dashboard">
        <ArrowLeft size={16} />
      </button>

      <nav className="breadcrumb" aria-label="Breadcrumb">
        <button type="button" className="crumb-dim crumb-link" onClick={onBack}>Dashboard</button>
        <span className="crumb-sep">›</span>
        <span className="crumb-dim">{status ? JOB_STATUS_LABEL[status] : 'Reports'}</span>
        <span className="crumb-sep">›</span>
        <span className="crumb-strong">{title}</span>
      </nav>

      <div className="top-actions">
        <span className="kbd-hint">
          Press <kbd>?</kbd> for shortcuts
        </span>

        <button
          className="theme-toggle"
          onClick={toggleDark}
          title={isDark ? `Switch to ${THEME_LABELS[lightTheme]}` : 'Switch to Dark'}
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
          <span className="theme-toggle-label">{themeLabel(theme, accentKey)}</span>
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
          className="btn-ghost"
          onClick={onDownloadSigma}
          disabled={sigmaRuleCount === 0 || sigmaDownloading}
          title={sigmaDownloading
            ? 'Building the detection-rule archive — this can take a moment for large reports…'
            : sigmaRuleCount === 0
              ? 'No detection rules match this report’s techniques yet.'
              : `Download all ${sigmaRuleCount} detected rule${sigmaRuleCount === 1 ? '' : 's'} as a ZIP. `
                + 'Use the Coverage page to pick a subset.'
          }
        >
          {sigmaDownloading ? (
            <>
              <Loader2 size={14} className="bundle-status-spin" />
              Preparing…
            </>
          ) : (
            <>
              <FileCode size={14} />
              Detection rules{sigmaRuleCount > 0 ? ` · ${sigmaRuleCount}` : ''}
            </>
          )}
        </button>

        {reviewCompleted ? (
          <button
            className="btn-primary"
            onClick={onDownload}
            title="Download the finalized STIX 2.1 bundle for this report."
          >
            <Download size={14} />
            Download STIX
          </button>
        ) : (
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
        )}
      </div>
    </header>
  )
}
