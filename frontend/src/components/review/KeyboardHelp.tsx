import React from 'react'

interface Props {
  open: boolean
  onClose: () => void
}

const SHORTCUTS = [
  { key: 'J / ↓',  desc: 'Next pending entity' },
  { key: 'K / ↑',  desc: 'Previous pending entity' },
  { key: 'A',      desc: 'Accept focused entity' },
  { key: 'R',      desc: 'Reject focused entity' },
  { key: 'U',      desc: 'Reset to pending' },
  { key: 'G',      desc: 'Open STIX graph' },
  { key: 'F',      desc: 'Finalize bundle' },
  { key: '?',      desc: 'This help overlay' },
  { key: 'Esc',    desc: 'Clear focus / close' },
]

export default function KeyboardHelp({ open, onClose }: Props) {
  if (!open) return null
  return (
    <div className="kbd-overlay" onClick={onClose}>
      <div className="kbd-card" onClick={e => e.stopPropagation()}>
        <h3>Keyboard shortcuts</h3>
        <div className="kbd-grid">
          {SHORTCUTS.map(({ key, desc }) => (
            // React.Fragment (not <>) so we can pass key= for correct reconciliation
            <React.Fragment key={key}>
              <div>
                {key.split(' / ').map((k, i) => (
                  <React.Fragment key={k}>
                    {i > 0 && ' / '}
                    <kbd>{k}</kbd>
                  </React.Fragment>
                ))}
              </div>
              <div>{desc}</div>
            </React.Fragment>
          ))}
        </div>
        <button className="btn-ghost kbd-close" onClick={onClose}>Close</button>
      </div>
    </div>
  )
}
