import React from 'react'

interface Props {
  open: boolean
  onClose: () => void
}

import { useReadOnly } from './readOnly'

// `writes`: the shortcut changes the report, so a read-only session does not have it (#707).
const SHORTCUTS = [
  { key: 'J / ↓',  desc: 'Next pending entity' },
  { key: 'K / ↑',  desc: 'Previous pending entity' },
  { key: 'A',      desc: 'Accept focused entity', writes: true },
  { key: 'R',      desc: 'Reject focused entity', writes: true },
  { key: 'U',      desc: 'Reset to pending', writes: true },
  { key: 'G',      desc: 'Open STIX graph' },
  { key: 'C',      desc: 'Open detection coverage' },
  { key: 'F',      desc: 'Finalize bundle', writes: true },
  { key: '?',      desc: 'This help overlay' },
  { key: 'Esc',    desc: 'Clear focus / close' },
]

export default function KeyboardHelp({ open, onClose }: Props) {
  const readOnly = useReadOnly()
  if (!open) return null
  return (
    <div className="kbd-overlay" onClick={onClose}>
      <div className="kbd-card" onClick={e => e.stopPropagation()}>
        <h3>Keyboard shortcuts</h3>
        <div className="kbd-grid">
          {SHORTCUTS.filter(s => !(readOnly && s.writes)).map(({ key, desc }) => (
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
