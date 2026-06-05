/**
 * Compact theme + accent switcher for the app sidebar.
 *
 * Displays a row of 5 theme swatches and 7 accent dots.
 * Clicking a swatch changes the app-wide theme via ThemeContext.
 */

import {
  useAppTheme,
  THEME_LABELS, THEME_PREVIEW, ACCENT_PALETTES, ACCENT_KEYS,
  type Theme,
} from '../context/ThemeContext'

export default function ThemeSwitcher() {
  const { theme, setTheme, accentKey, setAccent, isDark } = useAppTheme()

  return (
    <div className="tsw-root">
      {/* ── Theme row ── */}
      <div className="tsw-label">Theme</div>
      <div className="tsw-dots">
        {(Object.keys(THEME_LABELS) as Theme[]).map(t => {
          const p = THEME_PREVIEW[t]
          const active = theme === t
          return (
            <button
              key={t}
              title={THEME_LABELS[t]}
              onClick={() => setTheme(t)}
              className={`tsw-dot ${active ? 'tsw-dot--active' : ''}`}
              style={{
                background: p.bg,
                boxShadow: active
                  ? `0 0 0 2px var(--bg-soft), 0 0 0 3.5px ${p.accent}`
                  : 'none',
              }}
            />
          )
        })}
      </div>

      {/* ── Accent row ── */}
      <div className="tsw-label">Accent</div>
      <div className="tsw-dots">
        {ACCENT_KEYS.map(k => {
          const p = ACCENT_PALETTES[k]
          const color = isDark ? p.dark : p.warm
          const active = accentKey === k
          return (
            <button
              key={k}
              title={k.charAt(0).toUpperCase() + k.slice(1)}
              onClick={() => setAccent(k)}
              className={`tsw-dot ${active ? 'tsw-dot--active' : ''}`}
              style={{
                background: color,
                boxShadow: active
                  ? `0 0 0 2px var(--bg-soft), 0 0 0 3.5px ${color}`
                  : 'none',
              }}
            />
          )
        })}
      </div>
    </div>
  )
}
