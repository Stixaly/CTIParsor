/**
 * Global theme context — shared across all app pages.
 *
 * Exposes:
 *   theme / setTheme     — 5 named visual themes
 *   accentKey / setAccent — 7 accent colour palettes
 *   isDark               — convenience bool for the dark theme
 *   lightTheme / toggleDark — dark ⇄ the last light theme chosen
 *
 * Both preferences are persisted to localStorage (same keys as Review page
 * so the user's choice carries over when navigating between pages).
 *
 * The `applyTheme()` call inside the Provider is synchronous and runs on every
 * render so HTML[data-theme] stays in sync even across React Router navigation.
 */

import { createContext, useContext, useState, useEffect, useLayoutEffect, useCallback, type ReactNode } from 'react'
import { usePref } from '../hooks/usePref'

// ── Types ────────────────────────────────────────────────────────────────────

export type Theme = 'warm' | 'ember' | 'parchment' | 'cool' | 'dark'

// ── Constants ─────────────────────────────────────────────────────────────────

export const THEME_LABELS: Record<Theme, string> = {
  warm:      'Warm',
  ember:     'Ember',
  parchment: 'Parchment',
  cool:      'Cool',
  dark:      'Dark',
}

/** Pre-rendered swatch for each theme — used by the picker dots */
export const THEME_PREVIEW: Record<Theme, { bg: string; ink: string; accent: string }> = {
  warm:      { bg: '#FAF7F1', ink: '#1B1714', accent: '#8B3A2F' },
  ember:     { bg: '#F4EBDF', ink: '#2A1A0F', accent: '#B8431B' },
  parchment: { bg: '#F8F0DB', ink: '#2B1D08', accent: '#9C5A1A' },
  cool:      { bg: '#F4F5F7', ink: '#161A22', accent: '#2B4FA6' },
  dark:      { bg: '#14110C', ink: '#F1ECDF', accent: '#E58A66' },
}

export const ACCENT_PALETTES: Record<string, {
  warm: string; warmSoft: string; dark: string; darkSoft: string
}> = {
  default:  { warm: '#8B3A2F', warmSoft: '#F2DDD7', dark: '#E58A66', darkSoft: '#3B231B' },
  indigo:   { warm: '#3B4FA6', warmSoft: '#DDE2F4', dark: '#8FA4F0', darkSoft: '#1F2438' },
  // teal and rose darkened a step: as text they fell to 3.8:1 and 4.4:1 on
  // the Ember background; now ≥ 4.6:1 on every light theme.
  teal:     { warm: '#116D6B', warmSoft: '#CDEAE8', dark: '#5BC7C2', darkSoft: '#142D2C' },
  rose:     { warm: '#AF315E', warmSoft: '#F6D5E0', dark: '#F08AAB', darkSoft: '#3A1B27' },
  forest:   { warm: '#3A6B2F', warmSoft: '#D3E6CC', dark: '#82BD75', darkSoft: '#1F2E1A' },
  violet:   { warm: '#6B3FAB', warmSoft: '#E2D6F2', dark: '#B194E6', darkSoft: '#251A38' },
  graphite: { warm: '#3D3D3D', warmSoft: '#DDDDDD', dark: '#C9C9C9', darkSoft: '#2A2A2A' },
}

export const ACCENT_KEYS = Object.keys(ACCENT_PALETTES) as string[]

export type LightTheme = Exclude<Theme, 'dark'>

/** A colour's name, for labels.  The default accent is two colours: oxblood
 *  on the light themes, coral on the dark one. */
export function accentName(key: string, isDark: boolean): string {
  if (key === 'default' || !ACCENT_PALETTES[key]) return isDark ? 'coral' : 'oxblood'
  return key
}

/** "Cool · indigo" — the theme and accent actually applied. */
export function themeLabel(theme: Theme, accentKey: string): string {
  return `${THEME_LABELS[theme] ?? theme} · ${accentName(accentKey, theme === 'dark')}`
}

const isLightTheme = (t: unknown): t is LightTheme =>
  typeof t === 'string' && t !== 'dark' && t in THEME_LABELS

// ── Internal helpers ──────────────────────────────────────────────────────────

/** Push theme tokens to html[data-theme] + CSS custom properties. */
function applyTheme(theme: Theme, accentKey: string) {
  if (typeof document === 'undefined') return
  document.documentElement.dataset.theme = theme
  const p = ACCENT_PALETTES[accentKey] ?? ACCENT_PALETTES.default
  const isDark = theme === 'dark'
  document.documentElement.style.setProperty('--accent',      isDark ? p.dark     : p.warm)
  document.documentElement.style.setProperty('--accent-soft', isDark ? p.darkSoft : p.warmSoft)
}

// ── Context ───────────────────────────────────────────────────────────────────

interface ThemeCtx {
  theme: Theme
  setTheme: (t: Theme) => void
  accentKey: string
  setAccent: (k: string) => void
  isDark: boolean
  /** The light theme the dark toggle returns to — the last one chosen. */
  lightTheme: LightTheme
  /** Dark ⇄ the last light theme (Review's toggle). */
  toggleDark: () => void
}

const ThemeContext = createContext<ThemeCtx>({
  theme: 'warm',
  setTheme: () => {},
  accentKey: 'default',
  setAccent: () => {},
  isDark: false,
  lightTheme: 'warm',
  toggleDark: () => {},
})

// ── Provider ──────────────────────────────────────────────────────────────────

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme,     setThemeRaw]  = usePref<Theme>('review.theme',  'warm')
  const [accentKey, setAccentRaw] = usePref('review.accent', 'default')
  // Seeded from the current theme, so a user already on Cool keeps Cool the
  // first time they toggle dark and back.
  const [storedLight, setLightRaw] = usePref<LightTheme>(
    'review.lightTheme', isLightTheme(theme) ? theme : 'warm')
  const lightTheme: LightTheme = isLightTheme(storedLight) ? storedLight : 'warm'

  // Memoised so consumers that list setTheme/setAccent in dep arrays
  // (or wrapped in React.memo) don't re-render on every parent render.
  const setTheme  = useCallback((t: Theme)   => {
    setThemeRaw(t)
    if (isLightTheme(t)) setLightRaw(t)
    applyTheme(t, accentKey)
  }, [accentKey])
  const setAccent = useCallback((k: string)  => { setAccentRaw(k); applyTheme(theme, k)         }, [theme])
  // It used to be `dark ? 'warm' : 'dark'`, so Cool → dark → light came back Warm.
  const toggleDark = useCallback(
    () => setTheme(theme === 'dark' ? lightTheme : 'dark'),
    [setTheme, theme, lightTheme])

  // useLayoutEffect fires synchronously after DOM mutations and BEFORE the
  // browser paints, which prevents a flash of the wrong theme on first load.
  // (The old useEffect ran *after* paint, causing a visible flicker.)
  useLayoutEffect(() => {
    applyTheme(theme, accentKey)
  }, [theme, accentKey])

  return (
    <ThemeContext.Provider value={{
      theme, setTheme, accentKey, setAccent, isDark: theme === 'dark', lightTheme, toggleDark,
    }}>
      {children}
    </ThemeContext.Provider>
  )
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useAppTheme(): ThemeCtx {
  return useContext(ThemeContext)
}
