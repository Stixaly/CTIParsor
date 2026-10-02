import { useCallback, useState } from 'react'

/** A piece of UI state mirrored into localStorage under `key`.
 *
 *  Reads once, lazily, on mount; writes inside the setter rather than from a
 *  `useEffect`, because an effect-based persist fires on the first render too
 *  and overwrites the stored value with the initial one.
 *
 *  Both reads and writes are guarded: `localStorage` throws outright in a few
 *  browser contexts (private windows with site data blocked), and a stored
 *  value can be non-JSON if it was written by an older build. */
export function usePref<T>(key: string, init: T): [T, (v: T) => void] {
  const [val, setVal] = useState<T>(() => {
    try { const s = localStorage.getItem(key); return s ? JSON.parse(s) : init }
    catch { return init }
  })
  // Stable across renders (like useState's own setter), so callers can list it
  // in a dependency array without re-running their hook on every render.
  const set = useCallback((v: T) => {
    setVal(v)
    try { localStorage.setItem(key, JSON.stringify(v)) } catch {}
  }, [key])
  return [val, set]
}
