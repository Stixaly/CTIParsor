import { createContext, useContext } from 'react'

/** The review page is read-only for this session (#707): a reader sees the report
 *  and its decisions, and no control on the page sends a write. The page sets it
 *  from the signed-in role (useCanWrite); without a provider it is false, as it is
 *  with authentication off. */
export const ReadOnlyContext = createContext(false)

export function useReadOnly(): boolean {
  return useContext(ReadOnlyContext)
}
