// Writes the analyst has sent for rows of the Review page, until the server answers.
//
// The page shows the analyst's copy of a row while one of its writes is open, and
// the server's copy otherwise, so a refresh neither undoes a decision still on its
// way nor hides one another session made (#706).

export class RowWrites {
  private last = 0
  private latest = new Map<string, number>()
  private open = new Map<string, Set<number>>()

  /** Registers a write sent on `ids` and returns its sequence number. */
  begin(ids: readonly string[]): number {
    const seq = ++this.last
    for (const id of ids) {
      this.latest.set(id, seq)
      const seqs = this.open.get(id) ?? new Set<number>()
      seqs.add(seq)
      this.open.set(id, seqs)
    }
    return seq
  }

  /** Records the server's answer to write `seq` on row `id`. */
  end(id: string, seq: number): void {
    const seqs = this.open.get(id)
    if (!seqs) return
    seqs.delete(seq)
    if (seqs.size === 0) this.open.delete(id)
  }

  /** True while at least one write on row `id` is still unanswered. */
  isPending(id: string): boolean {
    return this.open.has(id)
  }

  /** True when write `seq` is the newest one sent on row `id`. */
  isLatest(id: string, seq: number): boolean {
    return this.latest.get(id) === seq
  }
}

export type WriteResult =
  | { ok: true }
  | { ok: false; error: unknown; latest: boolean }

/** Sends one write on `ids` and follows it until the server answers.
 *
 *  On success `settled(true)` runs.  On failure each row whose newest write this
 *  was goes back through `revert` (the server's copy), `latest` is true, and
 *  `settled(false)` runs.  An older write that fails reverts nothing: the newer
 *  decision on the row stands, and the caller is told so through `latest`. */
export function trackWrite(
  writes: RowWrites,
  ids: readonly string[],
  send: () => Promise<unknown>,
  revert: (id: string) => void,
  settled: (ok: boolean) => void,
): Promise<WriteResult> {
  const seq = writes.begin(ids)
  return send().then<WriteResult, WriteResult>(
    () => {
      for (const id of ids) writes.end(id, seq)
      settled(true)
      return { ok: true }
    },
    (error: unknown) => {
      const newest = ids.filter(id => writes.isLatest(id, seq))
      for (const id of ids) writes.end(id, seq)
      for (const id of newest) revert(id)
      settled(false)
      return { ok: false, error, latest: newest.length > 0 }
    },
  )
}
