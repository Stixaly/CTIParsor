import { useQuery } from '@tanstack/react-query'

import { fetchCoverage } from '../api/client'

/**
 * Coverage data for a job (ADR-0006).
 *
 * The single seam between the CoverageMatrix view and the coverage source.
 * Today it reads the live-computed `/coverage` endpoint; if coverage later moves
 * to a richer/persisted model, only this hook changes — the view stays put.
 */
export function useCoverage(jobId: string | undefined) {
  return useQuery({
    queryKey: ['coverage', jobId],
    queryFn: () => fetchCoverage(jobId!),
    enabled: !!jobId,
  })
}
