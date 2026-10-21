import { useQuery } from '@tanstack/react-query'

import { fetchAttackIndex } from '../api/client'

/**
 * The ATT&CK index of the release the API runs (ADR-0087): technique names
 * and tactics for the Coverage page and the ATT&CK search.
 *
 * Fetched once per page load and shared.  The API fixes its release when it
 * starts, so the index cannot change under a running page: a restart on
 * another ATTACK_RELEASE shows at the next load.  A failed fetch is not kept;
 * the next mount asks again.
 */
export function useAttackIndex() {
  return useQuery({
    queryKey: ['attack-index'],
    queryFn: fetchAttackIndex,
    staleTime: Infinity,
  })
}
