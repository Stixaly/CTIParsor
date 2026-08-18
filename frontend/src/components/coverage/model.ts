import type { DetectionFormat } from '../../types'

/** One report technique with its selectable rules, pre-partitioned by format.
 *  Built once in Coverage.tsx from the /coverage/rules groups and shared by the
 *  format board, the matrix, the drill-in strip and the export panel, so every
 *  block counts the same rules the same way. */
export interface TechEntry {
  id: string
  name: string
  tactics: string[]                             // ATT&CK tactics ('other' when unmapped)
  score: number                                 // 0-3 readiness from the coverage cell
  ruleIds: string[]                             // distinct rule ids covering this technique
  byFormat: Record<DetectionFormat, string[]>   // the same ids split by format
}
