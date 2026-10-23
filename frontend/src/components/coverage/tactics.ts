// ATT&CK enterprise tactics in kill-chain order: the Coverage page's columns.
//
// FIFTEEN columns, matching mitre_index.json on every ATT&CK track (19.2 and
// 20.0, ADR-0087) — not the fourteen of the classic matrix. That index renames
// TA0005 to `stealth` (not `defense-evasion`) and adds TA0112
// `defense-impairment`. The previous list here used `defense-evasion`, so the
// 148 techniques tagged `stealth` and the 56 tagged `defense-impairment` all
// fell through to the 'other' bucket — 204 enterprise techniques shown as
// unmapped.
//
// Kept in step with TACTIC_ORDER in pipeline/detection/phases.py. Both lists
// are locked against the index of every committed track: this one by
// tactics.test.ts, that one by
// test_every_enterprise_tactic_in_the_index_has_a_column.
export const TACTIC_ORDER: readonly string[] = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'stealth', 'defense-impairment',
  'credential-access', 'discovery', 'lateral-movement', 'collection',
  'command-and-control', 'exfiltration', 'impact',
]

export const TACTIC_LABEL: Readonly<Record<string, string>> = {
  'reconnaissance': 'Reconnaissance', 'resource-development': 'Resource Dev',
  'initial-access': 'Initial Access', 'execution': 'Execution', 'persistence': 'Persistence',
  'privilege-escalation': 'Priv Esc', 'stealth': 'Stealth',
  'defense-impairment': 'Defense Impairment',
  'credential-access': 'Credential Access', 'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement', 'collection': 'Collection',
  'command-and-control': 'Command & Control', 'exfiltration': 'Exfiltration',
  'impact': 'Impact', 'other': 'Other',
}

// The ATT&CK domain whose techniques get a column: ENTERPRISE_DOMAIN in
// pipeline/detection/phases.py.
export const ENTERPRISE_DOMAIN = 'enterprise-attack'

/** What the ATT&CK index says about one technique (useAttackIndex). */
export interface TechMeta { name: string; domain: string; tactics: string[] }

/** The columns a technique is filed under: its tactics that have a column when
 *  its index entry is an enterprise one, ['other'] otherwise — as the backend's
 *  phase band does (tactics_for_technique, ADR-0025). A mobile, ICS or CAPEC
 *  technique is off-matrix even when its tactic shortnames are enterprise ones:
 *  T1660 Phishing (`mobile-attack`, ['initial-access']) used to land in the
 *  Initial Access column. An id the index lacks goes to 'other' too. */
export function techniqueColumns(meta: TechMeta | undefined): string[] {
  if (meta?.domain !== ENTERPRISE_DOMAIN) return ['other']
  const tactics = meta.tactics.filter(t => TACTIC_ORDER.includes(t))
  return tactics.length ? tactics : ['other']
}
