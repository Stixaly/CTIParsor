/**
 * STIX 2.1 Appendix B per-pair relationship constraints — single source of truth.
 *
 * Maps "sourceType>targetType" → the spec-defined verbs for that pair.
 * Every pair additionally accepts `related-to`; a same-type pair also accepts
 * `duplicate-of` and `derived-from` (§3.7, see `commonVerbs`).  The table must
 * equal `_SUGGESTED` in pipeline/stix_rel_spec.py
 * (tests/test_rel_constraints_parity.py).
 *
 * This module is intentionally dependency-free (no React, no component imports)
 * so it can be shared by both the Review components (tokens.ts) and the Policy
 * page without an import cycle.  Previously each kept its own copy of this table
 * and they had already drifted (Policy carried two pairs tokens.ts lacked).
 */
export const STIX_REL_CONSTRAINTS: Record<string, string[]> = {
  // attack-pattern
  'attack-pattern>malware': ['delivers', 'uses'],
  'attack-pattern>tool': ['uses'],
  'attack-pattern>identity': ['targets'],
  'attack-pattern>location': ['targets'],
  'attack-pattern>vulnerability': ['targets'],
  // campaign
  'campaign>intrusion-set': ['attributed-to'],
  'campaign>threat-actor': ['attributed-to'],
  'campaign>infrastructure': ['compromises', 'uses'],
  'campaign>location': ['originates-from', 'targets'],
  'campaign>identity': ['targets'],
  'campaign>vulnerability': ['targets'],
  'campaign>attack-pattern': ['uses'],
  'campaign>malware': ['uses'],
  'campaign>tool': ['uses'],
  // course-of-action
  'course-of-action>indicator': ['investigates', 'mitigates'],
  'course-of-action>attack-pattern': ['mitigates'],
  'course-of-action>malware': ['mitigates', 'remediates'],
  'course-of-action>tool': ['mitigates'],
  'course-of-action>vulnerability': ['mitigates', 'remediates'],
  // identity
  'identity>location': ['located-at'],
  // indicator
  'indicator>attack-pattern': ['indicates'],
  'indicator>campaign': ['indicates'],
  'indicator>infrastructure': ['indicates'],
  'indicator>intrusion-set': ['indicates'],
  'indicator>malware': ['indicates'],
  'indicator>threat-actor': ['indicates'],
  'indicator>tool': ['indicates'],
  'indicator>observed-data': ['based-on'],
  // infrastructure
  'infrastructure>infrastructure': ['communicates-with', 'consists-of', 'controls', 'uses'],
  'infrastructure>ipv4-addr': ['communicates-with', 'consists-of'],
  'infrastructure>ipv6-addr': ['communicates-with', 'consists-of'],
  'infrastructure>domain-name': ['communicates-with', 'consists-of'],
  'infrastructure>url': ['communicates-with', 'consists-of'],
  'infrastructure>observed-data': ['consists-of'],
  // All STIX SCOs are valid targets for infrastructure consists-of (validator §7.6)
  'infrastructure>artifact': ['consists-of'],
  'infrastructure>autonomous-system': ['consists-of'],
  'infrastructure>directory': ['consists-of'],
  'infrastructure>email-addr': ['consists-of'],
  'infrastructure>email-message': ['consists-of'],
  'infrastructure>file': ['consists-of'],
  'infrastructure>mac-addr': ['consists-of'],
  'infrastructure>mutex': ['consists-of'],
  'infrastructure>network-traffic': ['consists-of'],
  'infrastructure>process': ['consists-of'],
  'infrastructure>software': ['consists-of'],
  'infrastructure>user-account': ['consists-of'],
  'infrastructure>windows-registry-key': ['consists-of'],
  'infrastructure>x509-certificate': ['consists-of'],
  'infrastructure>malware': ['controls', 'delivers', 'hosts'],
  'infrastructure>vulnerability': ['has'],
  'infrastructure>tool': ['hosts'],
  'infrastructure>location': ['located-at'],
  // intrusion-set
  'intrusion-set>threat-actor': ['attributed-to'],
  'intrusion-set>infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'intrusion-set>location': ['originates-from', 'targets'],
  'intrusion-set>identity': ['targets'],
  'intrusion-set>vulnerability': ['targets'],
  'intrusion-set>attack-pattern': ['uses'],
  'intrusion-set>malware': ['uses'],
  'intrusion-set>tool': ['uses'],
  // malware
  'malware>threat-actor': ['authored-by'],
  'malware>intrusion-set': ['authored-by'],
  'malware>infrastructure': ['beacons-to', 'exfiltrates-to', 'targets', 'uses'],
  'malware>ipv4-addr': ['communicates-with'],
  'malware>ipv6-addr': ['communicates-with'],
  'malware>domain-name': ['communicates-with'],
  'malware>url': ['communicates-with'],
  'malware>malware': ['controls', 'downloads', 'drops', 'uses', 'variant-of'],
  'malware>tool': ['downloads', 'drops', 'uses'],
  'malware>file': ['downloads', 'drops'],
  'malware>vulnerability': ['exploits', 'targets'],
  'malware>location': ['originates-from', 'targets'],
  'malware>identity': ['targets'],
  'malware>attack-pattern': ['uses'],
  // malware-analysis (§7.6 of the spec)
  'malware-analysis>malware': ['characterizes', 'analysis-of', 'static-analysis-of', 'dynamic-analysis-of'],
  // threat-actor
  'threat-actor>identity': ['attributed-to', 'impersonates', 'targets'],
  'threat-actor>infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'threat-actor>location': ['located-at', 'targets'],
  'threat-actor>vulnerability': ['targets'],
  'threat-actor>attack-pattern': ['uses'],
  'threat-actor>malware': ['uses'],
  'threat-actor>tool': ['uses'],
  // tool
  'tool>malware': ['delivers', 'drops'],
  'tool>vulnerability': ['has', 'targets'],
  'tool>identity': ['targets'],
  'tool>infrastructure': ['uses', 'targets'],  // validator: tool uses → infrastructure
  'tool>location': ['targets'],
  // SCO-level relationships (stix2validator RELATIONSHIPS table)
  'domain-name>ipv4-addr': ['resolves-to'],
  'domain-name>ipv6-addr': ['resolves-to'],
  'domain-name>domain-name': ['resolves-to'],
  'ipv4-addr>autonomous-system': ['belongs-to'],
  'ipv4-addr>mac-addr': ['resolves-to'],  // validator: ipv4-addr resolves-to mac-addr
  'ipv6-addr>autonomous-system': ['belongs-to'],
  'ipv6-addr>mac-addr': ['resolves-to'],  // validator: ipv6-addr resolves-to mac-addr
}

/** The STIX 2.1 common relationships (§3.7).  Only `related-to` links any two
 *  objects; `duplicate-of` and `derived-from` link two objects of the same
 *  type, so pick a pair's own with `commonVerbs`.  Same rule as the backend's
 *  `pipeline/stix_rel_spec.py`: offering `malware duplicate-of tool` here let
 *  an analyst pick a verb that Stage 4 then shipped as `related-to`. */
export const UNIVERSAL_VERBS = ['related-to', 'duplicate-of', 'derived-from']

/** The common relationships valid for this pair of types. */
export function commonVerbs(src: string, tgt: string): string[] {
  return src === tgt ? UNIVERSAL_VERBS : ['related-to']
}

/**
 * Return the spec-defined valid verbs for a (src, tgt) pair, followed by the
 * common verbs valid for it, or null when the pair has no Appendix B definition.
 */
export function pairVerbs(src: string, tgt: string): string[] | null {
  const v = STIX_REL_CONSTRAINTS[`${src}>${tgt}`]
  return v ? [...new Set([...v, ...commonVerbs(src, tgt)])] : null
}

/** STIX types Stage 4 treats as observables (`_OBSERVABLE_SCO_TYPES` in
 *  pipeline/stage4_stix_mapping.py, checked by tests/test_rel_constraints_parity.py). */
export const OBSERVABLE_TYPES = new Set([
  'ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'email-addr', 'mac-addr',
  'autonomous-system', 'file', 'windows-registry-key', 'mutex',
  'user-account', 'network-traffic', 'software', 'artifact',
])

/** All STIX 2.1 cyber-observable types (`SCO_TYPES` in pipeline/stix_rel_spec.py). */
export const SCO_TYPES = new Set([
  'artifact', 'autonomous-system', 'directory', 'domain-name', 'email-addr',
  'email-message', 'file', 'ipv4-addr', 'ipv6-addr', 'mac-addr', 'mutex',
  'network-traffic', 'process', 'software', 'url', 'user-account',
  'windows-registry-key', 'x509-certificate',
])

/** The verbs named for this exact pair: the spec's table, plus the project's
 *  `indicator based-on <SCO>` (`_PROJECT_EXTENSIONS`, ADR-0061). */
function listedVerbs(src: string, tgt: string): string[] {
  const ext = src === 'indicator' && SCO_TYPES.has(tgt) ? ['based-on'] : []
  return [...(STIX_REL_CONSTRAINTS[`${src}>${tgt}`] ?? []), ...ext]
}

const uniq = (xs: string[]) => [...new Set(xs)]

/**
 * The verbs Stage 4 ships as written for a src → tgt row or pinned rule.  Any
 * other verb ships as `related-to`, except between an observable and a
 * technique, where Stage 4 drops it.  Same decisions as
 * `verb_ships_as_written` in pipeline/stage4_stix_mapping.py; both are held to
 * `shippedVerbs.fixture.json` (tests/test_rel_constraints_parity.py).
 *
 * - An observable and a technique, either way round: only `indicates`,
 *   through the observable's Indicator (ADR-0012, ADR-0065).
 * - An observable opposite an SDO: the verbs listed for the pair stay on the
 *   observable; any other verb is carried by the observable's Indicator in its
 *   place (ADR-0041, ADR-0062), so it ships if the Indicator's pair allows it.
 * - Otherwise: the listed verbs, then the common verbs valid for the pair.
 */
export function shippedVerbs(src: string, tgt: string): string[] {
  const srcObs = OBSERVABLE_TYPES.has(src), tgtObs = OBSERVABLE_TYPES.has(tgt)
  if ((srcObs && tgt === 'attack-pattern') || (src === 'attack-pattern' && tgtObs)) {
    return ['indicates']
  }
  const allowed = (s: string, t: string) => uniq([...listedVerbs(s, t), ...commonVerbs(s, t)])
  if (srcObs && !tgtObs) return uniq([...listedVerbs(src, tgt), ...allowed('indicator', tgt)])
  if (tgtObs && !srcObs) return uniq([...listedVerbs(src, tgt), ...allowed(src, 'indicator')])
  return allowed(src, tgt)
}
