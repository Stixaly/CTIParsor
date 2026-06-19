export type JobStatus =
  | 'uploaded'
  | 'processing'
  | 'for_review'
  | 'reviewing'
  | 'completed'
  | 'failed'

export interface Job {
  id: string
  original_filename: string
  status: JobStatus
  report_text?: string
  created_at: string
  updated_at: string
  entity_count?: number
  relationship_count?: number
  tlp_level?: string | null
  pap_level?: string | null
}

// TLP / PAP marking levels offered at upload time — applied via
// object_marking_refs to every object in the generated STIX bundle.
export const MARKING_LEVELS = ['RED', 'AMBER', 'GREEN', 'WHITE'] as const
export type MarkingLevel = typeof MARKING_LEVELS[number]

export interface Entity {
  id: string
  job_id: string
  value: string
  entity_type: string
  context: string
  confidence: number
  mitre_id: string | null
  accepted: boolean | null
  source: string
}

export type EvidenceLabel = 'observed' | 'reported' | 'assessed' | 'inferred' | 'gap'

export interface Relationship {
  id: string
  job_id: string
  source_value: string
  relationship_type: string
  target_value: string
  confidence: number
  accepted: boolean | null
  evidence_text: string | null
  evidence_label?: EvidenceLabel
}

// ── Detection coverage (ADR-0006) ───────────────────────────────────────────
export interface CoverageCell {
  technique_id: string
  score: number            // 0-3 readiness (NOT lab validation)
  corpora: string[]
  rule_count: number
}

export interface CoverageResult {
  job_id: string
  techniques_total: number
  by_score: Record<string, number>
  validated: boolean
  cells: CoverageCell[]
}

export interface CoverageRule {
  id: string
  corpus: string
  title: string
  severity: string
  license: string
  source_ref: string
}

export interface DetectionCorpus {
  corpus: string
  license: string
  rules: number
}

// Corpus registry entry as shown in the Settings panel (ADR-0007)
export interface CorpusConfig {
  name: string
  adapter: string
  path?: string
  git?: string
  license: string
  private?: boolean
  enabled: boolean
  rules: number
}

export interface ProgressEvent {
  stage?: number
  label?: string
  chunk?: number
  total?: number
  entities?: number
  chars?: number
  chunks?: number
  objects?: number
  valid?: boolean
  status?: string
  error?: string
  /** Stage 2 sub-counts */
  gazetteer?: number
  semantic_ttps?: number
  cyner?: number
  gliner?: number
  /** Stage 3 running extraction totals (updated per chunk) */
  malware?: number
  actors?: number
  tools?: number
  relationships?: number
}

export interface StixObject {
  id: string
  type: string
  name?: string
  value?: string
  hashes?: Record<string, string>
  relationship_type?: string
  source_ref?: string
  target_ref?: string
  pattern?: string
  [key: string]: unknown
}

export interface StixBundle {
  id: string
  type: 'bundle'
  objects: StixObject[]
}

// STIX 2.1 object type → brand color (used in STIX graph nodes and badges).
// Covers all 18 SDOs, 18 SCOs, 2 SROs, and pipeline-internal names.
export const STIX_COLORS: Record<string, string> = {
  // ── SDOs ─────────────────────────────────────────────────────────────────
  'attack-pattern':   '#c2410c',  // orange-700
  'campaign':         '#a21caf',  // fuchsia-700
  'course-of-action': '#0f766e',  // teal-700
  'grouping':         '#4338ca',  // indigo-700
  'identity':         '#0369a1',  // sky-700
  'incident':         '#be123c',  // rose-700
  'indicator':        '#1d4ed8',  // blue-700
  'infrastructure':   '#0e7490',  // cyan-700
  'intrusion-set':    '#b91c1c',  // red-700
  'location':         '#15803d',  // green-700
  'malware':          '#c2410c',  // orange-700
  'malware-analysis': '#92400e',  // amber-800
  'note':             '#6b7280',  // gray-500
  'observed-data':    '#166534',  // green-800
  'opinion':          '#5b21b6',  // violet-800
  'report':           '#374151',  // gray-700
  'threat-actor':     '#dc2626',  // red-600
  'tool':             '#16a34a',  // green-600
  'vulnerability':    '#ca8a04',  // yellow-600
  // ── SROs ─────────────────────────────────────────────────────────────────
  'relationship':     '#475569',
  'sighting':         '#6d28d9',
  // ── SCOs ─────────────────────────────────────────────────────────────────
  'artifact':         '#78716c',
  'autonomous-system':'#0284c7',
  'directory':        '#a16207',
  'domain-name':      '#7c3aed',
  'email-addr':       '#db2777',
  'email-message':    '#be185d',
  'file':             '#0891b2',
  'ipv4-addr':        '#2563eb',
  'ipv6-addr':        '#1d4ed8',
  'mac-addr':         '#0369a1',
  'mutex':            '#7e22ce',
  'network-traffic':  '#0891b2',
  'process':          '#0e7490',
  'software':         '#15803d',
  'url':              '#2563eb',
  'user-account':     '#9d174d',
  'windows-registry-key': '#6d28d9',
  'x509-certificate': '#0f766e',
  // ── Pipeline-internal short-name aliases (different from STIX canonical) ──
  // Types identical to STIX canonical (malware, tool, campaign, identity,
  // infrastructure, location, incident, vulnerability, file, url, mutex,
  // software, process) are already covered above.
  threat_actor:    '#dc2626',   // → threat-actor
  intrusion_set:   '#b91c1c',   // → intrusion-set
  ipv4:            '#2563eb',   // → ipv4-addr
  ipv6:            '#1d4ed8',   // → ipv6-addr
  domain:          '#7c3aed',   // → domain-name
  email:           '#db2777',   // → email-addr
  sha256:          '#0891b2',   // → file
  md5:             '#0891b2',   // → file
  sha1:            '#0891b2',   // → file
  cve:             '#ca8a04',   // → vulnerability
  technique:       '#c2410c',   // → attack-pattern
  tactic:          '#a16207',   // → attack-pattern (tactic phase)
  procedure:       '#166534',   // → attack-pattern (sub-technique)
  ttp:             '#c2410c',   // → attack-pattern
  asn:             '#0284c7',   // → autonomous-system
  mac_addr:        '#0369a1',   // → mac-addr
  registry_key:    '#6d28d9',   // → windows-registry-key
  user_account:    '#9d174d',   // → user-account
  network_traffic: '#0891b2',   // → network-traffic
}

export const ENTITY_HIGHLIGHT: Record<string, string> = {
  // Network SCOs
  ipv4:             'bg-blue-100 text-blue-900 border-b-2 border-blue-400',
  ipv6:             'bg-blue-100 text-blue-900 border-b-2 border-blue-400',
  domain:           'bg-purple-100 text-purple-900 border-b-2 border-purple-400',
  url:              'bg-indigo-100 text-indigo-900 border-b-2 border-indigo-400',
  email:            'bg-pink-100 text-pink-900 border-b-2 border-pink-400',
  mac_addr:         'bg-sky-100 text-sky-900 border-b-2 border-sky-400',
  asn:              'bg-sky-100 text-sky-900 border-b-2 border-sky-500',
  network_traffic:  'bg-cyan-100 text-cyan-900 border-b-2 border-cyan-400',
  // File / hash SCOs
  md5:              'bg-amber-100 text-amber-900 border-b-2 border-amber-400',
  sha1:             'bg-amber-100 text-amber-900 border-b-2 border-amber-400',
  sha256:           'bg-amber-100 text-amber-900 border-b-2 border-amber-400',
  file:             'bg-amber-100 text-amber-900 border-b-2 border-amber-500',
  // System SCOs
  registry_key:     'bg-violet-100 text-violet-900 border-b-2 border-violet-500',
  mutex:            'bg-purple-100 text-purple-900 border-b-2 border-purple-500',
  user_account:     'bg-rose-100 text-rose-900 border-b-2 border-rose-400',
  // Vulnerability
  cve:              'bg-red-100 text-red-900 border-b-2 border-red-400',
  vulnerability:    'bg-red-100 text-red-900 border-b-2 border-red-400',
  // ATT&CK
  ttp:              'bg-orange-100 text-orange-900 border-b-2 border-orange-400',
  technique:        'bg-amber-100 text-amber-900 border-b-2 border-amber-500',
  tactic:           'bg-yellow-100 text-yellow-900 border-b-2 border-yellow-500',
  procedure:        'bg-lime-100 text-lime-900 border-b-2 border-lime-500',
  // Named SDOs
  malware:          'bg-orange-200 text-orange-950 border-b-2 border-orange-500',
  threat_actor:     'bg-red-200 text-red-950 border-b-2 border-red-500',
  intrusion_set:    'bg-red-100 text-red-900 border-b-2 border-red-400',
  tool:             'bg-green-100 text-green-900 border-b-2 border-green-400',
  campaign:         'bg-fuchsia-100 text-fuchsia-900 border-b-2 border-fuchsia-400',
  infrastructure:   'bg-teal-100 text-teal-900 border-b-2 border-teal-400',
  identity:         'bg-sky-100 text-sky-900 border-b-2 border-sky-400',
  location:         'bg-green-100 text-green-900 border-b-2 border-green-500',
  incident:         'bg-rose-200 text-rose-950 border-b-2 border-rose-500',
}

export const ENTITY_TYPE_LABELS: Record<string, string> = {
  // Network SCOs
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL',
  email: 'Email', mac_addr: 'MAC', asn: 'ASN', network_traffic: 'Net Traffic',
  // File / hash SCOs
  md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', file: 'File',
  // System SCOs
  registry_key: 'Registry Key', mutex: 'Mutex', user_account: 'User Account',
  // Vulnerability
  cve: 'CVE', vulnerability: 'Vulnerability',
  // ATT&CK
  ttp: 'TTP', technique: 'Technique', tactic: 'Tactic', procedure: 'Procedure',
  // Named SDOs
  malware: 'Malware', threat_actor: 'Threat Actor', intrusion_set: 'Intrusion Set',
  tool: 'Tool', campaign: 'Campaign', infrastructure: 'Infrastructure',
  identity: 'Identity', location: 'Location', incident: 'Incident',
  // STIX canonical names
  'attack-pattern': 'Attack Pattern', 'threat-actor': 'Threat Actor',
  'intrusion-set': 'Intrusion Set', 'course-of-action': 'Course of Action',
  'malware-analysis': 'Malware Analysis', 'observed-data': 'Observed Data',
  'grouping': 'Grouping', 'note': 'Note', 'opinion': 'Opinion', 'report': 'Report',
  'sighting': 'Sighting', 'domain-name': 'Domain', 'ipv4-addr': 'IPv4',
  'ipv6-addr': 'IPv6', 'email-addr': 'Email', 'mac-addr': 'MAC',
  'autonomous-system': 'ASN', 'network-traffic': 'Net Traffic',
  'windows-registry-key': 'Registry Key', 'user-account': 'User Account',
  'x509-certificate': 'X.509 Cert', 'software': 'Software',
  'directory': 'Directory', 'artifact': 'Artifact',
  'email-message': 'Email Message', 'process': 'Process',
}
