/**
 * Shared types, tier map, node-radius helper, and static layout functions
 * (hierarchical + radial).  The force layout is managed by GraphCanvas via
 * d3-force directly.
 */

// ── Graph data types ──────────────────────────────────────────────────────────

export interface GraphNode {
  id:         string
  type:       string   // pipeline underscore name (e.g. "threat_actor", "ipv4")
  name:       string   // entity value
  confidence: number   // 0–1
  source:     string
  mitre_id:   string | null
  context:    string
  accepted:   boolean | null
}

export interface GraphEdge {
  id:         string
  source:     string   // entity id
  target:     string   // entity id
  rel:        string   // relationship_type
  confidence: number   // 0–1
  accepted:   boolean | null
  evidence:   string
}

export interface Pos { x: number; y: number }
export type PosMap = Record<string, Pos>

// ── Tier map — drives node radius + hierarchical layout row ──────────────────
// tier 0 = strategic actors | 1 = capabilities | 2 = infrastructure
// tier 3 = atomic IoCs      | 4 = context/detection

export const ENTITY_TIER: Record<string, number> = {
  // tier 0 — strategic
  threat_actor: 0, 'threat-actor': 0,
  intrusion_set: 0, 'intrusion-set': 0,
  campaign: 0,

  // tier 1 — capabilities
  malware: 1, tool: 1,
  technique: 1, tactic: 1, procedure: 1, ttp: 1,
  'attack-pattern': 1,
  vulnerability: 1, cve: 1,

  // tier 2 — infrastructure / mid-level
  infrastructure: 2, indicator: 2, 'observed-data': 2,

  // tier 3 — atomic IoCs / SCOs
  domain: 3, 'domain-name': 3,
  ipv4: 3, 'ipv4-addr': 3,
  ipv6: 3, 'ipv6-addr': 3,
  url: 3,
  email: 3, 'email-addr': 3,
  file: 3, sha256: 3, sha1: 3, md5: 3,
  registry_key: 3, 'windows-registry-key': 3,
  user_account: 3, 'user-account': 3,
  mutex: 3,
  asn: 3, 'autonomous-system': 3,
  network_traffic: 3, 'network-traffic': 3,

  // tier 4 — context
  identity: 4, location: 4,
  'course-of-action': 4, incident: 4,
}

export function getTier(type: string): number {
  return ENTITY_TIER[type] ?? 3
}

export function nodeRadius(type: string, degree: number): number {
  const tier = getTier(type)
  const base = tier === 0 ? 22 : tier === 1 ? 16 : tier === 2 ? 12 : 9
  return Math.min(base + Math.sqrt(Math.max(0, degree)) * 2, 32)
}

// ── STIX type icons ───────────────────────────────────────────────────────────
//
// Two-tier system:
//
// Tier 1 — Official OASIS STIX 2.1 icons (SDO types)
//   Path data extracted from the official stix-icons repository
//   (White/normal/SVG/ variant, viewBox 0 0 85 85, fill-based).
//   Inlined directly — no external file load, works in all SVG contexts.
//   typeStixIcon() returns the StixIconDef for a given type.
//
// Tier 2 — Lucide-react stroke paths (SCO types & IoCs)
//   Network observables, hashes, system artefacts — not in the official
//   STIX icon set.  24 × 24 viewBox, stroke-based (lucide-react ISC licence).
//   typeIconPath() returns the path string for a given SCO type.

// ── Tier 1: official STIX SDO icons (inline path data, 85×85 viewBox) ─────────
//
// Each entry is one or more SVG path `d` strings from the official STIX 2.1
// icon set (White/normal/SVG/), viewBox 0 0 85 85, fill-based.
// Inlining the paths avoids <image> file-loading failures inside inline SVGs.

export interface StixIconDef {
  d: string[]          // one or more path `d` strings
  evenodd?: boolean    // true if the paths use fill-rule:evenodd
}

const _SDO: Record<string, StixIconDef> = {
  // Threat_Actor.svg
  threat_actor: { evenodd: true, d: [
    'M65.8,56.54a26.7,26.7,0,0,0,1.12-24.78l4.08-13L60.6,21.05l-1.84.41A21.26,21.26,0,0,0,56,19.62a27,27,0,0,0-29.77,1.84l-1.84-.41L14,18.71l4.08,13.05A26.92,26.92,0,0,0,65.8,56.54Zm-19.88.91H39a2.45,2.45,0,1,1,0-4.89h6.94a2.45,2.45,0,0,1,0,4.89Zm.91-13.35a3.35,3.35,0,0,1,1.23-4.59l6-3.47a3.36,3.36,0,1,1,3.37,5.81l-6,3.47A3.34,3.34,0,0,1,46.83,44.1ZM33.48,45.32l-6-3.47A3.36,3.36,0,0,1,30.82,36l6,3.47a3.36,3.36,0,0,1-3.36,5.81Z',
  ]},
  // Intrusion_Set.svg
  intrusion_set: { d: [
    'M22.75,55.75A5.31,5.31,0,1,1,26.5,57.3,5.31,5.31,0,0,1,22.75,55.75ZM53.2,52a5.3,5.3,0,1,1,5.3,5.3A5.3,5.3,0,0,1,53.2,52ZM30.34,66.42a3.28,3.28,0,0,1,5.38-3.77,1.88,1.88,0,0,0,1.5.89,2.2,2.2,0,0,0,2-2.28V42.4H15a27.5,27.5,0,0,1,55,0H45.79V61.16A8.67,8.67,0,0,1,37.32,70H37A8,8,0,0,1,30.34,66.42Z',
  ]},
  // Campaign.svg
  campaign: { evenodd: true, d: [
    'M16,59.63V46.33H26.42V38.77h5.66v7.56H42V52H35.32V62.85H42V69H25.31A9.35,9.35,0,0,1,16,59.63ZM52.92,47.74V42.1H46.24V35.45h6.68V21.24H46.24V16.1H59.59A9.44,9.44,0,0,1,69,25.47V42.1H61.92v5.64ZM16,42.1V25.37A9.44,9.44,0,0,1,25.41,16H42.1v9.47h6.67v5.64H42.1V42H36.43V34.44H22.17V42H16Z',
  ]},
  // Malware.svg
  malware: { d: [
    'M42.5,26.48a16.26,16.26,0,0,0-4.44.59,4.53,4.53,0,0,1,8.88,0A16.26,16.26,0,0,0,42.5,26.48Zm-2.37,27V41.69a2.37,2.37,0,0,1,4.74,0V53.44a2.37,2.37,0,0,1-4.74,0Zm18.76,4.14,7.8,4.15a3.23,3.23,0,1,0,3-5.73l-9.39-5V43.76H70.74a3.26,3.26,0,1,0,0-6.52H58.89a15,15,0,0,0-1.48-2.76l6.12-6.12A3.21,3.21,0,1,0,59,23.81l-5.53,5.53c0-.39.1-.89.1-1.28a11.06,11.06,0,0,0-22.12,0,5.53,5.53,0,0,0,.1,1.28L26,23.81a3.21,3.21,0,0,0-4.54,4.55l6.12,6.12a15,15,0,0,0-1.48,2.76H14.26a3.26,3.26,0,1,0,0,6.52H24.73V51l-9.39,5a3.23,3.23,0,1,0,3,5.73l7.8-4.15A17.76,17.76,0,0,0,42.5,68.45,18,18,0,0,0,58.89,57.58Z',
  ]},
  // Tool.svg
  tool: { evenodd: true, d: [
    'M16.46,68.51l-.6-.6a6.29,6.29,0,0,1,0-8.93L26.28,48.57A2.94,2.94,0,0,1,31,45.29l1.79,1.79,2.68-2.68-4.07-4.07a13.39,13.39,0,0,1-12.9-3.47,13.13,13.13,0,0,1-3.87-10.42v-.1l.1-.89a1.35,1.35,0,0,1,2.28-.79l5,5a3.67,3.67,0,0,0,5.26,0l3-3a3.67,3.67,0,0,0,0-5.26l-5-5a1.34,1.34,0,0,1,.79-2.28L27,14h.1A13.36,13.36,0,0,1,41,30.81L45,34.88l12-12a2.13,2.13,0,0,1,.29-2.78l5-5,7.05,7-5,5a2.39,2.39,0,0,1-2.78.29l-12,11.81L69.14,58.79a6.29,6.29,0,0,1,0,8.93l-.6.59a6.29,6.29,0,0,1-8.93,0L40.07,48.77l-2.68,2.67,1.79,1.79A2.94,2.94,0,0,1,35.9,58L25.48,68.41A6.31,6.31,0,0,1,16.46,68.51Zm49.9-2.78a3.37,3.37,0,1,0-4.76,0A3.41,3.41,0,0,0,66.36,65.73Z',
  ]},
  // Attack_Pattern.svg (technique / tactic / ttp / procedure)
  'attack-pattern': { evenodd: true, d: [
    'M48.37,15.46,69.54,36.58a8.35,8.35,0,0,1,0,11.84L48.37,69.54a8.34,8.34,0,0,1-11.83,0L15.46,48.42a8.35,8.35,0,0,1,0-11.84L36.54,15.46A8.34,8.34,0,0,1,48.37,15.46ZM37.73,26.82l-10.94,11a5.57,5.57,0,0,0-1.29-.1,4.74,4.74,0,1,0,5.07,4.38,4.11,4.11,0,0,0-.2-1.09L40,31.3V55.49A4.68,4.68,0,0,0,37.73,60a4.73,4.73,0,1,0,9.44-.7c0-.3-.1-.6-.1-.8L58.21,47.23a3.67,3.67,0,0,0,1.79.2,4.74,4.74,0,1,0-5.07-4.38.9.9,0,0,0,.1.5L44.89,53.6V30.4a4.66,4.66,0,0,0,2.28-4.48,4.76,4.76,0,0,0-5.07-4.38A5,5,0,0,0,37.73,26.82Z',
  ]},
  // Vulnerability.svg
  vulnerability: { evenodd: true, d: [
    'M45.79,70.72V66.64A24.31,24.31,0,0,0,66.62,45.73h4.09a3.28,3.28,0,1,0,0-6.56H66.62A24.3,24.3,0,0,0,45.79,18.36V14.28a3.29,3.29,0,0,0-6.58,0v4.08A24.3,24.3,0,0,0,18.38,39.27H14.29a3.28,3.28,0,1,0,0,6.56h4.09A24.3,24.3,0,0,0,39.31,66.64v4.08A3.32,3.32,0,0,0,42.6,74,3.37,3.37,0,0,0,45.79,70.72ZM24.66,42.45A17.84,17.84,0,1,1,42.5,60.27,17.81,17.81,0,0,1,24.66,42.45Zm29.8,0a12,12,0,1,0-12,11.94A12,12,0,0,0,54.46,42.45ZM37,42.45a5.48,5.48,0,1,1,5.48,5.47A5.45,5.45,0,0,1,37,42.45Z',
  ]},
  // Infrastructure.svg
  infrastructure: { evenodd: true, d: [
    'M16,59.63V57.31H29.73V69H25.39A9.43,9.43,0,0,1,16,59.63ZM36.49,69V57.31H69v2.32A9.43,9.43,0,0,1,59.61,69ZM16,50.56V25.37A9.43,9.43,0,0,1,25.39,16h4.34V50.56Zm20.49,0V16H59.61A9.43,9.43,0,0,1,69,25.37V50.56Z',
  ]},
  // Indicator.svg
  indicator: { d: [
    'M40.52,70.17a3.23,3.23,0,0,1-.9-4.5,6.08,6.08,0,0,0,1.1-4.5c-.2-1.3-1.1-2.9-3.2-4.5-.2-.1-.7-.5-1.4-.9a20.09,20.09,0,0,1-2.7-2.1,18,18,0,0,1-5.3-8.5v-.1a14.77,14.77,0,0,1,4.7-14.8c.2-.1.4-.3,0,0a15.48,15.48,0,0,1,6-3.1,12.19,12.19,0,0,1,3.2-.4,15.81,15.81,0,0,1,3.8.4h.1a17.2,17.2,0,0,1,4,1.4,31.71,31.71,0,0,1,10.5,8.3,3.26,3.26,0,1,1-4.9,4.3,25.16,25.16,0,0,0-8.2-6.6,18.08,18.08,0,0,0-2.7-1h-.1a5.66,5.66,0,0,0-2.2-.2,8.81,8.81,0,0,0-1.7.2,7.43,7.43,0,0,0-3.3,1.7.1.1,0,0,0-.1.1,8.11,8.11,0,0,0-2.8,7.1l.2,1.1.3.8a11.73,11.73,0,0,0,3.2,4.6,29.32,29.32,0,0,0,3.7,2.6c6.8,5.1,7.4,12.1,3.7,17.8A4.14,4.14,0,0,1,40.52,70.17Zm12.1-5.4c.2-9.1-3.4-16-11.7-20.5a3.24,3.24,0,1,1,3.1-5.7c10.6,5.7,15.4,14.9,15.2,26.4a3.18,3.18,0,0,1-3.3,3.2A3.41,3.41,0,0,1,52.62,64.77ZM27.12,63a26.62,26.62,0,0,1-10-13.8,3.29,3.29,0,0,1,6.3-1.9,19.85,19.85,0,0,0,7.5,10.4,3.33,3.33,0,0,1,.8,4.6A3.44,3.44,0,0,1,27.12,63Zm35.1-11c-.6-1.5-1.3-3-2-4.5a3.29,3.29,0,1,1,5.9-2.9c.8,1.7,1.6,3.4,2.3,5.1a3.18,3.18,0,0,1-1.9,4.2A3.5,3.5,0,0,1,62.22,52Zm-43.3-9.6a3.26,3.26,0,0,1-2.9-3.6,26,26,0,0,1,3.6-10.9,24.09,24.09,0,0,1,6.1-7A25,25,0,0,1,36,15.77a26.65,26.65,0,0,1,22.5,4.7,3.28,3.28,0,1,1-4,5.2,19.8,19.8,0,0,0-24.7.3,21.17,21.17,0,0,0-4.6,5.3,19.88,19.88,0,0,0-2.7,8.2A3.41,3.41,0,0,1,18.92,42.37Zm42.9-10.9c-.1-.2-.3-.3-.4-.5a3.25,3.25,0,0,1,4.6-4.6,11,11,0,0,1,1,1.1,3.23,3.23,0,0,1-.6,4.6A3.32,3.32,0,0,1,61.82,31.47Z',
  ]},
  // Location.svg
  location: { evenodd: true, d: [
    'M36.59,31.23a5.86,5.86,0,0,1,5.9-5.89,5.92,5.92,0,0,1,5.89,5.89,5.86,5.86,0,0,1-5.89,5.9A5.92,5.92,0,0,1,36.59,31.23Zm21.84-3.09C56.88,20.8,51.28,15,42.49,15s-14.3,5.8-16,13.14c-3.09,14.59,7.64,30.24,16,41.74C50.8,58.38,61.62,42.63,58.43,28.14Z',
  ]},
  // Identity_Organization.svg
  identity: { evenodd: true, d: [
    'M59.63,16H25.37c-5.14,0-9.37,4.23-9.37,9.37v34.26c0,5.14,4.23,9.37,9.37,9.37h34.26c5.14,0,9.37-4.23,9.37-9.37V25.37c0-5.14-4.23-9.37-9.37-9.37Zm-33.79,14.28l15.69-6.79c.61-.3,1.34-.3,1.95,0l15.68,6.79v2.07H25.84v-2.07Zm.55,4.56h32.22c1.04,0,1.88.84,1.88,1.88s-.84,1.88-1.88,1.88H26.39c-1.04,0-1.88-.84-1.88-1.88s.84-1.88,1.88-1.88Zm30.4,6.27v14.12h-7.05v-14.12h7.05Zm-10.77,0v14.12h-7.05v-14.12h7.05Zm-10.77,0v14.12h-7.05v-14.12h7.05Zm26.36,20.62H23.39v-1.75c0-1.24,1.01-2.25,2.25-2.25h33.73c1.24,0,2.25,1.01,2.25,2.25v1.75Z',
  ]},
  // Incident.svg (two paths)
  incident: { d: [
    'M63.59,44.88a3.36,3.36,0,0,1,0-4.75L73,30.72a.87.87,0,0,0-.62-1.49H59.13a3.36,3.36,0,0,1-3.36-3.35V12.58A.87.87,0,0,0,54.29,12l-9.42,9.41a3.35,3.35,0,0,1-4.74,0L30.71,12a.87.87,0,0,0-1.48.61v13.3a3.36,3.36,0,0,1-3.36,3.35H12.61A.87.87,0,0,0,12,30.72l9.42,9.41a3.36,3.36,0,0,1,0,4.75L12,54.29a.87.87,0,0,0,.62,1.49H25.87a3.36,3.36,0,0,1,3.36,3.35V72.42a.87.87,0,0,0,1.48.61l9.42-9.41a3.35,3.35,0,0,1,4.74,0L54.29,73a.87.87,0,0,0,1.48-.61V59.13a3.36,3.36,0,0,1,3.36-3.35H72.39A.87.87,0,0,0,73,54.29Zm-9.21-.82A12,12,0,1,1,40.94,30.62,12,12,0,0,1,54.38,44.06Z',
    'M42.5,36.9a5.6,5.6,0,1,0,5.6,5.6A5.6,5.6,0,0,0,42.5,36.9Z',
  ]},
  // Course_of_Action.svg
  'course-of-action': { evenodd: true, d: [
    'M19.74,65.46l-.2-.2a15.72,15.72,0,0,1,0-22.1L43.16,19.54a15.72,15.72,0,0,1,22.1,0l.2.2a15.72,15.72,0,0,1,0,22.1L41.84,65.46A15.72,15.72,0,0,1,19.74,65.46ZM37.2,60.72,48.91,49,36,36.09,24.28,47.8a9,9,0,0,0,0,12.71l.21.21A9,9,0,0,0,37.2,60.72Z',
  ]},
  // Observed_Data.svg
  'observed-data': { evenodd: true, d: [
    'M14,42.5A28.5,28.5,0,1,1,42.5,71,28.47,28.47,0,0,1,14,42.5Zm51.08,0A22.58,22.58,0,1,0,42.5,65.08,22.62,22.62,0,0,0,65.08,42.5Zm-37.73,0a13.6,13.6,0,0,1,.1-2H42V27.35h.5A15.15,15.15,0,1,1,27.35,42.5Z',
  ]},
  // Sighting.svg
  sighting: { d: [
    'M31.52,65.92l-12.4-45.8a3.26,3.26,0,1,1,6.3-1.7l.3,1.3c7.4-4,11.8-2.1,16,.4s7.9,5.3,14.3,3.4l1.6-.5a2.54,2.54,0,0,1,3.3,1.7l5.9,21.9a2.53,2.53,0,0,1-1.7,3.1l-1.6.5h-.2c-1.1.2-2.1.4-3.2.5-7,.5-11.8-2.8-16.1-4.6-3.3-1.4-6.5-2-10.5.1l-.6.3,4.8,17.7a3.26,3.26,0,0,1-2.3,4A3.16,3.16,0,0,1,31.52,65.92Z',
  ]},
  // Report.svg
  report: { evenodd: true, d: [
    'M20,61.53V16H57.5A7.44,7.44,0,0,1,65,23.47V69H27.5A7.5,7.5,0,0,1,20,61.53Zm24.2-8.48a2.44,2.44,0,0,0-2.4-2.42h-9a2.42,2.42,0,0,0,0,4.84h9A2.44,2.44,0,0,0,44.2,53.05ZM54.7,40.73a2.44,2.44,0,0,0-2.4-2.42H32.7a2.43,2.43,0,0,0,0,4.85H52.3A2.45,2.45,0,0,0,54.7,40.73Zm0-12.31A2.45,2.45,0,0,0,52.3,26H32.7a2.43,2.43,0,0,0,0,4.85H52.3A2.44,2.44,0,0,0,54.7,28.42Z',
  ]},
  // Note.svg
  note: { evenodd: true, d: [
    'M16,59.74V25.53a9.41,9.41,0,0,1,9.36-9.36h31L40.55,32a2.38,2.38,0,0,0-.7,1.31l-2,11.37a2.42,2.42,0,0,0,2.81,2.82l11.38-2a2.39,2.39,0,0,0,1.3-.7l15.5-15.5V59.64A9.41,9.41,0,0,1,59.47,69H25.26A9.3,9.3,0,0,1,16,59.74ZM43.37,42l1-5.63L49,41ZM53,38.11,47.2,32.27,66.31,13.15a.39.39,0,0,1,.61,0l5.23,5.23a.39.39,0,0,1,0,.61Z',
  ]},
  // Grouping.svg
  grouping: { d: [
    'M16,34.7V25.3A9.35,9.35,0,0,1,25.3,16h9.4v6.8h-10a1.9,1.9,0,0,0-1.9,1.9v10Zm46.2,0v-10a1.9,1.9,0,0,0-1.9-1.9h-10V16h9.4A9.35,9.35,0,0,1,69,25.3v9.4ZM27.85,38.15a10.2,10.2,0,0,1,20.4,0h-6.8a3.35,3.35,0,0,0-3.3,3.4v6.8A10.33,10.33,0,0,1,27.85,38.15ZM40.26,57.06a2,2,0,0,1-2-2v-6.6a10.24,10.24,0,0,0,10.2-10.2h6.6a2,2,0,0,1,2,2v14.8a2,2,0,0,1-2.1,2ZM25.3,69A9.35,9.35,0,0,1,16,59.7V50.3h6.8v10a2,2,0,0,0,1.9,1.9h10V69Zm25,0V62.2h10a1.9,1.9,0,0,0,1.9-1.9v-10H69v9.4A9.35,9.35,0,0,1,59.7,69Z',
  ]},
  // Opinion.svg
  opinion: { evenodd: true, d: [
    'M60.54,39.9a5,5,0,1,0-5,5A5,5,0,0,0,60.54,39.9Zm-13.07,0a5,5,0,1,0-5,5A5,5,0,0,0,47.47,39.9Zm-13.08,0a5,5,0,1,0-5,5A5,5,0,0,0,34.39,39.9Zm-11,32.73V57.53C16.46,53.38,12,47,12,39.8,12,27.23,25.68,17,42.5,17S73,27.23,73,39.8,59.32,62.6,42.5,62.6a35.65,35.65,0,0,1-8.82-1Z',
  ]},
  // Relationship.svg
  relationship: { d: [
    'M52.35,42.27a8.38,8.38,0,1,0,8.38-8.37A8.39,8.39,0,0,0,52.35,42.27Zm-2.42,10.8a15.25,15.25,0,0,1-4.09-7.35H39.15a15.27,15.27,0,1,1,0-6.9h6.69a15.28,15.28,0,1,1,4.09,14.25Z',
  ]},
  // Malware_Analysis.svg
  'malware-analysis': { d: [
    'M34,42.5A8.5,8.5,0,1,1,42.5,51,8.51,8.51,0,0,1,34,42.5ZM19.28,66.24a3.23,3.23,0,0,1,0-4.61l6.22-6.19L24,53.38a22,22,0,0,1-3-8v-.09h-8.8a3.24,3.24,0,1,1,0-6.48h8.8v-.1a22,22,0,0,1,3-7.95l1.48-2.06-6.22-6.18a3.23,3.23,0,0,1,0-4.61,3.28,3.28,0,0,1,4.64,0l6.42,6.37,1.78-1.07a11.51,11.51,0,0,1,2.57-1.18,2.78,2.78,0,0,1,3.66,1.57,2.74,2.74,0,0,1-1.58,3.63,16.11,16.11,0,0,0,0,30,2.74,2.74,0,0,1,1.58,3.63,2.78,2.78,0,0,1-3.66,1.57c-.89-.39-1.78-.79-2.57-1.18l-1.78-1.08-6.42,6.38a3.48,3.48,0,0,1-2.05.62A3.68,3.68,0,0,1,19.28,66.24Zm41.8.39-6.42-6.38-1.78,1.08c-.79.39-1.68.79-2.57,1.18a2.78,2.78,0,0,1-3.66-1.57,2.74,2.74,0,0,1,1.58-3.63,16.11,16.11,0,0,0,0-30,2.74,2.74,0,0,1-1.58-3.63,2.78,2.78,0,0,1,3.66-1.57,11.51,11.51,0,0,1,2.57,1.18l1.78,1.07L61.08,18a3.28,3.28,0,0,1,4.64,0,3.23,3.23,0,0,1,0,4.61L59.5,28.75,61,30.81a22,22,0,0,1,3,8v.1h8.8a3.24,3.24,0,1,1,0,6.48h-8.8v.09a22,22,0,0,1-3,8L59.5,55.44l6.22,6.19a3.23,3.23,0,0,1,0,4.61,3.68,3.68,0,0,1-2.59,1A3.48,3.48,0,0,1,61.08,66.63Z',
  ]},
}

// Aliases — same icon, different type name
_SDO['threat-actor']    = _SDO.threat_actor
_SDO['intrusion-set']   = _SDO.intrusion_set
_SDO.technique          = _SDO['attack-pattern']
_SDO.tactic             = _SDO['attack-pattern']
_SDO.procedure          = _SDO['attack-pattern']
_SDO.ttp                = _SDO['attack-pattern']
_SDO.cve                = _SDO.vulnerability

/**
 * Returns the official STIX 2.1 icon definition (path data, 85×85 viewBox)
 * for an SDO entity type, or null for SCO / unknown types.
 */
export function typeStixIcon(type: string): StixIconDef | null {
  return _SDO[type] ?? null
}

/** @deprecated use typeStixIcon() + typeIconPath() — kept for import compatibility */
export function typeIconUrl(_type: string): string | null { return null }

// ── Tier 2: SCO / IoC icons — lucide-react stroke paths (24 × 24 viewBox) ─────
// Used for network observables, hashes, and system artefacts that are NOT
// covered by the official STIX SDO icon set.

// SCO types only — lucide-react stroke paths (24 × 24 viewBox).
// SDO types are now covered by typeIconUrl() via official STIX SVG files.
const _SCO_PATH: Record<string, string> = {
  // IPv4 / IPv6 → Wifi (concentric arcs)
  ipv4:              'M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0 M12 20h.01',
  ipv6:              'M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0 M12 20h.01',
  'ipv4-addr':       'M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0 M12 20h.01',
  'ipv6-addr':       'M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0 M12 20h.01',

  // domain → Globe (sphere with meridians)
  domain:            'M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2z M2 12h20 M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z',
  'domain-name':     'M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2z M2 12h20 M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z',

  // URL → Link2 (two chain links)
  url:               'M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71 M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71',

  // email → Mail (envelope)
  email:             'M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z M22 6l-10 7L2 6',
  'email-addr':      'M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z M22 6l-10 7L2 6',

  // file / hashes → FileText
  file:              'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8 M10 9H8',
  sha256:            'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8 M10 9H8',
  sha1:              'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8 M10 9H8',
  md5:               'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8 M10 9H8',

  // registry key → Key
  registry_key:           'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0 L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
  'windows-registry-key': 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0 L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',

  // mutex → Lock (padlock)
  mutex:             'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2z M7 11V7a5 5 0 0 1 10 0v4',

  // user account → User (head + shoulders)
  user_account:      'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2 M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8',
  'user-account':    'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2 M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8',

  // ASN → Network topology
  asn:               'M6 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M18 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M12 15a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M9 6h6 M6 9v3a6 6 0 0 0 12 0V9',
  'autonomous-system':'M6 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M18 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M12 15a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M9 6h6 M6 9v3a6 6 0 0 0 12 0V9',

  // MAC address → Cpu (chip with pins)
  mac_addr:          'M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4 M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18',
  'mac-addr':        'M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4 M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18',

  // network traffic → Activity (pulse wave)
  network_traffic:   'M22 12h-4l-3 9L9 3l-3 9H2',
  'network-traffic': 'M22 12h-4l-3 9L9 3l-3 9H2',
}

/**
 * Return the lucide stroke-path (24 × 24 viewBox) for SCO entity types.
 * Returns null for SDO types — use typeIconUrl() for those.
 */
export function typeIconPath(type: string): string | null {
  return _SCO_PATH[type] ?? null
}

// ── Hierarchical layout ───────────────────────────────────────────────────────

function _bary(
  id: string,
  adj: Record<string, Set<string>>,
  rank: Record<string, number>,
): number {
  let s = 0, c = 0
  adj[id]?.forEach(nb => { if (rank[nb] != null) { s += rank[nb]; c++ } })
  return c ? s / c : 1e6
}

export function layoutHierarchical(
  nodes: GraphNode[],
  edges: GraphEdge[],
  deg: Record<string, number>,
  adj: Record<string, Set<string>>,
  opts: { spanW?: number; colW?: number; rowH?: number } = {},
): PosMap {
  const spanW = opts.spanW ?? 1400
  const colW  = opts.colW  ?? 128
  const rowH  = opts.rowH  ?? 200

  const tiers: Record<number, GraphNode[]> = {}
  for (const n of nodes) {
    const t = getTier(n.type)
    ;(tiers[t] = tiers[t] || []).push(n)
  }
  const tierKeys = Object.keys(tiers).map(Number).sort((a, b) => a - b)

  const pos: PosMap = {}
  let prevOrder: string[] | null = null

  tierKeys.forEach((tk, ti) => {
    let row = tiers[tk]
    if (prevOrder) {
      const rank = Object.fromEntries(prevOrder.map((id, i) => [id, i]))
      row = [...row].sort((a, b) => _bary(a.id, adj, rank) - _bary(b.id, adj, rank))
    } else {
      row = [...row].sort((a, b) => (deg[b.id] || 0) - (deg[a.id] || 0))
    }
    const total = row.length
    const step  = total > 1 ? Math.min(colW, spanW / (total - 1)) : 0
    row.forEach((n, i) => {
      pos[n.id] = { x: (i - (total - 1) / 2) * step, y: ti * rowH }
    })
    prevOrder = row.map(n => n.id)
  })
  return pos
}

// ── Radial layout ─────────────────────────────────────────────────────────────

export function layoutRadial(
  nodes: GraphNode[],
  edges: GraphEdge[],
  deg: Record<string, number>,
  adj: Record<string, Set<string>>,
  opts: { ringGap?: number } = {},
): PosMap {
  const ringGap = opts.ringGap ?? 130

  // Root = highest-degree tier-0 node (or fallback to most-connected)
  let root = nodes[0]
  let best = -Infinity
  for (const n of nodes) {
    const score = (deg[n.id] || 0) - getTier(n.type) * 100
    if (score > best) { best = score; root = n }
  }

  // BFS depth from root
  const depth: Record<string, number> = { [root.id]: 0 }
  const q = [root.id]
  while (q.length) {
    const cur = q.shift()!
    adj[cur]?.forEach(nb => {
      if (depth[nb] == null) { depth[nb] = depth[cur] + 1; q.push(nb) }
    })
  }
  let maxD = 0
  for (const id in depth) maxD = Math.max(maxD, depth[id])
  for (const n of nodes) if (depth[n.id] == null) depth[n.id] = maxD + 1
  maxD++

  const rings: Record<number, GraphNode[]> = {}
  for (const n of nodes) (rings[depth[n.id]] = rings[depth[n.id]] || []).push(n)

  const pos: PosMap = {}
  Object.keys(rings).map(Number).sort((a, b) => a - b).forEach(d => {
    const row = rings[d]
    if (d === 0) { pos[row[0].id] = { x: 0, y: 0 }; return }
    const R = d * ringGap
    row.forEach((n, i) => {
      const a = (i / row.length) * Math.PI * 2 - Math.PI / 2
      pos[n.id] = { x: R * Math.cos(a), y: R * Math.sin(a) }
    })
  })
  return pos
}
