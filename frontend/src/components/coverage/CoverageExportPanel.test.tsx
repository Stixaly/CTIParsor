import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import CoverageExportPanel from './CoverageExportPanel'
import type { RuleSelection, SelectableRule } from '../../hooks/useRuleSelection'
import type { TechEntry } from './model'

// The ZIP is built from a blob, so the export goes through a temporary <a>.
// Firefox ignores click() on an <a> that is not in the document (#546).
const api = vi.hoisted(() => ({
  downloadExportSelection: vi.fn(),
}))
vi.mock('../../api/client', async (orig) => ({ ...(await orig<object>()), ...api }))

const RULE: SelectableRule = {
  id: 'r1', format: 'sigma', corpus: 'corpus-a', license: 'MIT', severity: 'high',
  title: 'Suspicious PowerShell', bytes: 120, techniques: ['T1059'],
}

const SELECTION: RuleSelection = {
  excluded: new Set<string>(),
  isSelected: () => true,
  selectedCount: 1,
  totalCount: 1,
  selectedBytes: 120,
  selectedOf: (ids) => ids.length,
  bytesOf: () => 120,
  toggleScope: () => {},
  selectAll: () => {},
  clearAll: () => {},
}

beforeEach(() => {
  api.downloadExportSelection.mockReset().mockResolvedValue({
    blob: new Blob(['zip'], { type: 'application/zip' }),
    filename: 'report_detection_rules.zip',
  })
  URL.createObjectURL = vi.fn(() => 'blob:zip')
  URL.revokeObjectURL = vi.fn()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('CoverageExportPanel — ZIP download', () => {
  it('attaches the export link to document.body while clicking it (#546)', async () => {
    const clicked: Array<{ attached: boolean; download: string }> = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push({ attached: document.body.contains(this), download: this.download })
    })
    render(
      <CoverageExportPanel
        jobId="job-1"
        reportName="report.pdf"
        columns={[]}
        rules={[RULE]}
        rulesById={new Map([[RULE.id, RULE]])}
        selection={SELECTION}
        hasPromoted
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /Download ZIP/ }))
    await waitFor(() => expect(clicked).toHaveLength(1))
    expect(clicked[0]).toEqual({ attached: true, download: 'report_detection_rules.zip' })
    expect(document.querySelectorAll('a[download]')).toHaveLength(0)           // removed again
    await waitFor(() => expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:zip'))
  })

  // #486 — while a promoted rule's metadata is pending, the ZIP cannot be built yet:
  // the plain GET would drop the promotion, so the download waits instead.
  it('disables the download and offers no GET link until the inventory is complete (#486)', () => {
    render(
      <CoverageExportPanel
        jobId="job-1"
        reportName="report.pdf"
        columns={[]}
        rules={[RULE]}
        rulesById={new Map([[RULE.id, RULE]])}
        selection={SELECTION}
        hasPromoted
        inventoryComplete={false}
      />,
    )
    expect(document.querySelector('a[download]')).toBeNull()
    expect(screen.getByRole('button', { name: 'Loading promoted rules…' })).toBeDisabled()
  })

  it('says so when the promoted rules could not be fetched, instead of loading forever (#486)', () => {
    render(
      <CoverageExportPanel
        jobId="job-1"
        reportName="report.pdf"
        columns={[]}
        rules={[RULE]}
        rulesById={new Map([[RULE.id, RULE]])}
        selection={SELECTION}
        hasPromoted
        inventoryComplete={false}
        inventoryFailed
      />,
    )
    expect(screen.queryByRole('button', { name: 'Loading promoted rules…' })).toBeNull()
    expect(screen.getByRole('button', { name: /Promoted rules did not load/ })).toBeDisabled()
  })
})

const RULE_B: SelectableRule = {
  id: 'r2', format: 'sigma', corpus: 'corpus-b', license: 'MIT', severity: 'low',
  title: 'Odd service', bytes: 80, techniques: ['T1059'],
}

const NONE_SELECTED: RuleSelection = {
  ...SELECTION,
  excluded: new Set(['r1', 'r2']),
  isSelected: () => false,
  selectedCount: 0,
  selectedBytes: 0,
  selectedOf: () => 0,
  bytesOf: () => 0,
}

// #566 — a format header with no rule shows its own format's badge, never another's.
describe('CoverageExportPanel — format header badges (#566)', () => {
  it('gives the empty Suricata and YARA headers their own letter, not Sigma', () => {
    render(
      <CoverageExportPanel
        jobId="job-1"
        reportName="report.pdf"
        columns={[]}
        rules={[RULE]}
        rulesById={new Map([[RULE.id, RULE]])}
        selection={SELECTION}
        hasPromoted
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'By format · corpus' }))
    expect(screen.queryByTitle('Sigma: 0 of 0 selected')).toBeNull()
    expect(screen.getByTitle('Suricata: 0 of 0 selected')).toHaveTextContent('N —')
    expect(screen.getByTitle('YARA: 0 of 0 selected')).toHaveTextContent('Y —')
  })
})

// #567 — the tactic header counts the corpora of the whole tactic, selected or not.
describe('CoverageExportPanel — tactic header corpora (#567)', () => {
  it('counts the tactic corpora when nothing is selected, as its technique row does', () => {
    const tech: TechEntry = {
      id: 'T1059', name: 'Command and Scripting Interpreter', tactics: ['execution'], score: 2,
      ruleIds: ['r1', 'r2'], byFormat: { sigma: ['r1', 'r2'], suricata: [], yara: [] },
    }
    render(
      <CoverageExportPanel
        jobId="job-1"
        reportName="report.pdf"
        columns={[{ tactic: 'execution', label: 'Execution', techs: [tech] }]}
        rules={[RULE, RULE_B]}
        rulesById={new Map([[RULE.id, RULE], [RULE_B.id, RULE_B]])}
        selection={NONE_SELECTED}
        hasPromoted
      />,
    )
    // The tactic row and its one technique row both say 2 corpora.
    expect(screen.getAllByText('2 corpora')).toHaveLength(2)
    expect(screen.queryByText('0 corpora')).toBeNull()
  })
})
