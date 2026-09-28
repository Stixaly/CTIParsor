import type { JobStatus } from '../types'

/** One name per job status, so the Dashboard's columns and Review's
 *  breadcrumb cannot disagree about what a report is. */
export const JOB_STATUS_LABEL: Record<JobStatus, string> = {
  uploaded:   'Uploaded',
  processing: 'Processing',
  for_review: 'For review',
  reviewing:  'Reviewing',
  completed:  'Completed',
  failed:     'Failed',
}
