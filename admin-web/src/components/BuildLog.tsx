import JobLog from './JobLog'
import { api } from '../api'
import type { BuildJob } from '../types'

// ---------------------------------------------------------------------------
// Live output of `docker compose build`.
//
// A thin wrapper over the shared job modal: this is docker's output, and
// JobLog.tsx is the modal. What is specific to a compose build is how a line is
// coloured, which is the part that cannot be generalised - see lineClass below.
// ---------------------------------------------------------------------------

/** Line colour by shape, not by parsing success into words.
 *
 *  Order matters and was wrong on the first pass: buildkit emits its failures
 *  as `#17 ERROR: ...`, which also matches a naive `^#\d+\s` step-header test.
 *  Checking the header first coloured the most important line in a failed build
 *  as a heading. So the ERROR arm has to come first.
 */
function lineClass(line: string): string {
  const step = line.match(/^#\d+\s+(.*)$/)
  if (step) {
    const rest = step[1]
    if (/^ERROR\b/i.test(rest) || /\berror\b/i.test(rest)) return 'compose-tok-bool'
    if (/^(DONE|CACHED)\b/i.test(rest)) return 'compose-tok-string'
    // "[internal] load build definition" and friends: the actual step names.
    if (/^\[/.test(rest)) return 'compose-tok-key font-medium'
    return 'compose-tok-plain'
  }
  if (/\bERROR\b|\berror:|failed|Failed to|denied|unauthorized/i.test(line)) {
    return 'compose-tok-bool'
  }
  // compose's own logrus warnings, e.g. a version mismatch on an env file.
  if (/level=(warning|error)\b/.test(line)) return 'compose-tok-warning'
  if (line.startsWith('#')) return 'compose-tok-comment'
  return 'compose-tok-plain'
}

export default function BuildLog({
  jobId,
  projectLabel,
  onClose,
  onFinished,
}: {
  jobId: string
  projectLabel: string
  onClose: () => void
  /** Called once when the job reaches a terminal state, so the page can
   *  refresh its container list. */
  onFinished?: (job: BuildJob) => void
}) {
  return (
    <JobLog
      jobId={jobId}
      title={`Building ${projectLabel}`}
      subtitle="docker compose build"
      fetchJob={(id) => api.containerBuildJob(id)}
      onClose={onClose}
      lineClass={lineClass}
      onFinished={onFinished && ((job) => onFinished(job as BuildJob))}
    />
  )
}