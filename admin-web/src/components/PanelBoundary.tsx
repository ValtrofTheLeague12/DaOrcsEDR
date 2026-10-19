import { Component, type ErrorInfo, type ReactNode } from 'react'

/**
 * Catches a render error in one panel and shows it, instead of letting React
 * unmount the whole console.
 *
 * This exists because of a specific failure: the panel went blank with no
 * message, and nothing on the page said why. Without a boundary, React 19
 * unmounts the entire tree on an uncaught error - including the sidebar - so a
 * bug in one lazy panel costs the operator the nav, the auth gate and every
 * other working page, and all they can report is "it won't open".
 *
 * Two decisions worth stating:
 *
 * It resets when the panel changes. A boundary that latches its error would
 * poison the whole session: one bad page would leave the operator unable to
 * navigate anywhere to recover. Keeping the error visible is the point;
 * trapping the user in it is not.
 *
 * It shows the message and the component stack rather than "something went
 * wrong". The stack names the file and line that threw, which is the difference
 * between a five-minute fix and an afternoon of bisecting.
 */
interface Props {
  /** Panel name, so the message can say what failed. */
  label: string
  children: ReactNode
}

interface State {
  error: Error | null
  stack: string
}

export default class PanelBoundary extends Component<Props, State> {
  state: State = { error: null, stack: '' }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Also to the console, so DevTools keeps the original with its own stack and
    // a "pause on exception" breakpoint still works.
    console.error(`[panel:${this.props.label}]`, error, info.componentStack)
    this.setState({ stack: info.componentStack ?? '' })
  }

  componentDidUpdate(prev: Props) {
    // Navigating away clears the failure. React only calls this on update, so a
    // fresh click is what recovers - which is exactly what someone does next.
    if (this.state.error && prev.label !== this.props.label) {
      this.setState({ error: null, stack: '' })
    }
  }

  private reload = () => window.location.reload()

  render() {
    const { error, stack } = this.state
    if (!error) return this.props.children

    return (
      <div className="flex flex-col gap-3 rounded-lg border border-danger/40 bg-danger/5 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="page-title">This panel failed to open</p>
            <p className="mt-1 text-[12px] text-default-500">
              <strong className="text-foreground">{this.props.label}</strong> threw
              while rendering. The rest of the console is still working - pick
              another page, or reload to try this one again.
            </p>
          </div>
          <button type="button" className="build-btn is-secondary" onClick={this.reload}>
            Reload
          </button>
        </div>

        <pre className="build-log overflow-x-auto whitespace-pre-wrap break-words text-[11px] text-danger">
          {error.message || String(error)}
        </pre>

        {stack && (
          <details className="text-[11px]">
            <summary className="cursor-pointer text-default-500">
              Component stack
            </summary>
            <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words font-mono text-default-400">
              {stack.trim()}
            </pre>
          </details>
        )}
      </div>
    )
  }
}