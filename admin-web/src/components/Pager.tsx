import { useEffect, useState } from 'react'

// ---------------------------------------------------------------------------
// Pagination for lists that are usually short and occasionally enormous.
//
// A lab box accumulates machines: VirtualBox on a research host can carry
// hundreds of registered VMs, most of them irrelevant to the person looking.
// Rendering all of them turns a status row into a scroll that pushes the
// information actually being looked for off the bottom of the card.
//
// This is page-in-memory, not server-side, because every payload here is
// already fully in the browser - the panel hands back the whole machine list in
// one response and there is no paged endpoint to talk to. Paging client-side
// keeps the API honest about what it returns instead of adding a cursor
// protocol that a 40-element array does not need.
//
// The page resets whenever `total` changes underneath it. Without that, a
// rescan that shrinks the list leaves the viewer stranded on a page 9 of 3 -
// blank, and indistinguishable from a rendering bug.
// ---------------------------------------------------------------------------

export const PAGE_SIZE = 8

export function usePaged<T>(items: T[] | null | undefined, pageSize = PAGE_SIZE) {
  const [page, setPage] = useState(0)
  // Tolerates a missing list on purpose. A panel running an older build than
  // the API it is talking to sends a payload without fields this component
  // expects, and the wrong answer to that is a blank page with a TypeError in
  // the console. An empty list renders as an empty state, which is at least
  // true and says which section is empty.
  const list = items ?? []
  const pages = Math.max(1, Math.ceil(list.length / pageSize))

  useEffect(() => {
    if (page > pages - 1) setPage(pages - 1)
  }, [page, pages])

  return {
    page: Math.min(page, pages - 1),
    pages,
    slice: list.slice(page * pageSize, page * pageSize + pageSize),
    atStart: page === 0,
    atEnd: page >= pages - 1,
    first: list.length === 0 ? 0 : page * pageSize + 1,
    last: Math.min((page + 1) * pageSize, list.length),
    next: () => setPage((p) => Math.min(p + 1, pages - 1)),
    prev: () => setPage((p) => Math.max(p - 1, 0)),
  }
}

export default function Pager({
  page,
  pages,
  first,
  last,
  total,
  onPrev,
  onNext,
}: {
  page: number
  pages: number
  first: number
  last: number
  total: number
  onPrev: () => void
  onNext: () => void
}) {
  // Hidden rather than disabled when everything fits on one page: a lone
  // "1 / 1" is noise, and a disabled pair of arrows invites the reader to
  // wonder what they would do when the answer is nothing.
  if (pages <= 1) return null

  return (
    <div className="flex items-center justify-between gap-3 border-t border-default-100 pt-2">
      <span className="font-mono text-[10px] tabular-nums text-default-400">
        {first}–{last} of {total}
      </span>
      <div className="flex items-center gap-1">
        <button
          onClick={onPrev}
          disabled={page === 0}
          aria-label="Previous page"
          className="rounded-md border border-default-200 px-2 py-0.5 text-[11px] text-default-500 transition-colors hover:border-accent hover:text-accent disabled:pointer-events-none disabled:opacity-30"
        >
          Prev
        </button>
        <span className="px-1 font-mono text-[10px] tabular-nums text-default-400">
          {page + 1}/{pages}
        </span>
        <button
          onClick={onNext}
          disabled={page >= pages - 1}
          aria-label="Next page"
          className="rounded-md border border-default-200 px-2 py-0.5 text-[11px] text-default-500 transition-colors hover:border-accent hover:text-accent disabled:pointer-events-none disabled:opacity-30"
        >
          Next
        </button>
      </div>
    </div>
  )
}