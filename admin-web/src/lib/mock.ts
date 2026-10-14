// Sample data must not be provably dead.
//
// Every panel that is still design-only holds a module-local literal like
// `{ reachable: true }`. The minifier can constant-fold `!status.reachable`
// to `false` and delete the branch entirely - and it did: the "clamd is not
// answering" alert, which is the single most important thing that panel could
// ever show an operator, was stripped from the shipped bundle.
//
// A JSON round trip makes the value opaque to the optimiser while staying
// readable, and matches where this is going anyway: every one of these becomes
// a fetch. Once a panel is real, replace mockData(MOCK) with the call and this
// stops mattering.
export function mockData<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}