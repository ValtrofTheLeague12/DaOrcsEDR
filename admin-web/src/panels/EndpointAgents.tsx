import AgentFleet from '../components/AgentFleet'

// Its own page rather than a tab under Networking: the fleet is the answer to
// "which endpoints are reporting?", which is a question asked on its own, and
// it does not need the topology scan that page exists to run.
export default function EndpointAgents() {
  return (
    <div className="network-page">
      <header className="network-page-header">
        <div>
          <p className="eyebrow">Endpoints</p>
          <h1 className="page-title mt-1">Endpoint agents</h1>
          <p className="mt-2 max-w-2xl text-xs text-default-500">
            Live heartbeats and the newest detections from every agent this
            console watches. Agents are read-only; detections and logs stay on
            the endpoint.
          </p>
        </div>
      </header>
      <AgentFleet />
    </div>
  )
}
