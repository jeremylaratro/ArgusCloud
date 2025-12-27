# awshound UI scaffold

Planned features:
- Load `nodes.jsonl` and `edges.jsonl` bundles for client-side graph rendering.
- Provide canned BloodHound-like queries: path to admin, reachable resources, exposure maps.
- Views: Org tree, trust graph (assume-role, SCPs), detection posture map, network exposure.

MVP approach:
- Static SPA (e.g., React/TS or Svelte) that ingests JSONL via file upload and renders with a graph library (Cytoscape/Visx).
- Keep offline-capable; no backend dependency.
- Ship minimal loader component that parses JSONL into in-memory graph and applies query filters.

Next steps:
- Scaffold UI project (tooling TBD) and implement file-upload + basic graph render of Org/Account nodes.
