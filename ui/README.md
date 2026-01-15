# ArgusCloud UI

ArgusCloud UI is a modern web interface for cloud security graph visualization and analysis. It provides interactive graph exploration, security finding analysis, and AWS data collection capabilities.

## Features

### Graph Visualization
- **Interactive Cytoscape.js graph** - Pan, zoom, and explore cloud resource relationships
- **Multiple layout algorithms** - Cola, Dagre, Breadthfirst, Circle, and Concentric layouts
- **Node highlighting** - Click nodes to highlight paths and connections
- **Edge filtering** - Filter by relationship types

### Security Analysis
- **Attack path visualization** - View security findings as highlighted paths
- **Severity-based filtering** - Filter by critical, high, medium, low severity
- **AWS Attack Queries** - Pre-built queries organized by category:
  - Common queries
  - Admin access paths
  - Privilege escalation
  - Credential theft
  - Public exposure
  - Cross-account access
  - Lateral movement
  - Data exfiltration

### Profile Management
- **Save/Load profiles** - Persist graph data with named profiles
- **Profile selector** - Quick switching between environments
- **Rename and delete** - Full profile lifecycle management
- **Bulk upload** - Import multiple environments via ZIP files

### Data Collection
- **AWS Credentials ingestion** - Direct credential input from web UI
- **Supported credential types**:
  - IAM user access keys (AKIA*)
  - Temporary session tokens (ASIA*)
- **Real-time progress** - Live status updates during collection
- **Secure handling** - Credentials cleared from memory after use

### Filtering and Search
- **Resource type filter** - Multi-select dropdown for node types
- **Provider filter** - Filter by cloud provider (AWS, GCP, Azure)
- **Severity filter** - Filter attack paths by severity level
- **Text search** - Search nodes by name, ID, or properties
- **Active filter bar** - Visual display of applied filters

### Export Options
- **JSON export** - Full graph data
- **SARIF export** - Security findings in SARIF format
- **HTML report** - Standalone HTML security report

### UI/UX Features
- **Dark/Light theme** - Toggle between themes
- **Resizable sidebar** - Drag to adjust sidebar width
- **Collapsible panels** - Expand/collapse filter sections
- **Status indicators** - API and Neo4j connection status
- **Responsive layout** - Adapts to screen size

## Architecture

The UI is a single-page application that communicates with the ArgusCloud API:

```
ui/
├── index.html        # Main HTML entry point
├── css/
│   └── main.css      # Styles (dark/light themes)
└── js/
    ├── app.js        # Main application logic
    ├── api.js        # API client functions
    ├── graph.js      # Cytoscape graph management
    ├── sidebar.js    # Sidebar and filter logic
    └── utils.js      # Utility functions
```

## API Endpoints Used

The UI communicates with these ArgusCloud API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with Neo4j status |
| `/graph` | GET | Fetch nodes and edges |
| `/attackpaths` | GET | Fetch security findings |
| `/profiles` | GET/POST | List and create profiles |
| `/profiles/<name>` | GET/DELETE | Get or delete specific profile |
| `/profiles/<name>/rename` | POST | Rename a profile |
| `/collect/aws` | POST | Start AWS collection |
| `/collect/<job_id>` | GET | Check collection status |
| `/upload` | POST | Upload JSONL/ZIP files |
| `/export/<format>` | GET | Export in json/sarif/html |

## Development

### Prerequisites
- ArgusCloud API server running (default: http://localhost:5000)
- Neo4j database connection

### Running Locally

1. Start the API server:
   ```bash
   arguscloud serve --no-auth
   ```

2. Serve the UI (any static file server):
   ```bash
   cd ui && python -m http.server 8080
   ```

3. Open http://localhost:8080 in your browser

### Configuration

The UI connects to the API at the same origin by default. For development with a separate API server, update the API base URL in `js/api.js`.

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Dependencies

External libraries loaded from CDN:
- **Cytoscape.js 3.28.1** - Graph visualization
- **JSZip 3.10.1** - ZIP file handling
- **Inter & JetBrains Mono fonts** - Typography
