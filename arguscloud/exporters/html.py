"""HTML report export."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from arguscloud.core.graph import GraphData, Edge


class HTMLExporter:
    """Export ArgusCloud findings to a standalone HTML report."""

    def __init__(self, graph: GraphData, attack_paths: List[Edge]):
        self.graph = graph
        self.attack_paths = attack_paths

    def export(self) -> str:
        """Export to HTML string."""
        return self._build_html()

    def export_to_file(self, path: str) -> None:
        """Export to an HTML file."""
        with open(path, "w") as f:
            f.write(self.export())

    def _build_html(self) -> str:
        """Build the HTML report."""
        # Count resources by type
        resource_counts: Dict[str, int] = {}
        for node in self.graph.nodes:
            resource_counts[node.type] = resource_counts.get(node.type, 0) + 1

        # Count findings by severity
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for edge in self.attack_paths:
            sev = edge.properties.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        findings_html = self._render_findings()
        resources_html = self._render_resources(resource_counts)

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArgusCloud Security Report</title>
    <style>
        :root {{
            --bg-primary: #0a0d12;
            --bg-secondary: #0f1419;
            --bg-tertiary: #151c24;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --critical: #dc2626;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #10b981;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        header {{ text-align: center; margin-bottom: 40px; }}
        h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        h1 span {{ color: var(--accent); }}
        .timestamp {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .stat {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .stat-value {{ font-size: 2rem; font-weight: 700; }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase; }}
        .stat.critical .stat-value {{ color: var(--critical); }}
        .stat.high .stat-value {{ color: var(--high); }}
        .stat.medium .stat-value {{ color: var(--medium); }}
        .stat.low .stat-value {{ color: var(--low); }}
        section {{ background: var(--bg-secondary); border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
        h2 {{ font-size: 1.25rem; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid var(--bg-tertiary); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--bg-tertiary); }}
        th {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-secondary); }}
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity.critical {{ background: rgba(220, 38, 38, 0.2); color: var(--critical); }}
        .severity.high {{ background: rgba(239, 68, 68, 0.2); color: var(--high); }}
        .severity.medium {{ background: rgba(245, 158, 11, 0.2); color: var(--medium); }}
        .severity.low {{ background: rgba(16, 185, 129, 0.2); color: var(--low); }}
        code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            background: var(--bg-tertiary);
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .resource-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 12px; }}
        .resource-item {{
            background: var(--bg-tertiary);
            padding: 16px;
            border-radius: 8px;
            text-align: center;
        }}
        .resource-count {{ font-size: 1.5rem; font-weight: 700; color: var(--accent); }}
        .resource-type {{ font-size: 0.75rem; color: var(--text-secondary); }}
        footer {{ text-align: center; margin-top: 40px; color: var(--text-secondary); font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Cloud<span>Hound</span> Security Report</h1>
            <p class="timestamp">Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </header>

        <div class="summary">
            <div class="stat">
                <div class="stat-value">{len(self.graph.nodes)}</div>
                <div class="stat-label">Resources</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(self.attack_paths)}</div>
                <div class="stat-label">Findings</div>
            </div>
            <div class="stat critical">
                <div class="stat-value">{severity_counts.get("critical", 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-value">{severity_counts.get("high", 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat medium">
                <div class="stat-value">{severity_counts.get("medium", 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-value">{severity_counts.get("low", 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <section>
            <h2>Security Findings</h2>
            {findings_html}
        </section>

        <section>
            <h2>Resource Inventory</h2>
            {resources_html}
        </section>

        <footer>
            <p>ArgusCloud - Multi-Cloud Security Graph Analytics</p>
        </footer>
    </div>
</body>
</html>'''

    def _render_findings(self) -> str:
        """Render findings table."""
        if not self.attack_paths:
            return '<p style="color: var(--text-secondary);">No security findings detected.</p>'

        rows = []
        for edge in sorted(self.attack_paths, key=lambda e: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(e.properties.get("severity", "medium"), 4)
        )):
            sev = edge.properties.get("severity", "medium")
            rows.append(f'''
                <tr>
                    <td><code>{edge.properties.get("rule", "unknown")}</code></td>
                    <td><span class="severity {sev}">{sev}</span></td>
                    <td>{edge.properties.get("description", "")}</td>
                    <td><code>{self._truncate(edge.src, 40)}</code></td>
                </tr>
            ''')

        return f'''
            <table>
                <thead>
                    <tr>
                        <th>Rule</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>Resource</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        '''

    def _render_resources(self, counts: Dict[str, int]) -> str:
        """Render resource counts grid."""
        if not counts:
            return '<p style="color: var(--text-secondary);">No resources found.</p>'

        items = []
        for rtype, count in sorted(counts.items(), key=lambda x: -x[1]):
            items.append(f'''
                <div class="resource-item">
                    <div class="resource-count">{count}</div>
                    <div class="resource-type">{rtype}</div>
                </div>
            ''')

        return f'<div class="resource-grid">{"".join(items)}</div>'

    def _truncate(self, s: str, length: int) -> str:
        """Truncate string with ellipsis."""
        return s if len(s) <= length else s[:length] + "..."
