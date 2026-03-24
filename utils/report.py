import json
import datetime


class ReportGenerator:
    def __init__(self):
        self.results = {}
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_results(self, protocol, data):
        self.results[protocol] = data

    def generate(self, output_path="reports/ghostgateway_report.html"):
        html = self._build_html()
        with open(output_path, "w") as f:
            f.write(html)
        print(f"[+] HTML Report generated: {output_path}")

    def _build_html(self):
        rows = ""
        for protocol, modules in self.results.items():
            for module, findings in modules.items():
                if isinstance(findings, list):
                    for finding in findings:
                        severity = finding.get("severity", "INFO")
                        color = {"CRITICAL": "#ff4c4c", "HIGH": "#ff8800",
                                 "MEDIUM": "#ffd700", "INFO": "#4fc3f7"}.get(severity, "#4fc3f7")
                        rows += f"""
                        <tr>
                            <td>{protocol}</td>
                            <td>{module}</td>
                            <td>{finding.get('check', '')}</td>
                            <td style="color:{color}; font-weight:bold;">{severity}</td>
                            <td>{finding.get('detail', '')}</td>
                        </tr>"""
                elif isinstance(findings, dict):
                    severity = findings.get("severity", "INFO")
                    color = {"CRITICAL": "#ff4c4c", "HIGH": "#ff8800",
                             "MEDIUM": "#ffd700", "INFO": "#4fc3f7"}.get(severity, "#4fc3f7")
                    rows += f"""
                    <tr>
                        <td>{protocol}</td>
                        <td>{module}</td>
                        <td>{findings.get('check', module)}</td>
                        <td style="color:{color}; font-weight:bold;">{severity}</td>
                        <td>{findings.get('detail', json.dumps(findings))}</td>
                    </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GhostGateway Report</title>
<style>
  body {{ background:#0d0d0d; color:#e0e0e0; font-family:'Courier New',monospace; padding:30px; }}
  h1 {{ color:#00ff88; letter-spacing:3px; }}
  h2 {{ color:#00bcd4; border-bottom:1px solid #333; padding-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
  th {{ background:#1a1a2e; color:#00ff88; padding:10px; text-align:left; }}
  td {{ padding:10px; border-bottom:1px solid #222; }}
  tr:hover {{ background:#1a1a1a; }}
  .badge {{ padding:4px 10px; border-radius:4px; font-size:12px; font-weight:bold; }}
  .footer {{ margin-top:40px; color:#555; font-size:12px; }}
  .warning {{ color:#ff4c4c; background:#1a0000; padding:10px; border-left:4px solid #ff4c4c; margin-bottom:20px; }}
</style>
</head>
<body>
<h1>&#128123; GhostGateway</h1>
<h2>Clinical IoT Gateway Attack Report</h2>
<div class="warning">
  &#9888; This report contains sensitive security findings. Handle with care. For authorized use only.
</div>
<p><strong>Generated:</strong> {self.timestamp}</p>
<table>
  <thead>
    <tr>
      <th>Protocol</th>
      <th>Module</th>
      <th>Check</th>
      <th>Severity</th>
      <th>Detail</th>
    </tr>
  </thead>
  <tbody>
    {rows if rows else '<tr><td colspan="5" style="text-align:center;color:#555;">No findings recorded.</td></tr>'}
  </tbody>
</table>
<div class="footer">
  GhostGateway v1.0.0 | Clinical IoT Gateway Attack Simulator | For Authorized Testing Only
</div>
</body>
</html>"""
