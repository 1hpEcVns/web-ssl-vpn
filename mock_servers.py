#!/usr/bin/env python3
"""Mock internal web servers for Web SSL VPN demo.
Ports: wiki=3001  hr=5001  mail=8081  files=9001
"""

import http.server
import sys
import os

CONTENT = {
    3001: {
        "title": "Internal Wiki",
        "body": "<h2>Company Documentation</h2><p>Knowledge base &amp; API docs.</p><ul><li>Getting Started Guide</li><li>API Reference</li><li>Coding Standards</li><li>Architecture Overview</li></ul>",
    },
    8081: {
        "title": "Mail Server",
        "body": '<h2>Roundcube Webmail</h2><div style="border:1px solid #ccc;padding:12px"><table style="width:100%"><tr><td><b>Alice</b></td><td>Meeting tomorrow</td><td>10:30</td></tr><tr><td><b>Bob</b></td><td>Project update</td><td>09:15</td></tr><tr><td><b>HR Dept</b></td><td>Benefits enrollment</td><td>Yesterday</td></tr></table></div>',
    },
    9001: {
        "title": "File Repository",
        "body": "<h2>Internal File Sharing</h2><ul><li><b>reports/</b> — monthly financial reports</li><li><b>releases/</b> — software packages</li><li><b>templates/</b> — document templates</li><li><b>assets/</b> — brand media</li></ul><p>Total: 438 files</p>",
    },
    5001: {
        "title": "HR Portal",
        "body": '<h2>Human Resources</h2><div style="border:1px solid #ccc;padding:12px"><ul><li>Payslip Archive</li><li>Leave Request Form</li><li>Performance Review</li><li>Employee Directory</li></ul></div>',
    },
}

CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#f5f5f5;padding:40px}
.container{max-width:700px;margin:0 auto;background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}
h1{color:#333;border-bottom:2px solid #1976d2;padding-bottom:8px;margin-bottom:20px}
ul{padding-left:20px;line-height:1.8}
table{border-collapse:collapse}
td{padding:6px 12px;border-bottom:1px solid #eee}
.auth{background:#e8f5e9;color:#2e7d32;padding:12px;border-radius:4px;margin-top:20px;font-size:14px}
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_port
        c = CONTENT.get(port, {"title": "Unknown", "body": "<p>No content.</p>"})
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{c['title']}</title><style>{CSS}</style></head><body><div class="container"><h1>{c['title']}</h1>{c['body']}<div class="auth">&#x2705; Authorized | VPN Gateway</div></div></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, fmt, *args):
        print(f"[mock:{self.server.server_port}] {args[0]}")


if __name__ == "__main__":
    ports = [3001, 5001, 8081, 9001]
    for port in ports:
        pid = os.fork()
        if pid == 0:
            srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
            print(f"[mock] {CONTENT[port]['title']:20s} -> http://127.0.0.1:{port}")
            srv.serve_forever()
    try:
        os.wait()
    except KeyboardInterrupt:
        pass
