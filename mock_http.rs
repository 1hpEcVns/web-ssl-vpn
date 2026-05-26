use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn main() {
    let servers = [
        (3001, "Internal Wiki", "<h2>Company Documentation</h2><p>Knowledge base &amp; API docs.</p><ul><li>Getting Started Guide</li><li>API Reference</li><li>Coding Standards</li><li>Architecture Overview</li></ul>"),
        (5001, "HR Portal", "<h2>Human Resources</h2><ul><li>Payslip Archive</li><li>Leave Request Form</li><li>Performance Review</li><li>Employee Directory</li></ul>"),
        (8081, "Mail Server", "<h2>Roundcube Webmail</h2><table style=\"width:100%;border-collapse:collapse\"><tr><td><b>Alice</b></td><td>Meeting tomorrow</td><td>10:30</td></tr><tr><td><b>Bob</b></td><td>Project update</td><td>09:15</td></tr><tr><td><b>HR</b></td><td>Benefits enrollment</td><td>Yesterday</td></tr></table>"),
        (9001, "File Repository", "<h2>Internal File Sharing</h2><ul><li><b>reports/</b> &mdash; monthly financial reports</li><li><b>releases/</b> &mdash; software packages</li><li><b>templates/</b> &mdash; document templates</li><li><b>assets/</b> &mdash; brand media</li></ul><p>Total: 438 files</p>"),
    ];

    let mut handles = vec![];
    for (port, title, body) in servers {
        let title = title.to_string();
        let body = body.to_string();
        let h = thread::spawn(move || {
            let addr = format!("127.0.0.1:{}", port);
            let listener = match TcpListener::bind(&addr) {
                Ok(l) => l,
                Err(e) => { eprintln!("[mock] {} (skipping, port in use)", e); return; }
            };
            println!("[mock] http://{}  {:20}", addr, title);
            for stream in listener.incoming() {
                if let Ok(mut stream) = stream {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let css = "body{font-family:-apple-system,sans-serif;background:#f5f5f5;padding:40px}.container{max-width:700px;margin:0 auto;background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}h1{color:#333;border-bottom:2px solid #1976d2;padding-bottom:8px}ul{padding-left:20px;line-height:1.8}td{padding:6px 12px;border-bottom:1px solid #eee}";
                    let html = format!("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{title}</title><style>{css}</style></head><body><div class=\"container\"><h1>{title}</h1>{body}<div style=\"background:#e8f5e9;color:#2e7d32;padding:12px;border-radius:4px;margin-top:20px\">&#x2705; Authorized | VPN Gateway</div></div></body></html>");
                    let resp = format!("HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", html.len(), html);
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });
        handles.push(h);
    }
    for h in handles {
        let _ = h.join();
    }
}
