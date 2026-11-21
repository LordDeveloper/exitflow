import http.server
import socketserver
import ssl
import urllib.request
import urllib.error
import os
import webbrowser
import threading

START_PORT = 8080
HTML_CANDIDATES = [
    "index.html",
    "mullvad-mikrotik-dashboard-v3.html",
    "mullvad-mikrotik-dashboard-v2.html",
    "mullvad-mikrotik-dashboard.html",
]

# Absolute REST URLs (http://router/rest/...) are rewritten to this proxy.
# Scheme is kept as a path prefix so HTTPS routers are not downgraded.
# Legacy /proxy/<host>/rest/... still defaults to HTTP.
PROXY_INJECT_SCRIPT = """
<script>
(function() {
    const origFetch = window.fetch;
    window.fetch = function(resource, init) {
        if (typeof resource === 'string') {
            const m = resource.match(/^(https?):\\/\\/([^/?#]+)(\\/rest(?:\\/|\\?|#|$).*)$/i);
            if (m) {
                resource = window.location.origin + '/proxy/' + m[1].toLowerCase() + '/' + m[2] + m[3];
            }
        }
        return origFetch.call(this, resource, init);
    };
})();
</script>
"""

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html_file = next((f for f in HTML_CANDIDATES if os.path.exists(f)), None)
            if not html_file:
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                msg = "<h3>فایل HTML داشبورد پیدا نشد!</h3><p>فایل index.html را کنار index.py قرار دهید.</p>"
                self.wfile.write(msg.encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            with open(html_file, "rb") as f:
                content = f.read().decode("utf-8")
                if "<head>" in content:
                    content = content.replace("<head>", "<head>" + PROXY_INJECT_SCRIPT, 1)
                else:
                    content = PROXY_INJECT_SCRIPT + content
                self.wfile.write(content.encode("utf-8"))
        elif self.path.startswith("/proxy/"):
            self.handle_proxy("GET")
        elif self.path.split("?", 1)[0].startswith("/fonts/"):
            self.serve_font()
        else:
            self.send_error(404)

    def serve_font(self):
        name = os.path.basename(self.path.split("?", 1)[0])
        if not name.endswith(".woff2"):
            self.send_error(404)
            return
        root = os.path.dirname(os.path.abspath(__file__))
        full = os.path.join(root, "fonts", name)
        if not os.path.isfile(full):
            self.send_error(404)
            return
        with open(full, "rb") as handle:
            data = handle.read()
        self.send_response(200)
        self.send_header("Content-Type", "font/woff2")
        self.send_header("Cache-Control", "public, max-age=604800")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self): self.handle_proxy("POST")
    def do_PUT(self): self.handle_proxy("PUT")
    def do_PATCH(self): self.handle_proxy("PATCH")
    def do_DELETE(self): self.handle_proxy("DELETE")

    def handle_proxy(self, method):
        raw = self.path[len("/proxy/"):]
        ssl_context = None
        if raw.startswith("https/"):
            target_url = "https://" + raw[len("https/"):]
            # RouterOS www-ssl certificates are commonly self-signed.
            ssl_context = ssl._create_unverified_context()
        elif raw.startswith("http/"):
            target_url = "http://" + raw[len("http/"):]
        else:
            target_url = "http://" + raw
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else None

        req = urllib.request.Request(target_url, data=body, method=method)
        if "Authorization" in self.headers:
            req.add_header("Authorization", self.headers["Authorization"])
        if "Content-Type" in self.headers:
            req.add_header("Content-Type", self.headers["Content-Type"])

        # Bypass a system proxy (V2Ray and similar) and talk to the LAN router directly.
        handlers = [urllib.request.ProxyHandler({})]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        opener = urllib.request.build_opener(*handlers)

        try:
            with opener.open(req, timeout=15) as resp:
                resp_data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(resp_data)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f"Router Connection Error: {e}".encode("utf-8"))

def run():
    port = START_PORT
    server = None
    while port < START_PORT + 20:
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), ProxyHandler)
            break
        except OSError:
            port += 1

    if not server:
        print("Could not bind to any port.")
        return

    url = f"http://127.0.0.1:{port}"
    print(f"Server is running at {url}")
    print("Press Ctrl+C to stop.")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    server.serve_forever()

if __name__ == "__main__":
    run()
