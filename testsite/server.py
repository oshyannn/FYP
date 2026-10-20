"""Tiny local server for the download-guard tests:   python server.py   then open http://localhost:8000/
Serves harmless files; program-type names are sent as forced downloads (Content-Disposition: attachment)."""
import http.server, os, time

PROGRAM = (".exe", ".msi", ".bat", ".js", ".sh", ".apk")
ROOT = os.path.dirname(os.path.abspath(__file__))


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def do_GET(self):
        if self.path.startswith("/slow/"):          # pretend the network/server is slow: wait 6 s, then serve the file
            time.sleep(6)
            self.path = "/files/" + self.path[len("/slow/"):]
        super().do_GET()

    def end_headers(self):
        if self.path.split("?")[0].lower().endswith(PROGRAM):
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", "attachment")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    # Threaded on purpose: a single-threaded server can sit waiting on an idle browser connection, and then Ctrl+C
    # is not noticed on Windows until the browser sends something.
    with http.server.ThreadingHTTPServer(("127.0.0.1", 8000), H) as s:
        s.daemon_threads = True
        print("Test site: http://localhost:8000/   (Ctrl+C to stop)")
        try:
            s.serve_forever(poll_interval=0.3)
        except KeyboardInterrupt:
            print("stopped")
