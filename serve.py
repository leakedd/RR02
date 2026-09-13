#!/usr/bin/env python3
# Serveur HTTP RR02 : /radar.html (UI) et /radar.json (données live)
import http.server, socketserver, json

PORT = 8789
JSON_PATH = '/tmp/rr02_radar.json'
HTML_PATH = '/tmp/rr02_radar.html'

class H(http.server.BaseHTTPRequestHandler):
    def _send(self, data: bytes, ctype: str):
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        try:
            path = self.path.split('?', 1)[0].split('#', 1)[0]
            if path in ('/radar.json', '/data'):
                raw = open(JSON_PATH, 'rb').read().decode()
                s = raw.strip()
                # take last valid object — file might contain previous partial tail
                try:
                    d = json.loads(s)
                except json.JSONDecodeError:
                    # fall back: extract last balanced {...} starting from last {"local"
                    idx = s.rfind('{"local"')
                    d = json.loads(s[idx:]) if idx >= 0 else {'players': []}
                out = json.dumps({'players': d.get('players', []),
                                  'items': d.get('items', []),
                                  'itemsN': d.get('itemsN', len(d.get('items', []) or [])),
                                  'on': d.get('on'), 'off': d.get('off'),
                                  'count': d.get('count'), 'ts': d.get('ts'),
                                  'local': d.get('local', {})}).encode()
                self._send(out, 'application/json')
            elif path in ('/', '/radar.html'):
                self._send(open(HTML_PATH, 'rb').read(), 'text/html; charset=utf-8')
            else:
                self.send_error(404)
        except Exception as e:
            self.send_error(500, str(e))
    def log_message(self, *a): pass

socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(('127.0.0.1', PORT), H) as srv:
    print(f'serving on http://127.0.0.1:{PORT}/')
    srv.serve_forever()
