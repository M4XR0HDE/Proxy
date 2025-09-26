import http.server
import socketserver
import urllib.request
import socket
import os
import json
import datetime
import select
import threading
import time


# Load whitelist from JSON file
def load_whitelist(path='whitelist.json'):
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        try:
            domains = json.load(f)
            return set(domains)
        except Exception:
            return set()

def is_whitelisted_host(host):
    WHITELIST_PATH = os.path.join(os.path.dirname(__file__), 'whitelist.json')
    whitelist = load_whitelist(WHITELIST_PATH)
    print(f"[DEBUG] Checking host: {host}")
    print(f"[DEBUG] Current whitelist: {whitelist}")
    for domain in whitelist:
        if host == domain or host.endswith('.' + domain):
            print(f"[DEBUG] Host {host} is whitelisted by domain {domain}")
            return True
    print(f"[DEBUG] Host {host} is NOT whitelisted")
    return False

class ProxyHandler(http.server.BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        if self.path.startswith('/request_whitelist'):
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith('/request_whitelist'):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data)
                domain = data.get('domain', '').strip()
                description = data.get('description', '').strip()
                if domain:
                    # Create domain-specific folder
                    domain_folder = os.path.join(os.path.dirname(__file__), 'whitelist_requests', domain.replace('.', '_'))
                    os.makedirs(domain_folder, exist_ok=True)
                    # Create Python file to add domain
                    py_path = os.path.join(domain_folder, f'add_{domain.replace(".", "_")}.py')
                    with open(py_path, 'w') as pyf:
                        pyf.write(
                            "import sys\n"
                            "import os\n"
                            "sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))\n"
                            "from whitelist_manager import add_to_whitelist\n"
                            f"add_to_whitelist('{domain}')\n"
                        )
                    # Create text file with description
                    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    txt_path = os.path.join(domain_folder, f'{domain}_{ts}.txt')
                    with open(txt_path, 'w') as txtf:
                        txtf.write(f"Domain: {domain}\nDescription: {description}\n")
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(b'OK')
                    return
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f'Error: {e}'.encode())
                return
        elif self.path.startswith('/blocked.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            host = self.headers.get('Host', 'unknown')
            try:
                with open(os.path.join(os.path.dirname(__file__), 'blocked.html')) as f:
                    html = f.read().replace('{website}', host)
                self.wfile.write(html.encode())
            except Exception:
                self.wfile.write(b'The site is blocked by the proxy.')
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        host = self.headers.get('Host')
        print(f"[GET] Host: {host}, Path: {self.path}")
        if not host or not is_whitelisted_host(host):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            try:
                with open(os.path.join(os.path.dirname(__file__), 'blocked.html')) as f:
                    html = f.read().replace('{website}', host or 'unknown')
                self.wfile.write(html.encode())
            except Exception:
                self.wfile.write(b'The site is blocked by the proxy.')
            return
        url = f'http://{host}{self.path}'
        try:
            req_headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req) as response:
                self.send_response(response.status)
                for header, value in response.getheaders():
                    self.send_header(header, value)
                self.end_headers()
                self.wfile.write(response.read())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Error: {e}'.encode())

    def do_CONNECT(self):
        host, _, port = self.path.partition(':')
        port = int(port) if port else 443
        print(f"[CONNECT] Host: {host}, Port: {port}")
        if not is_whitelisted_host(host):
                # Log blocked HTTPS domain
                log_folder = os.path.join(os.path.dirname(__file__), 'https_requests')
                os.makedirs(log_folder, exist_ok=True)
                log_path = os.path.join(log_folder, 'blocked_https.json')
                try:
                    if os.path.exists(log_path):
                        with open(log_path, 'r') as f:
                            blocked = json.load(f)
                    else:
                        blocked = []
                except Exception:
                    blocked = []
                entry = {
                    'domain': host,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                blocked.append(entry)
                try:
                    with open(log_path, 'w') as f:
                        json.dump(blocked, f, indent=2)
                except Exception as e:
                    print(f"Error logging blocked HTTPS domain: {e}")
                # Log blocked HTTPS domain (simple, only once)
                simple_log_path = os.path.join(log_folder, 'simple_blocked_https.json')
                try:
                    if os.path.exists(simple_log_path):
                        with open(simple_log_path, 'r') as f:
                            simple_blocked = set(json.load(f))
                    else:
                        simple_blocked = set()
                except Exception:
                    simple_blocked = set()
                if host not in simple_blocked:
                    simple_blocked.add(host)
                    try:
                        with open(simple_log_path, 'w') as f:
                            json.dump(list(simple_blocked), f, indent=2)
                    except Exception as e:
                        print(f"Error logging simple blocked HTTPS domain: {e}")
                # For HTTP, send a simple HTML page instead of tunneling
                self.send_response(200)
                self.end_headers()
                try:
                    with open(os.path.join(os.path.dirname(__file__), 'blocked.html')) as f:
                        html = f.read().replace('{website}', host)
                    self.wfile.write(html.encode())
                except Exception:
                    self.wfile.write(b'The site is blocked by the proxy.')
                return
        try:
            remote = socket.create_connection((host, port))
            self.send_response(200, 'Connection Established')
            self.end_headers()
            sockets = [self.connection, remote]
            while True:
                try:
                    rlist, _, _ = select.select(sockets, [], [], 1)
                except Exception:
                    break
                if self.connection in rlist:
                    try:
                        data = self.connection.recv(4096)
                    except (ConnectionResetError, BrokenPipeError):
                        break
                    if not data:
                        break
                    try:
                        remote.sendall(data)
                    except (ConnectionResetError, BrokenPipeError):
                        break
                if remote in rlist:
                    try:
                        data = remote.recv(4096)
                    except (ConnectionResetError, BrokenPipeError):
                        break
                    if not data:
                        break
                    try:
                        self.connection.sendall(data)
                    except (ConnectionResetError, BrokenPipeError):
                        break
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Error: {e}'.encode())

    def do_HEAD(self):
        # Serve blocked.html for HEAD requests to /blocked.html
        if self.path.startswith('/blocked.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def wait_for_port_to_be_free(port, host='localhost', timeout=50):
    start = time.time()
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, port))
            s.close()
            print('port open again')
            break
        except OSError:
            s.close()
        if time.time() - start > timeout:
            print('Warning: port still not free after timeout.')
            break
        time.sleep(1)
        
def input_listener(httpd):
    while True:
        cmd = input().strip().lower()
        if cmd in ('stop', 'exit'):
            print('Stopping proxy...')
            httpd.shutdown()
            httpd.server_close()
            break

class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    # Added: Make worker threads daemon for fast shutdown
    daemon_threads = True

if __name__ == '__main__':
    PORT = 8080
    try:
        httpd = ThreadedTCPServer(("", PORT), ProxyHandler)
        print(f"Serving proxy on port {PORT}")
        listener_thread = threading.Thread(target=input_listener, args=(httpd,), daemon=True)
        listener_thread.start()
        httpd.serve_forever()
        # Wait until port is open again after server is closed
        port = httpd.server_address[1]
        wait_for_port_to_be_free(port)
    except KeyboardInterrupt:
        print('Proxy interrupted by user, shutting down.')
    