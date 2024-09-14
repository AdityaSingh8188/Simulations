# firewall_server.py

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse

host = "localhost"
port = 8000

#########
# Handle the response here 
def block_request(self):
    self.send_response(403)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request blocked"}')
    print("Blocking request")

def handle_request(self):
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"message": "Request allowed"}')

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_request(self)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        parsed_data = urlparse.parse_qs(post_data.decode('utf-8'))

        # Malicious headers to block
        malicious_headers = {
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Check for the specific malicious pattern in the payload
        if any("class.module.classLoader.resources.context.parent.pipeline.first" in key for key in parsed_data):
            block_request(self)
        # Check for the specific malicious headers
        elif all(self.headers.get(key) == value for key, value in malicious_headers.items()):
            block_request(self)
        else:
            handle_request(self)

if __name__ == "__main__":        
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)
