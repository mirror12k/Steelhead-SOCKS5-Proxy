# Steelhead SOCKS5 Proxy
Steelhead is an intercepting SOCKS5 proxy. It is pure python with no external dependencies.

## Features:

- SOCKS5 proxying.
- SSL-stripping.
- HTTP request interception.
- Programmable routing.

## Usage:
```py
import threading
import requests
from steelhead_socks_proxy import ThreadedTCPServer, HTTPInterceptingSOCKSRequestHandler

# create our proxy server
proxy_server = ThreadedTCPServer(('localhost', 8080), HTTPInterceptingSOCKSRequestHandler)
# start as a daemon thread
server_thread = threading.Thread(target=proxy_server.serve_forever)
server_thread.daemon = True
server_thread.start()
print(f'server thread started: {server_thread}')

# specify where to find our proxy
proxy_config = {'https': f'socks5h://localhost:8080', 'http': f'socks5h://localhost:8080'}
# make an https request to example.org that will be intercepted by our socks proxy
response = requests.get('https://example.org/', proxies=proxy_config, verify=False)
print(f'got response: {response}')
```

