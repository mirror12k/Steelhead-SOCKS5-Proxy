# SOCKS Proxy Server Code
import socket
import socketserver
import threading
import struct
import ssl
import select
import traceback
import time

from urllib.parse import urlparse
import http.client
from io import BytesIO
from dataclasses import dataclass, field
from typing import Dict



@dataclass
class DomainConnectionRouter:
    domain_map: Dict[str, str] = field(default_factory=dict)
    def add_route(self, domain: str, destination: str):
        self.domain_map[domain] = destination
    def get_destination(self, domain: str) -> str:
        return self.domain_map.get(domain, None)

@dataclass
class ProxyingContext:
    client_socket: socket.socket
    remote_socket: socket.socket
    address: str
    port: str
    is_ssl: bool

@dataclass
class ParsedHTTPRequest:
    method: str
    path: str
    version: str
    headers: http.client.HTTPMessage
    body: bytes

    @staticmethod
    def parse_request(request: bytes):
        parts = request.split(b"\r\n\r\n", 1)
        request_line, request_headers = parts[0].split(b'\r\n', 1)
        method, path, version = request_line.decode('iso-8859-1').split(' ')
        header_io = BytesIO(request_headers)  # Exclude the request line
        parsed_headers = http.client.parse_headers(header_io)
        body = parts[1] if len(parts) > 1 else b""
        return ParsedHTTPRequest(method, path, version, parsed_headers, body)

    def convert_to_bytes(self) -> bytes:
        request_line = f"{self.method} {self.path} {self.version}\r\n".encode('iso-8859-1')
        headers = b"".join(f"{k}: {v}\r\n".encode('iso-8859-1') for k, v in self.headers.items())
        return request_line + headers + b"\r\n" + self.body

@dataclass
class ParsedHTTPResponse:
    version: str
    status: int
    reason: str
    headers: http.client.HTTPMessage
    body: bytes

    @staticmethod
    def parse_response(response: bytes):
        # Split response into headers and body
        parts = response.split(b"\r\n\r\n", 1)
        header_io = BytesIO(parts[0])
        status_line = header_io.readline().decode('iso-8859-1').strip()
        version, status, reason = status_line.split(' ', 2)
        parsed_headers = http.client.parse_headers(header_io)
        body = parts[1] if len(parts) > 1 else b""

        return ParsedHTTPResponse(version, int(status), reason, parsed_headers, body)

    def convert_to_bytes(self) -> bytes:
        status_line = f"{self.version} {self.status} {self.reason}\r\n".encode('iso-8859-1')
        headers = b"".join(f"{k}: {v}\r\n".encode('iso-8859-1') for k, v in self.headers.items())
        if 'transfer-encoding' in self.headers and self.headers['transfer-encoding'] == 'chunked':
            # Convert body to chunked encoding
            chunked_body = f"{len(self.body):X}\r\n".encode('iso-8859-1') + self.body + b"\r\n"
            chunked_body += b"0\r\n\r\n"  # End of chunked body
            return status_line + headers + b"\r\n" + chunked_body
        else:
            # Non-chunked response
            return status_line + headers + b"\r\n" + self.body



class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class BaseSOCKSRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server, router: DomainConnectionRouter = None):
        self.router = router
        super().__init__(request, client_address, server)

    def handle(self):
        socks_request = self.handle_socks_handshake()
        if socks_request is None:
            self.request.close()
            return

        address_type, address, port = socks_request
        self.handle_socks_connection_request(address_type, address, port)

    def handle_socks_handshake(self):
        # Step 1: Greeting and Authentication
        greeting = self.request.recv(2)

        # Verify that the greeting is correctly formatted
        if len(greeting) != 2 or greeting[0] != 0x05:
            return

        auth_methods = self.request.recv(greeting[1])
        self.request.sendall(b'\x05\x00')  # No authentication required

        # Step 2: Request Parsing
        socks5_request = self.request.recv(4)
        if len(socks5_request) != 4:
            return
        version, cmd, _, address_type = struct.unpack('!BBBB', socks5_request)

        # Check the version and cmd
        if version != 0x05:
            return
        if cmd != 0x01:
            return

        # handle different address types
        if address_type == 1: # IPv4
            address = socket.inet_ntoa(self.request.recv(4))
        elif address_type == 3: # Domain name
            domain_length = ord(self.request.recv(1))
            address = self.request.recv(domain_length).decode("utf-8")
        elif address_type == 4: # IPv6
            address = socket.inet_ntop(socket.AF_INET6, self.request.recv(16))
        else:
            return

        port = struct.unpack('!H', self.request.recv(2))[0]

        return address_type, address, port

    def handle_socks_connection_request(self, address_type, address, port):
        # Step 3: Connect to the Destination
        self.remote = None
        try:
            self.remote = self.route_to_destination(address, port)

            # Send a response to client indicating a succeeded connection
            if address_type == 3:
                self.request.sendall(struct.pack('!BBBBBBB', 5, 0, 0, address_type, 0, 0, 0))
            else:
                self.request.sendall(struct.pack('!BBBBIH', 5, 0, 0, address_type, 0, 0))

            self.proxying_context = ProxyingContext(self.request, self.remote, address, port, False)

            # Step 4: Relay Data
            self.relay_data()

        except (socket.gaierror, socket.error) as e:
            # Handle name resolution or connection failure
            print(f"Socket error: {e}")
            # Send a connection failure response to the client
            self.request.sendall(struct.pack('!BBBBIH', 5, 4, 0, address_type, 0, 0))
        except Exception as e:
            print(f"handler exception: {e}")
            print(''.join(traceback.format_exception(None, e, e.__traceback__)))
        finally:
            # Close both sockets in the finally block
            if self.request:
                self.request.close()
            if self.remote:
                self.remote.close()


    def route_to_destination(self, address, port):
        if self.router:
            # Use the router to get the destination
            destination = self.router.get_destination(address)
            if destination:
                # Parse the new destination and connect
                parsed_url = urlparse(destination)
                return self.connect_to_destination(parsed_url.hostname, parsed_url.port or port)

        # Fall back to the original address and port
        return self.connect_to_destination(address, port)

    def connect_to_destination(self, address, port):
        remote = None
        try:
            # Determine if the address is IPv4 or IPv6
            addr_info = socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            af, socktype, proto, canonname, sa = addr_info[0]
            # Create the appropriate socket type
            remote = socket.socket(af, socktype, proto)
            # connect
            remote.connect(sa)
        except (socket.gaierror, socket.error) as e:
            # on socket error, we close the socket before re-raising the error to prevent clean-up issues
            if remote:
                remote.close()
            raise e

        return remote

    def send_to_client(self, msg):
        self.client_write_buffer += msg
    def send_to_remote(self, msg):
        self.remote_write_buffer += msg

    def relay_data(self):
        self.proxying_context.client_socket.setblocking(0)
        self.proxying_context.remote_socket.setblocking(0)

        self.client_write_buffer = b""
        self.remote_write_buffer = b""

        sockets = [self.proxying_context.client_socket, self.proxying_context.remote_socket]

        while True:
            read_sockets, write_sockets, exception_sockets = select.select(
                    sockets, 
                    [ sock for sock in sockets if len(self.get_write_buffer(sock)) > 0 ], 
                    sockets, 
                    1)

            for sock in write_sockets:
                self.write_to_socket(sock)

            for sock in read_sockets:
                try:
                    # print(f'sock: {sock}')
                    data = sock.recv(4096 * 256)
                    if not data:
                        return  # End the relay when no data is received

                    while data:
                        # print(f'-? {data}')
                        if sock is self.proxying_context.client_socket:
                            self.on_client_message(data)
                        else:
                            self.on_remote_message(data)
                        data = sock.recv(4096 * 256)

                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLWantWriteError:
                    pass
                except BlockingIOError:
                    pass

            for sock in exception_sockets:
                return # end relay when a socket is in an exception state

            if not read_sockets and not write_sockets and not exception_sockets:
                time.sleep(0.1)

    def get_write_buffer(self, sock):
        if sock is self.proxying_context.client_socket:
            return self.client_write_buffer
        elif sock is self.proxying_context.remote_socket:
            return self.remote_write_buffer

    def write_to_socket(self, sock):
        try:
            buffer = self.get_write_buffer(sock)
            bytes_written = sock.send(buffer)
            if sock is self.proxying_context.client_socket:
                self.client_write_buffer = self.client_write_buffer[bytes_written:]
            elif sock is self.proxying_context.remote_socket:
                self.remote_write_buffer = self.remote_write_buffer[bytes_written:]
        except BlockingIOError:
            # Resource temporarily unavailable; wait and retry
            pass
        except socket.error as e:
            if e.errno == socket.errno.EAGAIN:
                # Resource temporarily unavailable; wait and retry
                pass
            else:
                raise e

    def on_client_message(self, msg):
        # Send the message received from the client to the remote server
        self.send_to_remote(msg)

    def on_remote_message(self, msg):
        # Send the message received from the remote server to the client
        self.send_to_client(msg)

class InterceptingSOCKSRequestHandler(BaseSOCKSRequestHandler):
    def handle_socks_connection_request(self, address_type, address, port):
        # Step 3: Connect to the Destination
        self.remote = None
        try:
            self.remote = self.route_to_destination(address, port)

            # Send a response to client indicating a succeeded connection
            if address_type == 3:
                self.request.sendall(struct.pack('!BBBBBBB', 5, 0, 0, address_type, 0, 0, 0))
            else:
                self.request.sendall(struct.pack('!BBBBIH', 5, 0, 0, address_type, 0, 0))

            # Peek the first few bytes to check for SSL/TLS header
            first_bytes = self.request.recv(3, socket.MSG_PEEK)

            # Check if the header matches the start of an SSL/TLS handshake
            is_ssl = len(first_bytes) == 3 and first_bytes[0] == 0x16 and (first_bytes[1] == 0x03)
            if is_ssl:
                # Upgrade both sockets to SSL/TLS
                self.request = self.upgrade_client_socket_to_ssl(self.request)
                self.remote = self.upgrade_remote_socket_to_ssl(self.remote)

            self.proxying_context = ProxyingContext(self.request, self.remote, address, port, is_ssl)

            # Step 4: Relay Data
            self.relay_data()

        except (socket.gaierror, socket.error) as e:
            # Handle name resolution or connection failure
            print(f"Socket error: {e}")
            # Send a connection failure response to the client
            self.request.sendall(struct.pack('!BBBBIH', 5, 4, 0, address_type, 0, 0))
        except Exception as e:
            print(f"handler exception: {e}")
            print(''.join(traceback.format_exception(None, e, e.__traceback__)))
        finally:
            # Close both sockets in the finally block
            if self.request:
                self.request.close()
            if self.remote:
                self.remote.close()

    def upgrade_client_socket_to_ssl(self, client_socket):
        client_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        client_ssl_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
        return client_ssl_context.wrap_socket(client_socket, server_side=True)
    def upgrade_remote_socket_to_ssl(self, remote_socket):
        ssl_context = ssl._create_unverified_context()
        return ssl_context.wrap_socket(remote_socket)

class HTTPInterceptingSOCKSRequestHandler(InterceptingSOCKSRequestHandler):
    def on_client_message(self, msg):
        if not hasattr(self, 'client_buffer'):
            self.reset_client_state()

        self.client_buffer += msg

        if not self.headers_received and b"\r\n\r\n" in self.client_buffer:
            self.headers_received = True
            self.proxying_context.last_http_request = self.parse_http_headers(self.client_buffer)

        if self.headers_received and len(self.client_buffer) >= self.expected_content_length:
            self.proxying_context.last_http_request.body = self.client_buffer
            self.on_http_request(self.proxying_context.last_http_request)
            self.reset_client_state()

    def reset_client_state(self):
        self.client_buffer = b""
        self.headers_received = False
        self.expected_content_length = 0

    def parse_http_headers(self, request):
        request_header, self.client_buffer = request.split(b"\r\n\r\n", 1)
        parsed_request = ParsedHTTPRequest.parse_request(request_header)
        if 'content-length' in parsed_request.headers:
            self.expected_content_length = int(parsed_request.headers['content-length'])
        else:
            self.expected_content_length = 0
        return parsed_request

    def reset_remote_state(self):
        self.remote_buffer = b""
        self.response_headers_received = False
        self.chunked_transfer = False
        self.chunk_size_remaining = 0
        self.last_chunk_received = False
        self.chunked_body = b""

    def on_remote_message(self, msg):
        if not hasattr(self, 'remote_buffer'):
            self.reset_remote_state()

        self.remote_buffer += msg

        if not self.response_headers_received:
            if b"\r\n\r\n" in self.remote_buffer:
                self.response_headers_received = True
                self.proxying_context.last_http_response = self.parse_http_response_headers(self.remote_buffer)

        if self.response_headers_received:
            if self.chunked_transfer:
                self.process_chunked_response()
            elif len(self.remote_buffer) >= self.chunk_size_remaining:
                self.proxying_context.last_http_response.body = self.remote_buffer[:self.chunk_size_remaining]
                self.on_http_response(self.proxying_context.last_http_response)
                self.reset_remote_state()

    def parse_http_response_headers(self, response):
        request_header, self.remote_buffer = response.split(b"\r\n\r\n", 1)
        parsed_response = ParsedHTTPResponse.parse_response(request_header)
        # print(f"got response: {parsed_response}")
        if self.proxying_context.last_http_request.method != 'HEAD':
            if 'transfer-encoding' in parsed_response.headers and parsed_response.headers['transfer-encoding'] == 'chunked':
                self.chunked_transfer = True
            elif 'content-length' in parsed_response.headers:
                self.chunk_size_remaining = int(parsed_response.headers['content-length'])
            else:
                self.chunk_size_remaining = 0
        else:
            # ignore any body if it is a HEAD request
            self.chunk_size_remaining = 0
        return parsed_response

    def process_chunked_response(self):
        while self.can_process_next_chunk():
            self.process_next_chunk()

        if self.last_chunk_received:
            self.finalize_chunked_response()

    def can_process_next_chunk(self):
        return self.remote_buffer and not self.last_chunk_received and (self.chunk_size_remaining == 0 or len(self.remote_buffer) >= self.chunk_size_remaining + 2)

    def process_next_chunk(self):
        if self.chunk_size_remaining == 0:
            self.parse_next_chunk_size()
        if self.chunk_size_remaining > 0 and len(self.remote_buffer) >= self.chunk_size_remaining + 2:
            self.accumulate_chunk()

    def parse_next_chunk_size(self):
        size_line, self.remote_buffer = self.remote_buffer.split(b"\r\n", 1)
        self.chunk_size_remaining = int(size_line, 16)
        if self.chunk_size_remaining == 0:
            self.last_chunk_received = True

    def accumulate_chunk(self):
        total_chunk_size = self.chunk_size_remaining + len(b'\r\n')
        if len(self.remote_buffer) >= total_chunk_size:
            chunk = self.remote_buffer[:self.chunk_size_remaining]
            self.remote_buffer = self.remote_buffer[total_chunk_size:]
            self.chunked_body += chunk
            self.chunk_size_remaining = 0

    def finalize_chunked_response(self):
        self.proxying_context.last_http_response.body = self.chunked_body
        self.on_http_response(self.proxying_context.last_http_response)
        self.reset_remote_state()

    def on_http_request(self, request: ParsedHTTPRequest):
        request_bytes = request.convert_to_bytes()
        self.send_to_remote(request_bytes)

    def on_http_response(self, response):
        self.log_request_response(self.proxying_context, response)
        response_bytes = response.convert_to_bytes()
        self.send_to_client(response_bytes)

    @staticmethod
    def log_request_response(proxying_context, response):
        request = proxying_context.last_http_request
        print(f'{request.method} {"https:" if proxying_context.is_ssl else "http:"}//{proxying_context.address}:{proxying_context.port}{request.path} -> {response.status} {response.reason}')


