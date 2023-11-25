#!/usr/bin/env python3
import threading
import unittest
import requests
import random
import time
import json
import socket
import http.server
import socketserver
import struct
import sys

# Suppress InsecureRequestWarning
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

import coverage

cov = coverage.Coverage()
cov.start()

sys.path.append('.')
from steelhead_socks_proxy import *



class _FunctionCoverageTest(unittest.TestCase):
  def test_coverage(self):
    cov.stop()
    cov.json_report(['steelhead_socks_proxy/socks_proxy.py'], outfile='/tmp/cov.json')
    with open('/tmp/cov.json', 'r') as f:
      data = json.loads(f.read())
    print('[i] total coverage percent:', data['totals']['percent_covered'])
    self.assertGreaterEqual(data['totals']['percent_covered'], 95.0)

class TestSocksHTTPProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy_port = random.randint(8100, 8200)
        cls.proxy_server = ThreadedTCPServer(('localhost', cls.proxy_port), HTTPInterceptingSOCKSRequestHandler)
        cls.proxy_config = {'https': f'socks5h://localhost:{cls.proxy_port}', 'http': f'socks5h://localhost:{cls.proxy_port}'}
        cls.server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()
        cls.server_thread.join()

    def test_http_get_example_org(self):
        """Test connecting to http://example.org/"""
        urllib3.disable_warnings(InsecureRequestWarning)
        proxy_config = {'https': f'socks5://localhost:{TestSocksHTTPProxy.proxy_port}', 'http': f'socks5://localhost:{TestSocksHTTPProxy.proxy_port}'}
        response = requests.get('http://example.org/', proxies=proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

        response = requests.get('http://example.org/', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def test_large_response(self):
        """Test proxy's handling of a large response from an external source"""
        # Example large file URL (e.g., a large image or a large text file from a public CDN)
        response = requests.get('http://ipv4.download.thinkbroadband.com/10MB.zip', proxies=self.proxy_config)
        self.assertEqual(response.status_code, 200)
        # You can assert the size of the content if known, or just check if it's substantial
        self.assertEqual(len(response.content), 10 * 1024 * 1024)  # Expect 10 MB of data


    def test_http_post_request(self):
        """Test making a POST request"""
        urllib3.disable_warnings(InsecureRequestWarning)
        data = {'key': 'value'}
        response = requests.post('https://httpbin.org/post', data=data, proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        
        self.assertEqual(response.status_code, 200)
        # Check if the response contains the data sent in the POST request
        self.assertIn('key', response.json()['form'])
        self.assertEqual(response.json()['form']['key'], 'value')

    def test_http_head_request(self):
        """Test making a HEAD request"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.head('https://httpbin.org/get', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        
        self.assertEqual(response.status_code, 200)
        # Check if the response body is empty as expected in a HEAD request
        self.assertEqual(response.text, '')
        # Optionally, you can also check for specific headers if required

    def test_http_patch_request(self):
        """Test making a PATCH request"""
        urllib3.disable_warnings(InsecureRequestWarning)
        data = {'newKey': 'newValue'}
        response = requests.patch('https://httpbin.org/patch', data=data, proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('newKey', response.json()['form'])
        self.assertEqual(response.json()['form']['newKey'], 'newValue')

    def test_http_put_request(self):
        """Test making a PUT request"""
        urllib3.disable_warnings(InsecureRequestWarning)
        data = {'key': 'updatedValue'}
        response = requests.put('https://httpbin.org/put', data=data, proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('key', response.json()['form'])
        self.assertEqual(response.json()['form']['key'], 'updatedValue')

    def test_http_delete_request(self):
        """Test making a DELETE request"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.delete('https://httpbin.org/delete', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        
        self.assertEqual(response.status_code, 200)

    def test_http_redirect(self):
        """Test handling a redirect"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.org%2F', proxies=TestSocksHTTPProxy.proxy_config, verify=False, allow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def test_brotli_encoding(self):
        """Test brotli encoding"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/brotli', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Encoding', response.headers)
        self.assertEqual(response.headers['Content-Encoding'], 'br')

    def test_deflate_encoding(self):
        """Test deflate encoding"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/deflate', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Encoding', response.headers)
        self.assertEqual(response.headers['Content-Encoding'], 'deflate')

    def test_utf8_encoding(self):
        """Test UTF-8 encoding"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/encoding/utf8', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Type', response.headers)
        self.assertIn('charset=utf-8', response.headers['Content-Type'])

    def test_gzip_encoding(self):
        """Test gzip encoding"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/gzip', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Encoding', response.headers)
        self.assertEqual(response.headers['Content-Encoding'], 'gzip')

    def test_html_response(self):
        """Test HTML response"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/html', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Type', response.headers)
        self.assertIn('text/html', response.headers['Content-Type'])

    def test_json_response(self):
        """Test JSON response"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/json', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Type', response.headers)
        self.assertIn('application/json', response.headers['Content-Type'])

    def test_robots_txt(self):
        """Test robots.txt response"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/robots.txt', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Type', response.headers)
        self.assertIn('text/plain', response.headers['Content-Type'])

    def test_xml_response(self):
        """Test XML response"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('https://httpbin.org/xml', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Content-Type', response.headers)
        self.assertIn('application/xml', response.headers['Content-Type'])

    def test_https_get_example_org(self):
        """Test connecting to https://example.org/"""
        urllib3.disable_warnings(InsecureRequestWarning)
        proxy_config = {'https': f'socks5://localhost:{TestSocksHTTPProxy.proxy_port}', 'http': f'socks5://localhost:{TestSocksHTTPProxy.proxy_port}'}
        response = requests.get('https://example.org/', proxies=proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

        response = requests.get('https://example.org/', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def make_https_request(self):
        response = requests.get('https://example.org/', proxies=TestSocksHTTPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def test_https_get_example_org_multiple_times_parallel(self):
        """Test connecting to https://example.org/ many times in parallel"""
        threads = []
        for _ in range(20):
            thread = threading.Thread(target=self.make_https_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def test_ipv6_connection(self):
        """Test connecting to an IPv6 address"""
        ipv6_address = "https://[2606:4700:4700::1111]/"  # Example public IPv6 address (Cloudflare DNS)
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get(ipv6_address, proxies=TestSocksHTTPProxy.proxy_config, verify=False)

    def test_invalid_address_connection(self):
        """Test connection failure due to invalid address"""
        invalid_address = "http://nonexistent.example.com/"
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get(invalid_address, proxies=TestSocksHTTPProxy.proxy_config, verify=False)

class ChunkedHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/random-chunked':
            self.send_response(200)
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            # Randomly generate chunks
            for _ in range(random.randint(5, 10)):
                chunk = b'RandomData' * random.randint(1, 50)  # Random repetition of 'RandomData'
                self.wfile.write(f"{len(chunk):X}\r\n".encode())
                self.wfile.write(chunk + b"\r\n")
            
            self.wfile.write(b"0\r\n\r\n")  # End of chunked message
        else:
            self.protocol_version = 'HTTP/1.1'
            self.send_response(200)
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            self.wfile.write(b'4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n')


class TestChunkedTransferEncoding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the mock server in a separate thread
        cls.mock_server_port = random.randint(9900, 10000)
        cls.mock_server = socketserver.TCPServer(('localhost', cls.mock_server_port), ChunkedHTTPHandler)
        cls.mock_server_thread = threading.Thread(target=cls.mock_server.serve_forever)
        cls.mock_server_thread.daemon = True
        cls.mock_server_thread.start()

        # Set up your proxy server (adjust to your proxy server setup)
        cls.proxy_port = random.randint(8200, 8300)
        cls.proxy_server = ThreadedTCPServer(('localhost', cls.proxy_port), HTTPInterceptingSOCKSRequestHandler)
        cls.server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        # Shut down the mock server
        cls.mock_server.shutdown()
        cls.mock_server.server_close()
        cls.mock_server_thread.join()

        # Shut down the proxy server
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()
        cls.server_thread.join()

    def test_chunked_transfer_encoding(self):
        proxy = {'http': f'socks5://localhost:{TestChunkedTransferEncoding.proxy_port}'}
        response = requests.get(f'http://127.0.0.1:{TestChunkedTransferEncoding.mock_server_port}', proxies=proxy)
        self.assertEqual(response.text, 'Wikipedia')

    def test_random_chunked_transfer_encoding(self):
        proxy = {'http': f'socks5://localhost:{TestChunkedTransferEncoding.proxy_port}'}
        response = requests.get(f'http://127.0.0.1:{TestChunkedTransferEncoding.mock_server_port}/random-chunked', proxies=proxy)
        
        # Assertions to verify the response
        self.assertEqual(response.status_code, 200)
        self.assertTrue('RandomData' in response.text)  # Check if 'RandomData' is in the response


class TestSocksTCPProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy_port = random.randint(8000, 8100)
        cls.proxy_server = ThreadedTCPServer(('localhost', cls.proxy_port), BaseSOCKSRequestHandler)
        cls.proxy_config = {'https': f'socks5h://localhost:{cls.proxy_port}', 'http': f'socks5h://localhost:{cls.proxy_port}'}
        cls.server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()
        cls.server_thread.join()

    def test_http_get_example_org(self):
        """Test connecting to http://example.org/"""
        urllib3.disable_warnings(InsecureRequestWarning)
        proxy_config = {'https': f'socks5://localhost:{TestSocksTCPProxy.proxy_port}', 'http': f'socks5://localhost:{TestSocksTCPProxy.proxy_port}'}
        response = requests.get('http://example.org/', proxies=proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

        response = requests.get('http://example.org/', proxies=TestSocksTCPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def test_https_get_example_org(self):
        """Test connecting to https://example.org/"""
        urllib3.disable_warnings(InsecureRequestWarning)
        proxy_config = {'https': f'socks5://localhost:{TestSocksTCPProxy.proxy_port}', 'http': f'socks5://localhost:{TestSocksTCPProxy.proxy_port}'}
        response = requests.get('https://example.org/', proxies=proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

        response = requests.get('https://example.org/', proxies=TestSocksTCPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def make_https_request(self):
        response = requests.get('https://example.org/', proxies=TestSocksTCPProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def test_https_get_example_org_multiple_times_parallel(self):
        """Test connecting to https://example.org/ many times in parallel"""
        threads = []
        for _ in range(20):
            thread = threading.Thread(target=self.make_https_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def test_invalid_address_connection(self):
        """Test connection failure due to invalid address"""
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get('http://nonexistent.example.com/', proxies=TestSocksTCPProxy.proxy_config, verify=False)
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get('https://nonexistent.example.com/', proxies=TestSocksTCPProxy.proxy_config, verify=False)

class TestSocksInterceptingProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy_port = random.randint(8000, 8100)
        cls.proxy_server = ThreadedTCPServer(('localhost', cls.proxy_port), InterceptingSOCKSRequestHandler)
        cls.proxy_config = {'https': f'socks5h://localhost:{cls.proxy_port}', 'http': f'socks5h://localhost:{cls.proxy_port}'}
        cls.server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()
        cls.server_thread.join()

    def test_http_get_example_org(self):
        """Test connecting to http://example.org/"""
        urllib3.disable_warnings(InsecureRequestWarning)
        proxy_config = {'https': f'socks5://localhost:{TestSocksInterceptingProxy.proxy_port}', 'http': f'socks5://localhost:{TestSocksInterceptingProxy.proxy_port}'}
        response = requests.get('http://example.org/', proxies=proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

        response = requests.get('http://example.org/', proxies=TestSocksInterceptingProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def test_https_get_example_org(self):
        """Test connecting to https://example.org/"""
        urllib3.disable_warnings(InsecureRequestWarning)
        proxy_config = {'https': f'socks5://localhost:{TestSocksInterceptingProxy.proxy_port}', 'http': f'socks5://localhost:{TestSocksInterceptingProxy.proxy_port}'}
        response = requests.get('https://example.org/', proxies=proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

        response = requests.get('https://example.org/', proxies=TestSocksInterceptingProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def make_https_request(self):
        response = requests.get('https://example.org/', proxies=TestSocksInterceptingProxy.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

    def test_https_get_example_org_multiple_times_parallel(self):
        """Test connecting to https://example.org/ many times in parallel"""
        threads = []
        for _ in range(20):
            thread = threading.Thread(target=self.make_https_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def test_invalid_address_connection(self):
        """Test connection failure due to invalid address"""
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get('http://nonexistent.example.com/', proxies=TestSocksInterceptingProxy.proxy_config, verify=False)
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get('https://nonexistent.example.com/', proxies=TestSocksInterceptingProxy.proxy_config, verify=False)

class NoBodyHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/close-immediately':
            self.close_connection = True
        elif self.path == '/wait':
            time.sleep(1)
            self.send_response(200)
            self.send_header('Content-Type', '')
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-Type', '')
            self.end_headers()

class TestSpecialResponses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Set up and start the mock server in a separate thread
        cls.mock_server_port = random.randint(8300, 8400)
        cls.mock_server = socketserver.TCPServer(("", cls.mock_server_port), NoBodyHTTPHandler)
        cls.mock_server_thread = threading.Thread(target=cls.mock_server.serve_forever)
        cls.mock_server_thread.daemon = True
        cls.mock_server_thread.start()

        cls.proxy_port = random.randint(8400, 8500)
        cls.proxy_server = ThreadedTCPServer(('localhost', cls.proxy_port), HTTPInterceptingSOCKSRequestHandler)
        cls.proxy_config = {'https': f'socks5h://localhost:{cls.proxy_port}', 'http': f'socks5h://localhost:{cls.proxy_port}'}
        cls.server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()
        cls.server_thread.join()
        # Shut down the mock server
        cls.mock_server.shutdown()
        cls.mock_server.server_close()
        cls.mock_server_thread.join()

    def test_no_body_no_content_length(self):
        """Test connection to a server with no body and no content-length or transfer-encoding"""
        response = requests.get(f'http://127.0.0.1:{self.mock_server_port}', proxies=TestSpecialResponses.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, '')
        self.assertNotIn('Content-Length', response.headers)
        self.assertNotIn('Transfer-Encoding', response.headers)

    def test_wait(self):
        """Test connection to a server with no body and no content-length or transfer-encoding"""
        response = requests.get(f'http://127.0.0.1:{self.mock_server_port}/wait', proxies=TestSpecialResponses.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, '')
        self.assertNotIn('Content-Length', response.headers)
        self.assertNotIn('Transfer-Encoding', response.headers)

    def test_server_closes_connection(self):
        """Test behavior when the server closes the connection before responding"""
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get(f'http://127.0.0.1:{self.mock_server_port}/close-immediately', verify=False)



# Define the simple HTTP handler
class SimpleTestHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('content-length', len(b"Localhost server response"))
        self.end_headers()
        self.wfile.write(b"Localhost server response")

# The test class
class TestRequestRouting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the local HTTP server
        cls.local_server_port = random.randint(8500, 8600)
        cls.local_httpd = socketserver.TCPServer(("", cls.local_server_port), SimpleTestHTTPHandler)
        cls.local_server_thread = threading.Thread(target=cls.local_httpd.serve_forever)
        cls.local_server_thread.daemon = True
        cls.local_server_thread.start()

        # Set up the DomainConnectionRouter with the redirection rule
        cls.router = DomainConnectionRouter()
        cls.router.add_route('server.internal', f'http://127.0.0.1:{cls.local_server_port}')
        cls.router.add_route('www.google.com', f'http://127.0.0.1:{cls.local_server_port}')

        # Start the proxy server with the routed request handler
        cls.proxy_port = random.randint(8600, 8700)
        cls.proxy_server = ThreadedTCPServer(('localhost', cls.proxy_port),
                                             lambda request, client_address, server: HTTPInterceptingSOCKSRequestHandler(request, client_address, server, cls.router))
        cls.server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        cls.proxy_config = {'http': f'socks5h://localhost:{cls.proxy_port}', 'https': f'socks5h://localhost:{cls.proxy_port}'}

    @classmethod
    def tearDownClass(cls):
        # Shut down the proxy server
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()
        cls.server_thread.join()

        # Shut down the local HTTP server
        cls.local_httpd.shutdown()
        cls.local_httpd.server_close()
        cls.local_server_thread.join()

    def test_request_redirection(self):
        """Test redirection from server.internal to localhost"""
        response = requests.get('http://server.internal/', proxies=self.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Localhost server response")

        # urllib3.disable_warnings(InsecureRequestWarning)
        # response = requests.get('https://server.internal/', proxies=self.proxy_config, verify=False)
        # self.assertEqual(response.status_code, 200)
        # self.assertEqual(response.text, "Localhost server response")

    def test_google_redirection(self):
        """Test redirection from www.google.com to localhost"""
        response = requests.get('http://www.google.com/', proxies=self.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Localhost server response")

        # urllib3.disable_warnings(InsecureRequestWarning)
        # response = requests.get('https://www.google.com/', proxies=self.proxy_config, verify=False)
        # self.assertEqual(response.status_code, 200)
        # self.assertEqual(response.text, "Localhost server response")

    def test_no_redirection(self):
        """Test no redirection from example.org"""
        urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get('http://example.org/', proxies=self.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)

        response = requests.get('https://example.org/', proxies=self.proxy_config, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Example Domain', response.text)


class TestSOCKS5Proxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy_port = random.randint(8100, 8200)
        cls.proxy_server = ThreadedTCPServer(('localhost', cls.proxy_port), HTTPInterceptingSOCKSRequestHandler)
        cls.server_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy_server.shutdown()
        cls.proxy_server.server_close()
        cls.server_thread.join()

    def send_socks5_greeting(self, version, nmethods, methods):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', self.proxy_port))
        sock.sendall(struct.pack('!BB', version, nmethods) + methods)
        return sock

    def test_invalid_socks5_greeting(self):
        """Test with an invalid SOCKS5 greeting (invalid version)"""
        sock = self.send_socks5_greeting(version=4, nmethods=1, methods=b'\x00')
        with self.assertRaises(ConnectionResetError):
            sock.recv(2)
        sock.close()

    def test_more_than_zero_auth_methods(self):
        """Test with more than 0 auth methods"""
        sock = self.send_socks5_greeting(version=5, nmethods=2, methods=b'\x00\x02')
        response = sock.recv(2)
        sock.close()
        self.assertEqual(response, b'\x05\x00')  # No authentication required

    def test_invalid_address_type(self):
        """Test with an invalid address type in the SOCKS5 request"""
        sock = self.send_socks5_greeting(version=5, nmethods=1, methods=b'\x00')
        sock.recv(2)  # Receive server response for greeting

        # Send invalid address type request (e.g., address type 5)
        sock.sendall(struct.pack('!BBBB', 5, 1, 0, 5) + b'invalid')
        with self.assertRaises(ConnectionResetError):
            sock.recv(10)
        sock.close()

    def send_socks5_request(self, version, cmd, address_type=0x01, destination=b'\x00\x00\x00\x00', port=b'\x00\x50'):
        """Helper function to send a SOCKS5 request with specified parameters."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', self.proxy_port))
        # Send the greeting and receive the server's response
        sock.sendall(b'\x05\x01\x00')
        sock.recv(2)
        # Send the request
        request = struct.pack('!BBBB', version, cmd, 0x00, address_type) + destination + port
        sock.sendall(request)
        return sock

    def test_invalid_version(self):
        """Test with an invalid SOCKS5 version."""
        sock = self.send_socks5_request(version=0x04, cmd=0x01)  # Invalid version
        with self.assertRaises(ConnectionResetError):
            sock.recv(10)  # Expecting the connection to be closed by the server
        sock.close()

    def test_invalid_cmd(self):
        """Test with an invalid SOCKS5 command."""
        sock = self.send_socks5_request(version=0x05, cmd=0x03)  # Invalid command
        with self.assertRaises(ConnectionResetError):
            sock.recv(10)  # Expecting the connection to be closed by the server
        sock.close()

if __name__ == '__main__':
    unittest.main()
