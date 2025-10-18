#!/usr/bin/env python3
"""
Simple TLS server for testing ESP-IDF mbedTLS client
This server listens on localhost:8443 and responds to TLS connections
"""

import socket
import ssl
import threading
import time

def handle_client(client_socket, address):
    """Handle a client connection"""
    print(f"Connection from {address}")
    
    try:
        # Create SSL context and wrap socket (modern approach)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain("server.crt", "server.key")
        
        ssl_socket = context.wrap_socket(client_socket, server_side=True)
        
        # Read the HTTP request
        request = ssl_socket.recv(1024).decode('utf-8')
        print(f"Received request:\n{request}")
        
        # Send a simple HTTP response
        response = """HTTP/1.0 200 OK\r
Content-Type: text/plain\r
Content-Length: 13\r
\r
Hello, TLS!"""
        
        ssl_socket.send(response.encode('utf-8'))
        ssl_socket.close()
        
    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        client_socket.close()

def main():
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to localhost:8443
    server_socket.bind(('127.0.0.1', 8443))
    server_socket.listen(5)
    
    print("TLS Server listening on 127.0.0.1:8443")
    print("Make sure you have server.crt and server.key files")
    print("Press Ctrl+C to stop the server")
    
    try:
        while True:
            client_socket, address = server_socket.accept()
            # Handle each client in a separate thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
