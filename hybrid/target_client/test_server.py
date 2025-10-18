#!/usr/bin/env python3
"""
Test script to verify the TLS server is working
This script connects to the TLS server and sends a simple HTTP request
"""

import socket
import ssl
import sys

def test_tls_server():
    """Test the TLS server by connecting and sending an HTTP request"""
    
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to the server
        print("Connecting to 127.0.0.1:8443...")
        client_socket.connect(('127.0.0.1', 8443))
        
        # Create SSL context and wrap socket (modern approach)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_socket = context.wrap_socket(client_socket, server_hostname='127.0.0.1')
        
        print("Connected! Sending HTTP request...")
        
        # Send HTTP request
        request = "GET /hello HTTP/1.0\r\nHost: 127.0.0.1:8443\r\n\r\n"
        ssl_socket.send(request.encode('utf-8'))
        
        # Receive response
        response = ssl_socket.recv(1024).decode('utf-8')
        print("Response received:")
        print(response)
        
        ssl_socket.close()
        print("Test completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        client_socket.close()

if __name__ == "__main__":
    test_tls_server()
