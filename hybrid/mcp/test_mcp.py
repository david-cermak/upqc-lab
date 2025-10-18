#!/home/david/repos/upqc-lab/hybrid/mcp/venv/bin/python
"""
Test script for the MCP server
This can be used to test the MCP server functionality directly
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

async def test_mcp_server():
    """Test the MCP server functionality"""
    
    # Test the process manager directly
    from fast_server import FastProcessManager
    
    working_dir = "/home/david/repos/upqc-lab/hybrid/target_client"
    process_manager = FastProcessManager()
    
    print("Starting OpenSSL server...")
    server_started = process_manager.start_server(working_dir)
    if not server_started:
        print("Failed to start server")
        return
    
    print("Waiting for server to start...")
    await asyncio.sleep(3)
    
    print("Starting mbedTLS client...")
    client_started = process_manager.start_client(working_dir)
    if not client_started:
        print("Failed to start client")
        process_manager.stop_processes()
        return
    
    print("Running test for 10 seconds...")
    await asyncio.sleep(10)
    
    print("Collecting outputs...")
    outputs = process_manager.get_outputs()
    
    print("\n=== SERVER OUTPUT ===")
    for line in outputs['server_output'][-20:]:  # Last 20 lines
        print(line)
    
    print("\n=== CLIENT OUTPUT ===")
    for line in outputs['client_output'][-20:]:  # Last 20 lines
        print(line)
    
    print(f"\nServer running: {outputs['server_running']}")
    print(f"Client running: {outputs['client_running']}")
    
    print("Stopping processes...")
    process_manager.stop_processes()

if __name__ == "__main__":
    asyncio.run(test_mcp_server())
