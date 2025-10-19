#!/home/david/repos/upqc-lab/hybrid/mcp/venv/bin/python
"""
Test script for the simplified MCP server
This can be used to test the MCP server functionality directly
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

async def test_mcp_server():
    """Test the simplified MCP server functionality"""
    
    # Test the simplified test runner directly
    from fast_server import SimpleTestRunner
    
    working_dir = "/home/david/repos/upqc-lab/hybrid/target_client"
    test_runner = SimpleTestRunner()
    
    print("Running hybrid PQC TLS test...")
    success, output = test_runner.run_test(working_dir)
    
    if success:
        print("Test completed successfully!")
        print("\n=== TEST OUTPUT ===")
        print(output)
    else:
        print("Test failed!")
        print(f"Error: {output}")
    
    print("\n=== GET OUTPUTS TEST ===")
    # Test the get_outputs functionality
    if test_runner.last_test_output:
        print("Last test output available:")
        print(test_runner.last_test_output[:500] + "..." if len(test_runner.last_test_output) > 500 else test_runner.last_test_output)
    else:
        print("No test output available")

if __name__ == "__main__":
    asyncio.run(test_mcp_server())
