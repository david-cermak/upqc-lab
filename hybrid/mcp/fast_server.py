#!/usr/bin/env python3
"""
Simple MCP Server for Hybrid PQC TLS Testing
Simplified version that follows the working shell script patterns
"""

import asyncio
import json
import subprocess
import time
import os
import signal
from typing import Dict, Any, List

# MCP imports
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

class SimpleTestRunner:
    def __init__(self):
        self.server_process = None
        self.client_process = None
        self.last_build_output = ""
        self.last_test_output = ""
        
    def cleanup_processes(self):
        """Clean up any existing processes"""
        try:
            # Kill any openssl processes on port 8443
            subprocess.run(['pkill', '-f', 'openssl'], capture_output=True)
        except:
            pass
        
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=1)
            except:
                try:
                    self.server_process.kill()
                except:
                    pass
            self.server_process = None
            
        if self.client_process:
            try:
                self.client_process.terminate()
                self.client_process.wait(timeout=1)
            except:
                try:
                    self.client_process.kill()
                except:
                    pass
            self.client_process = None
    
    def build_client(self, working_dir: str) -> tuple[bool, str]:
        """Build mbedTLS client using ESP-IDF - follows run_client.sh pattern"""
        try:
            # Set up environment like the shell script
            env = os.environ.copy()
            env['IDF_PATH'] = '/home/david/esp/idf'
            
            # Use the exact same build command as the shell script
            build_script = f"""
            source /home/david/esp/idf/export.sh
            cd {working_dir}
            idf.py build
            """
            
            print(f"Building client in {working_dir}...")
            build_process = subprocess.run(
                ['bash', '-c', build_script],
                env=env,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            build_output = f"Build return code: {build_process.returncode}\n"
            if build_process.stdout:
                build_output += f"Build stdout:\n{build_process.stdout}\n"
            if build_process.stderr:
                build_output += f"Build stderr:\n{build_process.stderr}\n"
            
            # Check return code like the shell script does
            if build_process.returncode != 0:
                build_output += f"Build failed with return code {build_process.returncode}\n"
                return False, build_output
                
            # Check if binary exists
            client_binary = os.path.join(working_dir, "build", "https_mbedtls.elf")
            if os.path.exists(client_binary):
                build_output += f"Build successful, binary exists: {client_binary}\n"
                return True, build_output
            else:
                build_output += f"Build completed but binary not found: {client_binary}\n"
                return False, build_output
                
        except subprocess.TimeoutExpired:
            build_output = "Build timed out after 60 seconds\n"
            return False, build_output
        except Exception as e:
            build_output = f"Build failed: {e}\n"
            return False, build_output
    
    def run_test(self, working_dir: str) -> tuple[bool, str]:
        """Run the complete test - follows run.sh pattern"""
        try:
            # Clean up first
            self.cleanup_processes()
            
            # Build client first (like run.sh does)
            build_success, build_output = self.build_client(working_dir)
            if not build_success:
                return False, f"Build failed:\n{build_output}"
            
            self.last_build_output = build_output
            
            # Set up environment like run.sh
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = "/home/david/ossl-3.5/lib64:/home/david/ossl-3.5/lib"
            env['PATH'] = "/home/david/ossl-3.5/bin:" + env.get('PATH', '')
            
            # Start server (like run.sh line 12) - removed -trace flag as requested
            server_cmd = [
                'openssl', 's_server', 
                '-accept', '8443',
                '-cert', 'server.crt',
                '-key', 'server.key',
                '-tls1_3',
                '-groups', 'X25519MLKEM768',
                '-www',
                '-msg',
                '-debug'
            ]
            
            self.server_process = subprocess.Popen(
                server_cmd,
                cwd=working_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to start (like run.sh sleep 1)
            time.sleep(1)
            
            # Start client (like run.sh line 14)
            client_binary = os.path.join(working_dir, "build", "https_mbedtls.elf")
            self.client_process = subprocess.Popen(
                [client_binary],
                cwd=working_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Wait for client to complete (like run.sh wait)
            try:
                client_output, _ = self.client_process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                # Client didn't exit cleanly, but we got the output we need
                self.client_process.kill()
                client_output, _ = self.client_process.communicate()
            
            # Get server output
            try:
                server_output, server_error = self.server_process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                # Server still running, kill it and get output
                self.server_process.kill()
                server_output, server_error = self.server_process.communicate()
            
            # Clean up
            self.cleanup_processes()
            
            # Format results
            test_output = f"""# Hybrid PQC TLS Test Results

## Build Output
```
{build_output}
```

## Server Output
```
{server_output}
```

## Server Error
```
{server_error}
```

## Client Output
```
{client_output}
```

## Analysis
Test completed. Client and server attempted handshake with X25519MLKEM768 groups.
"""
            
            self.last_test_output = test_output
            return True, test_output
            
        except subprocess.TimeoutExpired:
            self.cleanup_processes()
            return False, "Test timed out"
        except Exception as e:
            self.cleanup_processes()
            return False, f"Test failed: {e}"

# Global test runner
test_runner = SimpleTestRunner()

# Initialize MCP server
server = Server("hybrid-pqc-tester")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="run_fast_test",
            description="Run fast OpenSSL server and mbedTLS client test (builds client first, then ~250ms test)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_outputs",
            description="Get test outputs",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="stop_test",
            description="Stop test processes",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    
    if name == "run_fast_test":
        working_dir = "/home/david/repos/upqc-lab/hybrid/target_client"
        
        success, output = test_runner.run_test(working_dir)
        
        if success:
            return [TextContent(type="text", text=output)]
        else:
            return [TextContent(type="text", text=f"Test failed:\n{output}")]
    
    elif name == "get_outputs":
        # Return the last test results
        if test_runner.last_test_output:
            return [TextContent(type="text", text=test_runner.last_test_output)]
        else:
            return [TextContent(type="text", text="No test results available")]
    
    elif name == "stop_test":
        test_runner.cleanup_processes()
        return [TextContent(type="text", text="Stopped all processes")]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Main entry point"""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="hybrid-pqc-tester",
                server_version="1.0.0",
                capabilities={
                    "tools": {}
                }
            )
        )

if __name__ == "__main__":
    asyncio.run(main())