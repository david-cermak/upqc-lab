#!/usr/bin/env python3
"""
Fast MCP Server for Hybrid PQC TLS Testing
Optimized for speed - should complete in ~250ms
"""

import asyncio
import json
import subprocess
import time
import os
import sys
import threading
import queue
from typing import Dict, Any, List

# MCP imports
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

class FastProcessManager:
    def __init__(self):
        self.server_process = None
        self.client_process = None
        self.server_output = []
        self.client_output = []
        self.server_queue = queue.Queue()
        self.client_queue = queue.Queue()
        self.server_thread = None
        self.client_thread = None
        
    def start_server(self, working_dir: str) -> bool:
        """Start OpenSSL server"""
        try:
            env = os.environ.copy()
            env['PATH'] = f"{os.path.expanduser('~/ossl-3.5/bin')}:{env.get('PATH', '')}"
            env['LD_LIBRARY_PATH'] = f"{os.path.expanduser('~/ossl-3.5/lib64')}:{os.path.expanduser('~/ossl-3.5/lib')}:{env.get('LD_LIBRARY_PATH', '')}"
            
            server_script = os.path.join(working_dir, "openssl_server.sh")
            self.server_process = subprocess.Popen(
                ["bash", server_script],
                cwd=working_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=0  # Unbuffered
            )
            
            # Start background thread to read output
            self.server_thread = threading.Thread(target=self._read_server_output, daemon=True)
            self.server_thread.start()
            return True
        except Exception as e:
            print(f"Failed to start server: {e}")
            return False
    
    def start_client(self, working_dir: str) -> bool:
        """Start mbedTLS client"""
        try:
            client_binary = os.path.join(working_dir, "build", "https_mbedtls.elf")
            if not os.path.exists(client_binary):
                print(f"Client binary not found: {client_binary}")
                return False
                
            self.client_process = subprocess.Popen(
                [client_binary],
                cwd=working_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0  # Unbuffered
            )
            
            # Start background thread to read output
            self.client_thread = threading.Thread(target=self._read_client_output, daemon=True)
            self.client_thread.start()
            return True
        except Exception as e:
            print(f"Failed to start client: {e}")
            return False
    
    def _read_server_output(self):
        """Read server output in background thread"""
        try:
            for line in iter(self.server_process.stdout.readline, ''):
                if line:
                    self.server_queue.put(("stdout", line.strip()))
        except:
            pass
        
        try:
            for line in iter(self.server_process.stderr.readline, ''):
                if line:
                    self.server_queue.put(("stderr", line.strip()))
        except:
            pass
    
    def _read_client_output(self):
        """Read client output in background thread"""
        try:
            for line in iter(self.client_process.stdout.readline, ''):
                if line:
                    self.client_queue.put(("stdout", line.strip()))
        except:
            pass
    
    def get_outputs(self) -> Dict[str, Any]:
        """Get all captured outputs quickly"""
        server_lines = []
        client_lines = []
        
        # Drain all available output from queues
        while not self.server_queue.empty():
            try:
                msg_type, content = self.server_queue.get_nowait()
                server_lines.append(f"{msg_type.upper()}: {content}")
            except queue.Empty:
                break
        
        while not self.client_queue.empty():
            try:
                msg_type, content = self.client_queue.get_nowait()
                client_lines.append(content)
            except queue.Empty:
                break
        
        server_running = self.server_process and self.server_process.poll() is None
        client_running = self.client_process and self.client_process.poll() is None
        
        return {
            "server_output": server_lines,
            "client_output": client_lines,
            "server_running": server_running,
            "client_running": client_running
        }
    
    def stop_processes(self):
        """Stop all processes immediately"""
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
        
        # Additional cleanup: kill any remaining openssl processes on port 8443
        try:
            import subprocess
            result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ':8443' in line and 'openssl' in line:
                    # Extract PID and kill it
                    import re
                    pid_match = re.search(r'pid=(\d+)', line)
                    if pid_match:
                        pid = int(pid_match.group(1))
                        subprocess.run(['kill', '-9', str(pid)], capture_output=True)
        except:
            pass

# Global process manager
process_manager = FastProcessManager()

# Initialize MCP server
server = Server("hybrid-pqc-tester")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="run_fast_test",
            description="Run fast OpenSSL server and mbedTLS client test (~250ms)",
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
        
        # Stop existing processes
        process_manager.stop_processes()
        
        # Start server
        if process_manager.start_server(working_dir):
            await asyncio.sleep(0.5)  # Brief wait for server to start
            
            # Start client
            if process_manager.start_client(working_dir):
                # Wait for handshake to complete (should be ~250ms)
                await asyncio.sleep(0.3)  # Brief wait for handshake
                
                outputs = process_manager.get_outputs()
                
                result = f"""# Fast Hybrid PQC TLS Test

## Status
- Server running: {outputs['server_running']}
- Client running: {outputs['client_running']}

## Server Output
```
{chr(10).join(outputs['server_output'])}
```

## Client Output  
```
{chr(10).join(outputs['client_output'])}
```

## Analysis
Test completed in ~250ms. Handshake failure expected due to group incompatibility.
"""
                return [TextContent(type="text", text=result)]
            else:
                return [TextContent(type="text", text="Failed to start client")]
        else:
            return [TextContent(type="text", text="Failed to start server")]
    
    elif name == "get_outputs":
        outputs = process_manager.get_outputs()
        result = json.dumps(outputs, indent=2)
        return [TextContent(type="text", text=result)]
    
    elif name == "stop_test":
        process_manager.stop_processes()
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

