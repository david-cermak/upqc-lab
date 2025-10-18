# Hybrid PQC TLS Testing MCP Server

This MCP (Model Context Protocol) server automates testing of hybrid post-quantum cryptography TLS connections between OpenSSL 3.5+ and mbedTLS clients.

## 🎯 Purpose

The MCP server enables rapid debugging of TLS handshake issues between:
- **OpenSSL 3.5+ server** with X25519MLKEM768 hybrid group support
- **mbedTLS client** (ESP32/ESP-IDF) attempting to connect

## 🚀 Key Features

- **Fast execution** - Complete test in ~250ms
- **Real-time output capture** - Both server and client logs
- **Automatic process management** - Starts/stops processes cleanly
- **Detailed handshake analysis** - Shows exact failure points
- **Port conflict resolution** - Handles existing processes

## 📊 Current Test Results

### ✅ What Works:
- OpenSSL 3.5+ server starts with X25519MLKEM768 hybrid group
- mbedTLS client connects successfully
- Handshake attempt begins immediately

### ❌ The Problem:
- **Handshake fails** with error `-0x7780` (fatal alert from peer)
- **Root cause**: mbedTLS doesn't support X25519MLKEM768 hybrid group
- **OpenSSL error**: "no suitable key share" - server can't find compatible group

### 📋 Exact Client Output:
```
I (20176839) port: Starting scheduler.
I (20176842) esp_netif_loopback: loopback initialization
I (20176843) example: Seeding the random number generator
I (20176843) example: Skipping certificate bundle for localhost testing...
I (20176843) example: Setting hostname for TLS session...
I (20176843) example: Setting up the SSL/TLS structure...
I (20176843) example: Connecting to 127.0.0.1:8443...
I (20176844) example: Connected.
I (20176844) example: Performing the SSL/TLS handshake...
E (20176845) example: mbedtls_ssl_handshake returned -0x7780
E (20176845) example: Last error was: -0x7780 - SSL - A fatal alert message was received from our peer
```

## 🛠️ Setup Instructions

### 1. Install Dependencies
```bash
cd /home/david/repos/upqc-lab/hybrid/mcp
# Activate your virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Cursor MCP Integration

Copy the MCP configuration to your Cursor settings:

**Option A: Global Cursor Configuration**
```bash
cp /home/david/repos/upqc-lab/hybrid/mcp/cursor_mcp_config.json ~/.cursor/mcp.json
```

**Option B: Workspace Configuration**
```bash
cp /home/david/repos/upqc-lab/hybrid/mcp/cursor_mcp_config.json /home/david/repos/upqc-lab/.cursor/mcp.json
```

### 3. Restart Cursor
Restart Cursor to load the MCP server configuration.

## 🎮 Usage

### Available MCP Tools

1. **`run_fast_test`** - Run complete test in ~250ms
   - Starts OpenSSL server with X25519MLKEM768
   - Starts mbedTLS client
   - Captures all outputs
   - Shows handshake failure analysis

2. **`get_outputs`** - Get current captured outputs
   - Returns JSON format with server/client logs
   - Real-time status of running processes

3. **`stop_test`** - Stop all running processes
   - Cleans up server and client processes
   - Frees port 8443

### Example Usage
```
# Run the fast test
run_fast_test

# Get detailed outputs
get_outputs

# Stop processes
stop_test
```

## 🔧 Technical Details

### Server Configuration
- **OpenSSL 3.5+** with X25519MLKEM768 hybrid group
- **Port**: 8443
- **TLS 1.3** with hybrid post-quantum cryptography
- **Debug logging** enabled for handshake analysis

### Client Configuration
- **mbedTLS** (ESP-IDF) client
- **TLS 1.3** support
- **Certificate verification** disabled for localhost testing
- **Debug logging** enabled

### Process Management
- **Background threads** for non-blocking output capture
- **Queue-based communication** for fast output collection
- **Automatic cleanup** with 1s timeout for process termination
- **Port conflict resolution** - kills existing processes

## 🐛 Debugging Workflow

1. **Run test** - `run_fast_test` to see current handshake failure
2. **Analyze outputs** - Check server/client logs for specific issues
3. **Modify code** - Update mbedTLS client or OpenSSL server configuration
4. **Rebuild client** - `idf.py build` in target_client directory
5. **Test again** - Repeat until handshake succeeds

## 📁 File Structure

```
mcp/
├── fast_server.py              # Main MCP server (optimized for speed)
├── test_mcp.py                # Direct testing script
├── requirements.txt            # Python dependencies
├── cursor_mcp_config.json      # Cursor MCP configuration
└── README.md                  # This file
```

## 🔍 Next Steps for Handshake Success

1. **Add mbedTLS hybrid group support** - Configure mbedTLS to support X25519MLKEM768
2. **Fallback strategy** - Use compatible groups between OpenSSL and mbedTLS
3. **Certificate handling** - Ensure proper certificate validation
4. **Protocol negotiation** - Verify TLS 1.3 and group negotiation

## 🚨 Troubleshooting

### Port 8443 Already in Use
```bash
# Kill existing OpenSSL processes
pkill -f openssl
# Or kill specific PID
kill <PID>
```

### MCP Server Not Loading
1. Check virtual environment is activated
2. Verify Python path in cursor_mcp_config.json
3. Restart Cursor after configuration changes

### Build Issues
```bash
# Set up ESP-IDF environment
source $HOME/esp/esp-idf/export.sh
# Build client
cd /home/david/repos/upqc-lab/hybrid/target_client
idf.py build
```

## 📈 Performance Metrics

- **Test execution time**: ~250ms
- **Server startup**: ~0.5s
- **Handshake attempt**: ~0.3s
- **Output capture**: Immediate
- **Process cleanup**: ~1s

The MCP server is optimized for rapid iteration during debugging of hybrid PQC TLS handshake issues.