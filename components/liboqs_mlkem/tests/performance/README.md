# ML-KEM-768 Performance Test

## Purpose

This application tests the performance of the ML-KEM-768 cryptographic component by measuring execution time, stack RAM usage, and heap usage for all API operations. The test is designed to provide comprehensive performance metrics for the ML-KEM-768 key encapsulation mechanism implementation.

## Overview

The performance test exercises all ML-KEM-768 APIs in sequence:
- `mlkem768_init()` - Initialize the context
- `mlkem768_keypair()` - Generate a key pair
- `mlkem768_encaps()` - Encapsulate a shared secret
- `mlkem768_decaps()` - Decapsulate a shared secret
- `mlkem768_cleanup()` - Clean up resources

Additionally, it calls utility functions to retrieve algorithm information and key sizes.

## Metrics Collected

The test measures three key performance metrics:

1. **Execution Time**: Uses ESP32's high-resolution timer (`esp_timer`) to measure the duration of each API call in microseconds and milliseconds.

2. **Stack RAM Usage**: Creates a dedicated FreeRTOS task with a known stack size and uses `uxTaskGetStackHighWaterMark()` to determine the maximum stack usage during execution.

3. **Heap Usage**: Monitors heap memory usage before and after operations using `esp_get_free_heap_size()` and `esp_get_minimum_free_heap_size()` to track peak memory consumption.

## Test Results

### Execution Timing

| Operation | Time (μs) | Time (ms) |
|-----------|-----------|-----------|
| Init      | 219       | 0.219     |
| Keypair   | 17,538    | 17.538    |
| Encaps    | 19,926    | 19.926    |
| Decaps    | 22,905    | 22.905    |
| Cleanup   | 48        | 0.048     |
| **Total** | **85,493** | **85.493** |

### Memory Usage

| Metric | Value |
|--------|-------|
| Stack Size | 16,384 bytes |
| Stack High Water Mark | 1,196 bytes |
| Stack Used | 15,188 bytes |
| Heap Free (Before) | 287,892 bytes |
| Heap Free (After) | 287,668 bytes |
| Heap Min Free (Before) | 287,892 bytes |
| Heap Min Free (After) | 282,800 bytes |
| **Peak Heap Usage** | **224 bytes** |

### Flash Memory Usage

| Component | Total Size | Flash Code (.text) | Flash Data (.rodata) |
|-----------|------------|-------------------|---------------------|
| **liboqs_mlkem.a** | **10,756 bytes** | **10,308 bytes** | **448 bytes** |

The ML-KEM-768 component uses exclusively flash memory (no DRAM or IRAM):
- **Flash Code**: 10,308 bytes for executable code
- **Flash Data**: 448 bytes for read-only data
- **Total Flash**: 10,756 bytes

### Algorithm Information

| Property | Value |
|----------|-------|
| Algorithm Name | ML-KEM-768 |
| Public Key Length | 1,184 bytes |
| Secret Key Length | 2,400 bytes |
| Ciphertext Length | 1,088 bytes |
| Shared Secret Length | 32 bytes |

## Test Environment

- **Chip**: ESP32-D0WD (revision v1.0)
- **CPU Frequency**: 160 MHz
- **ESP-IDF Version**: v6.0-dev-1002-gbfe5caf58f
- **Flash Size**: 2 MB

## Building and Running

```bash
cd components/liboqs_mlkem/tests/performance
idf.py build flash monitor
```

The test will execute automatically on startup and print the performance metrics to the serial console.

