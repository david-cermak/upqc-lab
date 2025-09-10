# PQC Lab TCP Example

Simple TCP server and client application for testing post-quantum cryptography implementations.

## Build

```bash
mkdir build
cd build
cmake ..
make
```

## Run

1. Start the server:
```bash
./bin/server
```

2. In another terminal, start the client:
```bash
./bin/client
```

3. Type messages in the client terminal. The server will echo them back.
4. Type `exit` to quit.

## Next Steps

This boilerplate will be extended with ML-KEM-512 (Kyber) post-quantum cryptography for secure key exchange.
