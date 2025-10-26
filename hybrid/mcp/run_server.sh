export LD_LIBRARY_PATH="/home/david/ossl-3.5/lib64:/home/david/ossl-3.5/lib:$LD_LIBRARY_PATH"
export PATH="$HOME/ossl-3.5/bin:$PATH"

# Check if server certificate and key exist, generate if not
if [ ! -f "server.crt" ] || [ ! -f "server.key" ]; then
    echo "Server certificate or key not found. Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    echo "Self-signed certificate generated: server.crt and server.key"
fi

# openssl s_server -accept 8443 -cert server.crt -key server.key -tls1_3 -groups X25519MLKEM768 -www -trace -msg -debug
openssl s_server -accept 8443 -cert server.crt -key server.key -tls1_3 -groups X25519MLKEM768 -www -msg -debug
echo "Server stopped"
