export LD_LIBRARY_PATH="/home/david/ossl-3.5/lib64:/home/david/ossl-3.5/lib:$LD_LIBRARY_PATH"
export PATH="$HOME/ossl-3.5/bin:$PATH"

# openssl s_server -accept 8443 -cert server.crt -key server.key -tls1_3 -groups X25519MLKEM768 -www -trace -msg -debug
openssl s_server -accept 8443 -cert server.crt -key server.key -tls1_3 -groups X25519MLKEM768 -www -msg -debug
echo "Server stopped"
