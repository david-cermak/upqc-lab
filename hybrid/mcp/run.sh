source /home/david/esp/idf/export.sh
cd /home/david/repos/upqc-lab/hybrid/target_client
export LD_LIBRARY_PATH="/home/david/ossl-3.5/lib64:/home/david/ossl-3.5/lib:$LD_LIBRARY_PATH"
export PATH="/home/david/ossl-3.5/bin:$PATH"

idf.py build
if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi

openssl s_server -accept 8443 -cert server.crt -key server.key -tls1_3 -groups X25519MLKEM768 -www -msg -debug &
sleep 1
./build/https_mbedtls.elf
pkill -f openssl
