source /home/david/esp/idf/export.sh
cd /home/david/repos/upqc-lab/hybrid/target_client
idf.py build
if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi
timeout 2 ./build/https_mbedtls.elf
echo "Client stopped"
pkill -f openssl
echo "Server stopped"
