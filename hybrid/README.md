OpenSSL 3.5 ships ML-KEM and hybrid groups like X25519MLKEM768 (aka X25519+Kyber-768) out of the box; it even offers that hybrid by default as a TLS 1.3 keyshare. 

## 1) Prereqs
```
sudo apt-get update
sudo apt-get install -y build-essential perl git curl ca-certificates
```

## 2) Build & install OpenSSL 3.5 locally

#### pick a version (3.5.x)
```
curl -LO https://www.openssl.org/source/openssl-3.5.0.tar.gz
tar xzf openssl-3.5.0.tar.gz
cd openssl-3.5.0
```

#### install under ~/ossl-3.5 (don’t replace system OpenSSL)

```
./Configure --prefix=$HOME/ossl-3.5 --openssldir=$HOME/ossl-3.5 linux-x86_64
make -j"$(nproc)"
make install_sw
```

#### use it in this shell

```
export PATH="$HOME/ossl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/ossl-3.5/lib64:$HOME/ossl-3.5/lib:$LD_LIBRARY_PATH"

openssl version -a
```

## 3) Quick local hybrid TLS test (s_server/s_client)

Generate a throwaway cert (classical is fine; hybrid affects the key exchange, not the cert):

```
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -subj '/CN=localhost' -days 1
```

#### Terminal A — start a TLS 1.3 server and force the hybrid group:

```
openssl s_server -accept 4433 -tls1_3 \
  -cert cert.pem -key key.pem \
  -www -trace -groups X25519MLKEM768
```

#### Terminal B — connect with the same hybrid group:

```
openssl s_client -connect 127.0.0.1:4433 -tls1_3 \
  -servername localhost \
  -groups X25519MLKEM768 -brief -msg
```

You should see the handshake complete. Use -trace/-msg to confirm the KeyShare group is X25519MLKEM768, something like:0

```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=localhost
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
Verification error: self-signed certificate
Negotiated TLS1.3 group: X25519MLKEM768
```