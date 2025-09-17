
set(kem_ref_SRCS liboqs/src/kem/kem.c
        liboqs/src/kem/kyber/kem_kyber_512.c
        liboqs/src/common/common.c
        kyber/ref/kem.c
        kyber/ref/fips202.c
        kyber/ref/symmetric-shake.c
        kyber/ref/indcpa.c
        kyber/ref/poly.c
        kyber/ref/polyvec.c
        kyber/ref/ntt.c
        kyber/ref/verify.c
        kyber/ref/reduce.c
        kyber/ref/randombytes.c
        kyber/ref/cbd.c)

list(TRANSFORM kem_ref_SRCS PREPEND "../../../impl/")

idf_component_register(SRCS "target.c" "client.c" "crypto_backend_custom_pqc.c"
        ${kem_ref_SRCS}
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/kem.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/kem.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/kyber/kem_kyber_512.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/common/common.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/fips202.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/symmetric-shake.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/indcpa.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/poly.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/polyvec.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/ntt.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/verify.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/reduce.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/randombytes.c"
#        "/home/david/repos/upqc-lab/impl/kyber/ref/cbd.c"
#

#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/kyber/kem_kyber_768.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/kyber/kem_kyber_1024.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/classic_mceliece/kem_classic_mceliece_348864.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/classic_mceliece/kem_classic_mceliece_460896.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/classic_mceliece/kem_classic_mceliece_6688128.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/classic_mceliece/kem_classic_mceliece_6960119.c"
#        "/home/david/repos/upqc-lab/impl/liboqs/src/kem/classic_mceliece/kem_classic_mceliece_8192128.c"
                    INCLUDE_DIRS "." #"../../host/build/liboqs/include"
        "include"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE KYBER_K=2)