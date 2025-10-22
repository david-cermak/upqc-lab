
# Shared KEM parameter selection (matches host)
set(UPQC_KEM_LEVEL "768" CACHE STRING "Select ML-KEM parameter set: 512 or 768")
set_property(CACHE UPQC_KEM_LEVEL PROPERTY STRINGS 512 768)

# Core liboqs and Kyber reference sources
set(kem_ref_SRCS
        liboqs/src/kem/kem.c
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
        kyber/ref/cbd.c)

# Add parameter-set specific wrappers from liboqs
if(UPQC_KEM_LEVEL STREQUAL "768")
    list(APPEND kem_ref_SRCS
        liboqs/src/kem/ml_kem/kem_ml_kem_768.c
        liboqs/src/kem/kyber/kem_kyber_768.c)
    set(_KYBER_K_VALUE 3)
else()
    list(APPEND kem_ref_SRCS
        liboqs/src/kem/ml_kem/kem_ml_kem_512.c
        liboqs/src/kem/kyber/kem_kyber_512.c)
    set(_KYBER_K_VALUE 2)
endif()

list(TRANSFORM kem_ref_SRCS PREPEND "../../../../impl/")

idf_component_register(SRCS
                            ${kem_ref_SRCS}
                            randombytes.c
                            mlkem768.c
        INCLUDE_DIRS        "."
                            "include"
)

# Propagate KEM choice and Kyber K
target_compile_definitions(${COMPONENT_LIB} PRIVATE KYBER_K=${_KYBER_K_VALUE})
target_compile_definitions(${COMPONENT_LIB} PRIVATE UPQC_KEM_LEVEL=${UPQC_KEM_LEVEL})
