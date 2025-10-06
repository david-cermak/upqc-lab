// Shared configuration for selecting ML-KEM parameter set across host and target
// Default to 512 if not specified at build time via -DUPQC_KEM_LEVEL=...
#ifndef UPQC_CONFIG_H
#define UPQC_CONFIG_H

// Expect UPQC_KEM_LEVEL as numeric 512 or 768
#ifndef UPQC_KEM_LEVEL
#define UPQC_KEM_LEVEL 512
#endif

// Normalize invalid values to 512
#if (UPQC_KEM_LEVEL != 512) && (UPQC_KEM_LEVEL != 768)
#undef UPQC_KEM_LEVEL
#define UPQC_KEM_LEVEL 512
#endif

// Derive names and parameters
#if (UPQC_KEM_LEVEL == 768)
#define UPQC_KYBER_K 3
#define UPQC_KEM_NAME "ML-KEM-768"
#define UPQC_OQS_KEM_ALG OQS_KEM_alg_ml_kem_768
#else
#define UPQC_KYBER_K 2
#define UPQC_KEM_NAME "ML-KEM-512"
#define UPQC_OQS_KEM_ALG OQS_KEM_alg_ml_kem_512
#endif

#endif // UPQC_CONFIG_H

