Post-Quantum Secure Boot and Firmware Signatures for IoT
Image: NIST illustration of classical (left) vs. post-quantum (right) encryption standards. As quantum computers advance, they threaten classic public-key schemes (RSA, ECDSA, etc.) by breaking their hard math assumptions. NIST has therefore standardized new post-quantum cryptography (PQC) algorithms (e.g. CRYSTALS-Dilithium and -Kyber) to replace vulnerable schemes
pqshield.com
nist.gov
. In practice, secure boot chains on IoT microcontrollers (ESP32, STM32, etc.) must be upgraded to verify firmware using quantum-safe signatures instead of RSA/ECDSA. The U.S. CNSA 2.0 guidance even mandates that “by 2025, the first PQC use case should be software signing and firmware signing”
pqshield.com
. In other words, IoT devices powered on after 2025 should verify firmware images with PQC algorithms at the hardware root-of-trust. Secure boot works by embedding trusted public keys in ROM or OTP, then checking each firmware stage’s digital signature at boot
pqshield.com
. A quantum-safe secure boot simply swaps in PQC signature schemes for the key verification step. For example, an MCU bootloader could store a PQC public key (say, a Dilithium key) and verify the firmware image’s post-quantum signature before executing it. This ensures that even if an attacker could later build a quantum computer, they could not forge a valid firmware image without breaking the PQC algorithm. Flash encryption (e.g. AES-XTS on ESP32) is orthogonal: it still uses symmetric AES, which remains safe by doubling key size (e.g. AES-256) against Grover’s attack. PQC typically enters in key exchange or authentication, not in-line flash encryption.
Post-Quantum Digital Signature Algorithms
Several families of PQC signature schemes are relevant:
Lattice-based (ML-DSA / Dilithium): The NIST standard Crystals-Dilithium (now called ML-DSA) is a stateless lattice signature offering strong security and reasonable performance. It generates and verifies signatures much like RSA/ECDSA but with larger keys. Unlike hash-based schemes, it allows an unlimited number of signatures with the same key, making it suitable for general use and protocol agility
wiki.st.com
. The downside is size and performance: keys and signatures are larger (e.g. a few KB) and signature generation can have unbounded time due to rejection sampling
wiki.st.com
.
Hash-based (XMSS/LMS): Stateful schemes like XMSS (eXtended Merkle Signature Scheme) and LMS (Leighton-Micali) use Merkle trees of one-time hash signatures. They produce relatively small signatures (often hundreds of bytes), and verification is very fast and side-channel resistant. However, they are stateful: each key pair can only sign a limited number of messages (the number of one-time keys). This is acceptable for secure boot, which signs firmware updates infrequently (e.g. dozens of updates over a device lifetime)
wiki.st.com
. Hash-based signatures require secure state management (to avoid re-using one-time keys) but are extremely simple and well-studied. In fact, ST’s documentation notes that LMS/XMSS “are suggested” for secure boot, since a device only verifies a signature limited times (e.g. per-boot) and does not need unlimited signing
wiki.st.com
. Importantly, hash-based schemes like LMS and XMSS do not need to be hybridized with a classical algorithm; France and Germany allow their direct use, though U.S. CNSA 2.0 forbids using stateful hash schemes (SLH-DSA) without a classical component
pqshield.com
.
Other PQC schemes: NIST also standardized the Dilithium/KEM family (ML-DSA and ML-KEM) for general use, and the SIKE/Kyber for encryption. Falcon (a lattice scheme) and SPHINCS+ (stateless hash-based) were finalists but are not yet in federal standards. For KEMs (key encapsulation), CRYSTALS-Kyber is the selected standard; it can replace RSA key exchange or be used to encrypt symmetric keys. In IoT TLS or device authentication, schemes like Kyber or SIKE can be used alongside signatures for key agreement
wolfssl.com
.
Overall, design choice depends on the use case. For firmware signing and secure boot, hash-based signatures (LMS/XMSS) are attractive: they offer fast verification (often hardware-accelerated with hash engines), well-studied security, and require no hybrid backup
wiki.st.com
. ML-DSA (Dilithium) is also viable if unlimited signatures are needed, but its signature generation can stall (rarely) due to its probabilistic algorithm
wiki.st.com
.
Hybrid PQC and Crypto Agility
Many practitioners advocate a hybrid signature scheme during the transition. In a PQ/T hybrid, each firmware image is signed by both a classical algorithm (e.g. ECDSA or RSA-PSS) and a PQC algorithm
pqshield.com
. The bootloader then verifies both signatures. This provides backward compatibility and defense in depth: if the PQC scheme is later found weak, the classical part still holds (or vice versa). The U.S. CNSA 2.0 framework mandates such PQ/T hybrids for signatures, to ensure smooth migration
pqshield.com
pqshield.com
. Many governments (and IoT vendors) thus plan to combine, for example, an ECDSA signature with a Dilithium signature on the same firmware blob. Hybrid schemes have trade-offs: they double the cost of verification (the bootloader must do, say, two public-key checks) and increase signature size. PQShield notes that PQ/T hybrids “increase latency” (since you run two verifications instead of one) and can complicate future upgrades
pqshield.com
. On the other hand, they allow “crypto agility”: firmware images carry multiple signatures, so devices can add or drop keys/algorithms over time without replacing hardware. For closed systems (e.g. military), it might be feasible to drop classical keys entirely once PQC is trusted; for open IoT fleets, a longer hybrid period is likely. Many standards bodies in Europe currently recommend hybridization for safety
pqshield.com
. Notably, some IoT secure-boot solutions natively support hybrids. For example, WolfSSL’s wolfBoot loader explicitly supports “hybrid authentication (PQC + classic)”
wolfssl.com
. In other words, wolfBoot can verify a firmware image that has, say, an ECDSA-256 signature and an XMSS signature, rejecting the image unless both checks pass (or according to the configured policy). WolfBoot documentation highlights that it supports both classic (ECDSA, RSA) and PQC (LMS/XMSS, ML-DSA) algorithms together
wolfssl.com
wolfssl.com
. In practice, hybrid signing might be implemented by simply concatenating two signatures or by signing metadata that includes the other signature. Toolchains and key-management systems will need to evolve accordingly. The upside is strong security: an adversary would need to break both a classical key and a PQ key to fake firmware.
Implementations and Tool Support
Several concrete implementations and libraries now provide PQC for firmware signing on microcontrollers:
WolfSSL / wolfBoot: A popular embedded TLS and crypto library, WolfSSL has extended its wolfCrypt engine with PQC. Its secure bootloader wolfBoot is open-source and supports a range of algorithms. WolfBoot “offers Post-Quantum options including hash-based signature schemes” and complies with CNSA 2.0
wolfssl.com
. It supports LMS/HSS, XMSS (including multi-tree XMSS^MT) and ML-DSA (Dilithium) up to NIST level 5
wolfssl.com
. It even lists “support for hybrid authentication (PQC + classic)” as a feature
wolfssl.com
. wolfBoot is portable to many architectures (ARM Cortex-M, Cortex-A, RISC-V, etc.), including STM32 and other IoT MCUs
wolfssl.com
. It also provides host-side tools (wolfBoot sign, wolfBoot keygen) to manage PQC keys and signatures. Importantly, wolfBoot can use hardware crypto (STM32-PKA, TPM, etc.) to accelerate verification, so even large PQC signatures are feasible at boot
wolfssl.com
wolfssl.com
.
ST X-CUBE-PQC: STMicroelectronics offers an expansion package for STM32 microcontrollers called X-CUBE-PQC. This library includes implementations of PQC algorithms alongside ST’s existing cryptolib. It specifically provides LMS/XMSS verification for secure boot authentication and ML-DSA signature generation/verification for general use
st.com
. The product description notes that “LMS and XMSS verification methods” are used “mainly for secure boot code authentication”
st.com
. It also includes ML-KEM (Kyber) for key exchange and ML-DSA for signatures, certified by NIST’s validation program
st.com
. In other words, STM32 developers can download X-CUBE-PQC to enable Dilithium or XMSS checks on-chip. ST even provides example code using the STM32 crypto accelerator to verify LMS/XMSS signatures and perform ML-DSA operations
st.com
. This makes it a practical solution for STM32H5/M33 platforms.
PQShield PQMicroLib-Core: PQShield (a leading PQC company) offers a bare-metal PQC library PQMicroLib-Core designed for constrained devices
pqshield.com
. It claims to fit in as little as 13 KB RAM on a microcontroller and even provides side-channel protections
pqshield.com
. Its “Key Benefits” highlight support on low-end MCUs, constant-time implementations, and optional use of hardware accelerators
pqshield.com
. PQMicroLib-Core is “CAVP-Ready” and supports the CNSA 2.0 algorithms (e.g. ML-DSA, LMS, XMSS)
pqshield.com
. The PQShield product page explicitly lists “Secure Boot” and “Secure Firmware Updates (OTA)” as common use cases
pqshield.com
. In short, PQShield provides a highly optimized PQC stack for ARM Cortex-M and similar IoT chips, enabling vendors to add PQ signatures even on deeply embedded devices.
Quantropi QiSpace (STM32): Quantropi is a security startup partnering with ST. Their QiSpace platform offers PQC solutions for IoT. According to ST’s blog, Quantropi’s uLoadXLQ product “protects firmware at startup by adding a quantum secure digital signature to the bootloader”, and it integrates with STM32’s Secure Boot mechanism
blog.st.com
. ST notes that Quantropi’s tools (integrated with STM32CubeMX) allow support for nearly all STM32 MCUs
blog.st.com
. In fact, Quantropi has reportedly deployed a PQC-enabled bootloader on STM32H7 hardware for a customer
blog.st.com
. While not an open-source library, this shows that commercial PQC solutions are reaching real STM32 products.
TLS/Crypto Libraries: More generally, many cryptographic libraries have begun adding PQC support. For example, WolfSSL’s TLS stack can use Kyber for key exchange on ESP32
wolfssl.com
, and liboqs (Open Quantum Safe) can be integrated into OpenSSL or mbed TLS. Mbed TLS itself is taking a cautious approach: as of 2023 the maintainers plan to “wait until there are official standards” before adding PQC beyond stateful hash-based signatures
mbed-tls.readthedocs.io
. However, experiments and third-party ports exist. The key point is that lightweight TLS or crypto engines on microcontrollers can now accommodate PQC schemes (often through conditional compilation flags or hardware accelerators).
Hardware and Secure Elements: Some chip vendors are planning hardware PQC support. For example, Microchip’s new PIC64-HPSC includes crypto modules for ML-DSA and ML-KEM
ir.microchip.com
. Likewise, dedicated security chips (SEPs) or TPMs may eventually include PQC algorithms. But for now, most PQC is done in software on MCUs.
Below is a summary of sample solutions and libraries:
WolfSSL/wolfBoot: Open-source secure bootloader supporting PQC (LMS/XMSS, ML-DSA) and hybrids
wolfssl.com
wolfssl.com
.
ST X-CUBE-PQC: STM32Cube expansion with LMS/XMSS verification and ML-DSA
st.com
.
PQShield PQMicroLib: Bare-metal PQC library fitting in <32 KB for secure boot/FWU
pqshield.com
pqshield.com
.
Quantropi QiSpace: Commercial PQC framework integrated via STM32CubeMX, used on STM32H7/MCUs
blog.st.com
blog.st.com
.
mbed TLS / WolfSSL: TLS engines with optional PQC (wolfSSL already has Kyber/Dilithium; mbed TLS plans to add standardized PQC).
Secure Elements/TPMs: Future support for PQC (ST PMA, Microchip ATECC/PQ).
ESP-IDF Tools: Currently ESP32’s IDF uses RSA/ECDSA for secure boot. No built-in PQC yet, but developers can integrate external libraries (wolfSSL, PQShield) to add PQC support for signatures or TLS.
Hybrid Signatures and Migration
As noted, hybrid signatures combine a PQC signature with a classical signature. In one common approach, the firmware image contains both signatures appended. The bootloader then checks them sequentially. For example, an ESP32 secure bootloader could verify an ECDSA-256 signature on the firmware header and then verify an XMSS signature on the same image. Only if both verifications pass does the boot continue. WolfBoot explicitly supports such hybrid authentication
wolfssl.com
. This way, existing devices can trust either component, and during a transition period both classical and post-quantum trust anchors are maintained. However, hybrid schemes double the code and data overhead: two signature verification routines must be included, and keys for both algorithms stored (e.g. in OTP). PQShield observes that this “increases latency” at boot
pqshield.com
. In constrained IoT, extra CPU cycles and flash space are at a premium. Manufacturers must judge whether the extra assurance is worth the cost. In high-security or regulated settings, hybrid is usually required by policy. In consumer IoT, some may opt to trust a proven PQC and drop classical keys sooner. Crypto agility is also a consideration. If devices can update keys, the system could start with hybrid PQC+ECDSA, then later stop verifying ECDSA (once classical crypto is considered unsafe). This requires a firmware update mechanism that can revoke old keys or algorithms – a nontrivial bootloader design challenge. Many PQC discussions emphasize planning for algorithm changes (e.g. using key identifiers, versioning, or multiple public key slots).
Considerations and Drawbacks of PQC Signatures
While PQC ensures long-term security, it introduces practical challenges on IoT MCUs:
Signature and Key Size: PQC keys and signatures are much larger than classical. For instance, an XMSS-LMS signature can be several kilobytes, and Dilithium signatures ~2–3 KB, versus a few hundred bytes for ECDSA
st.com
wiki.st.com
. This consumes more flash/storage and bandwidth (if firmware is OTA-downloaded). Public keys also bloat: a Dilithium public key ~2–4 KB. Bootloaders and key stores must allocate for these sizes.
Performance: Verification of PQC signatures is generally slower than ECDSA on the same hardware. Although accelerated hash engines help for XMSS, verifying many Merkle-tree paths can cost time. Dilithium verification is faster than signing, but still heavier than ECC. In a secure-boot context (one check per boot), the extra milliseconds may be acceptable, but in a rapid reboot or real-time system it could matter. PQC signature generation (done off-chip by the signer) can be very slow or unpredictable (especially Dilithium, which may retry many times
wiki.st.com
). This means firmware images must be signed on a powerful host, not on-device.
Stateful keys: Hash-based (LMS/XMSS) require strict state management. If a device loses power or resets unexpectedly, the counter of used one-time keys must be preserved to avoid re-use (which would catastrophically break security). Bootloaders must safely store and update this state (for example, in non-volatile memory after each update). This is a new operational complexity compared to stateless schemes. It also limits the total number of updates (e.g. 2^20 for an XMSS256 tree) before a new key pair is needed. For most IoT devices, tens of thousands of updates are plenty, but the designer must account for this.
Implementation readiness: PQC algorithms are relatively new. Library support on microcontrollers is still maturing. As mentioned, mbed TLS is not yet shipping ML-DSA or Dilithium by default
mbed-tls.readthedocs.io
, awaiting final standards and parameters. This means out-of-the-box support on many IoT platforms is limited. Developers may need to integrate third-party or proprietary libraries (as described above). Side-channel security is another concern: robust constant-time implementations are essential. PQShield’s PQMicroLib touts “DPA protection” and constant-time code
pqshield.com
; WolfBoot uses constant-time for HPC on M33, etc. Auditing and compliance (FIPS/CAVP testing) is still catching up for PQC.
Bootloader complexity: Integrating a new signature algorithm means updating the entire boot chain. Existing bootloaders (like Espressif’s secure boot V2) assume ECDSA/RSA and specific signature formats. To use PQC, one must modify or replace the bootloader to parse and run the new algorithms. WolfBoot is one option; otherwise OEMs must fork SDKs or wait for official support. Some vendors (e.g. ST) are working with partners like Quantropi to co-design this integration.
blog.st.com
blog.st.com
.
Hybrid overhead: As noted, doing PQ/T hybrid doubles the work and code. Some systems may not justify this overhead. Organizations like France/Germany allow skipping hybrid for well-understood hash-based schemes
pqshield.com
, so one might sign solely with LMS/XMSS on devices intended for that environment. Otherwise, most guides urge hybrid compliance at least until PQC is proven.
Quantum vulnerability margins: Some PQC schemes are believed secure today, but future cryptanalysis could weaken them. Relying on any single new algorithm carries risk. Lattice problems (Dilithium/Kyber) have not been broken so far, but research continues. Hash-based (XMSS) rely only on hash security, which is more conservative. Hence another reason to combine algorithms (multi-algo safety).
Despite these challenges, the consensus is clear: firmware signing is the first major PQC use case in devices
pqshield.com
. Toolkits and examples are emerging to make implementation practical. For instance, WolfSSL’s example shows enabling Kyber on ESP32 with just a few config flags
wolfssl.com
, implying that similarly one could enable Dilithium or LMS support. Developers should prototype early: even if devices aren’t fielded until later, building the capability now is key.
Flash Encryption and PQC
While the focus is on signatures, it is worth briefly discussing flash encryption. Many MCUs (ESP32, STM32H7, etc.) support hardware flash encryption (XTS-AES or similar) to keep code/data at rest encrypted. These schemes use symmetric keys (often 128- or 256-bit AES). Quantum computers do speed up brute-force attacks via Grover’s algorithm, roughly halving the security per key bit. In practice, AES-128 would drop to an effective 64-bit against a quantum attack, which is marginally safe. Many vendors already use AES-256 for flash encryption; this gives ~128-bit post-quantum strength (since 256/2=128). Thus, symmetric flash encryption remains viable by choosing a large key. No fundamental change is needed, though devices should migrate to AES-256 if not already. PQC KEMs (like Kyber) could be used to manage or exchange keys for encrypted flash in some architectures, but on-chip key storage (e.g. in eFuse) is more common.
Key Takeaways
PQC signatures are necessary for future-proof secure boot. Algorithms like CRYSTALS-Dilithium (ML-DSA) and hash-based XMSS/LMS provide viable options.
Hash-based schemes (XMSS/LMS) are particularly well-suited to firmware signing: fast verification, simple security, and no needed hybridization
wiki.st.com
.
Lattice-based schemes (Dilithium/ML-DSA) offer unlimited signing at the cost of larger signatures and potential latency variability
wiki.st.com
.
Hybrid PQ/T schemes (e.g. Dilithium+ECDSA) are often required by policy. They double the verification overhead, but ease transition
pqshield.com
.
Tool and library support is growing: ST’s X-CUBE-PQC and Quantropi address STM32, WolfBoot addresses generic MCUs, PQShield offers tiny libraries, and TLS stacks (wolfSSL, OpenSSL with OQS) support KEM/signature.
Pitfalls include larger code size, slower boots, key/state management, and the need for crypto agility. Thorough testing and side-channel security are crucial. Developers should start experimenting now, using available PQC libraries on their target hardware.
By carefully choosing algorithms, employing hybrids when needed, and leveraging emerging PQC libraries, IoT vendors can implement quantum-safe secure boot. This ensures that future quantum computers – whenever they arrive – will not allow attackers to stealthily overwrite firmware and compromise devices. Sources: Authoritative blogs and documentation from STMicroelectronics, PQShield, WolfSSL, and NIST have been consulted. Key references include PQShield’s discussion of secure boot
pqshield.com
pqshield.com
, ST’s X-CUBE-PQC overview
st.com
, and WolfSSL’s wolfBoot product page
wolfssl.com
, among others. These detail the algorithms used (LMS, XMSS, ML-DSA), hybrid strategies, and example implementations on STM32/ESP32 platforms.
