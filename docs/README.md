Updated Agenda — Adopting Post-Quantum Algorithms for Embedded Systems

(~30 minutes total, 1–2 min buffer for Q&A)

1. Introduction — Why Post-Quantum, Why Now (≈ 3 min)

What post-quantum cryptography (PQC) is and why it matters

Embedded/IoT devices: long lifetime, hard to patch, trusted roots that must remain valid for decades

Overview of talk and live demos

2. The Quantum Threat Landscape (≈ 3 min)

How quantum computing breaks classical public-key crypto (RSA, ECC, ECDSA)

“Harvest-Now, Decrypt-Later” — attackers collecting data today to decrypt in the future

“Sign-Today, Forge-Tomorrow” — firmware signing & secure-boot threats

3. Firmware Signing, Secure Boot & OTA Update Risks (NEW — ≈ 4 min)

Devices verify firmware using signatures — if those (RSA/ECDSA) are broken, a quantum-enabled attacker could forge signatures

Result: attacker uploads malicious firmware via OTA or local update; device accepts it as legitimate

This directly compromises the root of trust — secure channel encryption doesn’t help if firmware is replaced

Implications for long-lived embedded systems (industrial, automotive, consumer IoT)

Mitigations:

Adopt PQC signature schemes (e.g. ML-DSA / Dilithium, SLH-DSA / SPHINCS+)

Plan for hybrid signatures during migration

Ensure algorithm agility in bootloaders and update verifiers

4. PQC Building Blocks & Standards (≈ 4 min)

Key Encapsulation Mechanisms (KEMs): ML-KEM 512 / 768 / 1024

PQC Signatures: ML-DSA, SLH-DSA (SPHINCS+), Falcon (optional)

Standardization status: NIST FIPS 203 / 204 / 205, IETF drafts, hybrid modes

Hybrid crypto rationale: gradual migration (classical + PQC)

5. Embedded Constraints & Integration Challenges (≈ 3 min)

Limited RAM/flash, performance and energy budgets

Firmware signing footprint (signature + public key sizes)

Side-channel and fault-injection resistance

Hardware acceleration and potential firmware library optimizations

6. Demo #1 — Dedicated Secure Channel with ML-KEM-512 + AES128-GCM (≈ 4 min)

Show server-client key exchange using ML-KEM-512

Derive symmetric key → AES128-GCM data channel

Highlight: small changes in stack, manageable overhead, migration feasibility

7. Demo #2 — Full TLS 1.3 Hybrid Group X25519 + ML-KEM-768 (≈ 5 min)

Hybrid handshake sequence demonstration

Discuss interoperability and handshake latency

Highlight: drop-in replacement potential for embedded TLS stacks

8. System-Level Migration Strategy (≈ 3 min)

Layered view: Boot → Firmware → Update → Transport

Start from root of trust (firmware signing) before upgrading network layer

Use hybrid approach across layers

Certification and compliance (NIST, ETSI, EU CRA quantum-safe guidance)

9. Key Takeaways & Outlook (≈ 2 min)

PQC is not future-talk anymore; migration must start now

Firmware signing and OTA update security are first-line priorities

Hybrid deployments = realistic adoption path

Demos prove feasibility on real embedded targets