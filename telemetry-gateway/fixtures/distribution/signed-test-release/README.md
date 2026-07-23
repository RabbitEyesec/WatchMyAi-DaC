# Signed synthetic test release

This directory is a static, offline-only release for preflight and isolated-lab bootstrap checks. It contains a strict default-deny policy plus the complete Ed25519 root, targets, snapshot, and timestamp verification chain.

The root requires two distinct signatures. Targets, snapshot, and timestamp use distinct role keys. Only public keys and signatures are committed; the randomly generated private keys were discarded. The metadata has deliberately long fixture expirations so a clean checkout remains reproducible.

Do not promote this organization, trust root, or policy outside an isolated test lab. A real deployment must enroll its own organizational root and freshly issued metadata through the documented signed-distribution ceremony.
