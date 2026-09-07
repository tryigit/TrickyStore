# Changelog

## V2.7.4

- **Key Attestation & Security:**
  - Unified attestation certificate rewriting: eliminated RootOfTrust divergence across default and custom AttestKey key generation requests while strictly synthesizing verified boot state (`deviceLocked = true`, `verifiedBootState = Verified`, matching `vbmeta.digest`).
  - Preserved caller-selected AttestKey certificate chains natively without breaking parent-child cryptographic signatures.
  - Seamless StrongBox support: automatically utilizes genuine StrongBox keyboxes when available and routes standard TEE keys cleanly without duplicate errors or app crashes.
  - Hardened module integrity protection: transitioned integrity verification to startup-only quarantine, preventing accidental module self-deletion during concurrent write churn.
  - Optimized O(1) keybox classification: precomputed security level mapping ensures instant key selection without runtime overhead.
- **WebUI & User Experience:**
  - Added clear, mobile-friendly **StrongBox**, **TEE**, and **RKP** badges next to keyboxes in the Keybox Hub, making it easy to identify keybox capabilities at a glance.
- **Module Installation & Compatibility:**
  - Automatically detects and removes conflicting or outdated third-party attestation modules during installation to prevent conflicts and ensure a clean setup.
- **Performance & Latency:**
  - Eliminated key generation timing side-channels by deferring X.509 leaf parsing via lazy wrappers and streaming reply parcel serialization in-place without intermediary allocations.
  - Streamlined high-frequency Binder transaction reply paths: purged logging, reflection, and redundant memory copies from latency-critical key generation routines.
  - Faster keystore response times with pre-encoded issuer chain caching and consistent readback cache synchronization.
