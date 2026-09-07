# Changelog

## V2.7.4

- **Key Attestation & Security:**
  - Unified attestation certificate rewriting: eliminated RootOfTrust divergence across default and custom AttestKey requests, ensuring consistent device and bootloader state spoofing.
  - Preserved caller-selected AttestKey certificate chains natively without breaking certificate signatures.
  - Seamless StrongBox support: automatically utilizes genuine StrongBox keyboxes when available and routes standard TEE keys cleanly without duplicate errors or app crashes.
  - Hardened module integrity protection: prevents accidental module self-deletion during high filesystem churn.
  - Instant keybox selection: optimized security level detection for faster key creation.
- **WebUI & User Experience:**
  - Added clear, mobile-friendly **StrongBox**, **TEE**, and **RKP** badges next to keyboxes in the Keybox Hub, making it easy to identify keybox capabilities at a glance.
- **Module Installation & Compatibility:**
  - Automatically detects and removes conflicting or outdated third-party attestation modules during installation to prevent conflicts and ensure a clean setup.
- **Performance & Latency:**
  - Significantly reduced key generation latency and timing-side-channel exposure during attestation checks.
  - Streamlined keystore background transactions by eliminating unnecessary memory allocations and logging overhead.
  - Faster keystore response times with pre-cached certificate chains and synchronized readback.
