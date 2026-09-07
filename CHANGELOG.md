# Changelog

## V2.7.4

- **Key Attestation & Security:**
  - Preserved caller-selected AttestKey certificate chains natively without breaking parent-child cryptographic signatures.
  - Seamless StrongBox support: automatically utilizes genuine StrongBox keyboxes when available and routes standard TEE keys cleanly without duplicate errors or app crashes.
  - Optimized O(1) keybox classification: precomputed security level mapping ensures instant key selection without runtime overhead.
- **WebUI & User Experience:**
  - Added clear, mobile-friendly **StrongBox** and **TEE** badges next to keyboxes in the Keybox Hub, making it easy to identify keybox capabilities at a glance.
  - Localized remote server status messages for all supported interface languages.
- **Module Installation & Compatibility:**
  - Automatically detects and removes conflicting or outdated Play Integrity Fix modules during installation to prevent conflicts and ensure a clean setup.
- **Performance & Reliability:**
  - Faster keystore response times with zero delay when applications check certificates.
  - Consistent readback cache synchronization between key generation and entry queries.
