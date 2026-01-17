# WhisperPair - CVE-2025-36911

![CVE](https://img.shields.io/badge/CVE-2025--36911-critical)
![Type](https://img.shields.io/badge/Exploit-Protocol%20Logic-red)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Status](https://img.shields.io/badge/Status-PoC-orange)

**WhisperPair** Proof-of-Concept (PoC) for **CVE-2025-36911**, a vulnerability in the **Google Fast Pair Service (GFPS)**.

**Key Insight:** Vulnerable devices accept RAW unencrypted Key-Based Pairing requests even when NOT in pairing mode - no Anti-Spoofing Public Key required.

> **WARNING:** This tool is for security research and testing on YOUR OWN devices only.

## Vulnerability Overview (CVE-2025-36911)

The Fast Pair protocol contains an **Improper Access Control** vulnerability that allows an attacker to:

1. Send raw Key-Based Pairing (KBP) requests to devices NOT in pairing mode
2. Bypass the standard cryptographic handshake requirements
3. Extract the device's BR/EDR (Classic Bluetooth) address from the response
4. Force-pair via Classic Bluetooth without user interaction
5. Inject an arbitrary Account Key to hijack the device

### Impact

Once exploited, an attacker within BLE range (~30m) can:
- **Force-pair** with the target device without user consent
- **Hijack audio** via HFP/A2DP profiles (microphone access)
- **Track the device** via Find My Device / Find Hub networks
- **Persistent access** through injected Account Keys

## Features & Capabilities

The `fast_pair_demo.py` implementation provides:

- **Multiple Exploit Strategies:**
  - `RAW_KBP` - Raw unencrypted requests (most common for vulnerable devices)
  - `RETROACTIVE` - Retroactive pairing flag bypass
  - `EXTENDED_RESPONSE` - Extended response format requests

- **Automated Exploit Chain:**
  - BLE scanning for Fast Pair devices (0xFE2C UUID)
  - Model ID fingerprinting
  - Key-Based Pairing request injection
  - Response parsing with multiple strategies (standard, extended, encrypted, brute-force)
  - BR/EDR address extraction
  - Classic Bluetooth pairing via `bluetoothctl`
  - Account Key injection with AES-128-ECB encryption

- **Analysis Tools:**
  - Shannon entropy calculation for response analysis
  - MAC address validation
  - Notification logging with timestamps
  - JSON result export

## Installation

```bash
# Install dependencies
pip install bleak colorama cryptography

# Or use requirements.txt
pip install -r requirements.txt
```

## Usage

```bash
# Auto-scan and exploit the nearest Fast Pair device
python3 fast_pair_demo.py

# Target a specific device by MAC address
python3 fast_pair_demo.py AA:BB:CC:DD:EE:FF
```

### Example Output

```
╔══════════════════════════════════════════════════════════╗
║  WhisperPair PoC - CVE-2025-36911                        ║
║  Fast Pair Pairing Mode Bypass                           ║
╚══════════════════════════════════════════════════════════╝

[*] Scanning for Fast Pair devices (10s)...
[+] Found: Pixel Buds Pro (AA:BB:CC:DD:EE:FF) RSSI: -45

[!] KBP WRITE ACCEPTED - Device is VULNERABLE!
[+] BR/EDR Address: AA:BB:CC:DD:EE:FF
[+] Account Key written successfully!
[+] Pairing successful!
```

## Technical Reference

### GFPS Characteristics

| Characteristic | UUID | Purpose |
|---------------|------|---------|
| Model ID | `fe2c1233-8366-4814-8eb0-01de32100bea` | Device fingerprinting |
| Key-Based Pairing | `fe2c1234-8366-4814-8eb0-01de32100bea` | KBP request/response |
| Passkey | `fe2c1235-8366-4814-8eb0-01de32100bea` | Passkey verification |
| Account Key | `fe2c1236-8366-4814-8eb0-01de32100bea` | **Injection vector** |

### KBP Request Format (16 bytes)

| Byte | Field | Description |
|------|-------|-------------|
| 0 | Message Type | `0x00` = KBP Request |
| 1 | Flags | Bonding/Response options |
| 2-7 | Provider Address | Target BLE MAC |
| 8-15 | Salt | Random bytes (becomes shared secret) |

### Exploit Strategies

- **RAW_KBP (0x11):** Initiate bonding + extended response
- **RETROACTIVE (0x0A):** Retroactive pairing bypass
- **EXTENDED (0x10):** Request extended response format

## Running Tests

```bash
python3 -m pytest test_fast_pair_demo.py -v
```

## References

- [CVE-2025-36911](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-36911)
- [WhisperPair Research](https://whisperpair.eu)
- [Google Fast Pair Specification](https://developers.google.com/nearby/fast-pair/spec)

## License

MIT License. For authorized security research only.
