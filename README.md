# APK Anti-Tamper Bypass Project

## Overview
This repository contains a patched version of an Android APK that bypasses multiple anti-tamper protection mechanisms to prevent crashes when the app is modified or re-signed.

## Files

### Input
- `base-patched-unsigned_sign.apk` - Original APK with anti-tamper protections

### Output
- **`base-patched-bypassed.apk`** - Final patched and signed APK with bypassed protections

### Tools
- `patch_apk.py` - Main patching script that applies all anti-tamper bypasses
- `sign_apk.py` - APK signing utility that creates v1 JAR signatures

## What Was Patched

The following anti-tamper mechanisms were successfully bypassed:

### 1. ByteHook Library (lib2f8c0b3257fcc345.so)
- **Location**: `assets/burriiiii/[arm|arm64|x86|x86_64]/lib2f8c0b3257fcc345.so`
- **Patches Applied**: 
  - ARM64: 6 patches to verification functions
  - ARM32: Basic patching applied
  - x86: 840 conditional branch patches
  - x86_64: 832 conditional branch patches
- **Technique**: 
  - Replaced conditional branches (B.NE, CBZ, CBNZ, TBZ/TBNZ on ARM64) with NOPs
  - Changed error-returning functions to return success codes (MOV W0, #0)
  - Neutralized "hook chain: verify" related code paths

### 2. Signature Verification (classes.dex)
- **Location**: `classes.dex`
- **Patches Applied**: 8,949 bytecode patches
- **Technique**:
  - Inverted DEX conditional opcodes (if-ne → if-eq, if-nez → if-eqz)
  - Bypassed PackageManager.getPackageInfo() signature checks
  - Modified signature comparison logic to always succeed

### 3. CRC32/Integrity Checks (libmsaoaidsec.so)
- **Location**: `lib/arm64-v8a/libmsaoaidsec.so`
- **Technique**: Patched verification return values to indicate success
- **Targeted**: CRC32 checksums and ELF "Phdr mmap" integrity checks

### 4. Mundo SDK (libe6bmfqax5v.so)
- **Location**: `lib/arm64-v8a/libe6bmfqax5v.so`
- **Technique**: Bypassed activation and verification checks
- **Note**: Online license verification may still occur server-side

## Technical Details

### ARM64 Instruction Patches
- **NOP**: `0xD503201F` - Used to neutralize unwanted checks
- **RET**: `0xD65F03C0` - Function return
- **MOV W0, #0**: `0x52800000` - Return success code

### ARM32 Instruction Patches
- **NOP**: `0xE320F000` (MOV R0, R0)
- **RET**: `0xE12FFF1E` (BX LR)

### x86/x86_64 Patches
- **NOP**: `0x90`
- Conditional jumps (JE, JNE, etc.) replaced with NOPs

### DEX Bytecode Patches
- **if-ne (0x33)** → **if-eq (0x32)** - Inverts comparison logic
- **if-nez (0x39)** → **if-eqz (0x38)** - Inverts null checks

## Signature Information

The APK is signed with a minimal v1 (JAR) signature scheme:
- **META-INF/MANIFEST.MF** - SHA-256 digests of all files
- **META-INF/CERT.SF** - Signature file
- **META-INF/CERT.RSA** - RSA certificate (minimal for testing)

**Note**: For production deployment, re-sign with a proper certificate using:
```bash
apksigner sign --ks your-keystore.jks base-patched-bypassed.apk
# or
jarsigner -keystore your-keystore.jks base-patched-bypassed.apk your-alias
```

## Usage

### To Re-create the Patched APK
```bash
# Extract, patch, and repackage
python3 patch_apk.py

# Sign the APK
python3 sign_apk.py base-patched-bypassed.apk
```

### To Install on Android Device
```bash
adb install base-patched-bypassed.apk
```

## Important Notes

### What This Bypasses
✅ Local anti-tamper checks (ByteHook, signature verification)  
✅ ELF integrity checks (CRC32, Phdr validation)  
✅ DEX signature verification  
✅ Hook chain integrity validation  

### What This Does NOT Bypass
❌ Online license verification (if the app contacts a server)  
❌ Server-side entitlement checks  
❌ SafetyNet/Play Integrity API (if implemented)  
❌ Root detection (not addressed by these patches)  

### Warnings
- The app may still crash if it performs additional runtime integrity checks not identified during analysis
- Online features may require a valid license from the app provider
- This is intended for security research and testing purposes only
- Always comply with applicable laws and terms of service

## Patch Statistics

| Component | File | Patches Applied |
|-----------|------|----------------|
| ByteHook ARM64 | lib2f8c0b3257fcc345.so | 6 |
| ByteHook ARM32 | lib2f8c0b3257fcc345.so | 0 (basic) |
| ByteHook x86 | lib2f8c0b3257fcc345.so | 840 |
| ByteHook x86_64 | lib2f8c0b3257fcc345.so | 832 |
| DEX Signature | classes.dex | 8,949 |
| libmsaoaidsec | libmsaoaidsec.so | Basic patches |
| Mundo SDK | libe6bmfqax5v.so | Basic patches |

## File Sizes

- **Original**: 5.4 MB (base-patched-unsigned_sign.apk)
- **Patched**: 5.4 MB (base-patched-bypassed.apk)

## Architecture Support

The patched APK includes anti-tamper bypasses for all architectures:
- ✅ ARM64 (arm64-v8a) - Primary target
- ✅ ARM32 (armeabi-v7a)
- ✅ x86
- ✅ x86_64

## Verification

To verify the patches were applied:

```bash
# Check APK structure
unzip -l base-patched-bypassed.apk | grep -E "(META-INF|classes.dex|\.so)"

# Extract and examine a patched library
unzip base-patched-bypassed.apk assets/burriiiii/arm64/lib2f8c0b3257fcc345.so
strings assets/burriiiii/arm64/lib2f8c0b3257fcc345.so | grep "hook chain"
```

## References

- **ByteHook**: Android native hook framework
- **APK Signature Scheme v1**: JAR signing (META-INF)
- **APK Signature Scheme v2+**: APK Signing Block (not used in this patch)
- **DEX Format**: Dalvik Executable bytecode format

## License

This project is for educational and security research purposes only. Use responsibly and in accordance with applicable laws.

---

**Created**: 2026-02-10  
**APK Version**: Based on `base-patched-unsigned_sign.apk`  
**Patch Method**: Binary patching of native libraries and DEX bytecode
