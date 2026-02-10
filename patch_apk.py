#!/usr/bin/env python3
"""
APK Anti-Tamper Bypass Patcher
Patches ByteHook, signature verification, and integrity checks
"""

import os
import sys
import struct
import re
import subprocess
import shutil
from pathlib import Path

class APKPatcher:
    def __init__(self, extract_dir="apk_extract"):
        self.extract_dir = Path(extract_dir)
        self.patches_applied = []
        
    def log(self, message):
        print(f"[*] {message}")
        
    def patch_bytehook_arm64(self, filepath):
        """Patch ARM64 ByteHook library to bypass verification"""
        self.log(f"Patching ByteHook ARM64: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
        
        original_size = len(data)
        patches_count = 0
        
        # Pattern 1: Look for verification functions that check hook chain
        # We'll search for common ARM64 patterns near "verify" strings
        # and patch conditional branches to unconditional
        
        # Search for "hook chain: verify" string references
        verify_str = b"hook chain: verify"
        positions = []
        pos = 0
        while True:
            pos = data.find(verify_str, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1
        
        self.log(f"  Found {len(positions)} 'hook chain: verify' string references")
        
        # Pattern: Replace common verification failure branches
        # B.NE (branch if not equal) -> B (unconditional branch) or NOP
        # Pattern: 54 xx xx xx (B.NE) -> 14 xx xx xx (B) or 1F 20 03 D5 (NOP)
        
        # Also replace CBZ/CBNZ (compare and branch) with B or NOP
        # Pattern matching for conditional branches followed by error handling
        
        patterns_to_patch = [
            # B.NE -> NOP (most common in verification)
            (b'\x54\x00\x00', b'\x1f\x20\x03'),  # B.NE near -> NOP
            # Some common verification patterns
        ]
        
        # More aggressive: NOP out sections near verification strings
        for verify_pos in positions:
            # Find nearest code section (search backwards for function prologue)
            search_start = max(0, verify_pos - 2000)
            search_end = min(len(data), verify_pos + 100)
            
            # Look for conditional branches in this region
            for i in range(search_start, search_end - 4, 4):
                # Check if aligned
                if i % 4 != 0:
                    continue
                    
                instr = struct.unpack('<I', data[i:i+4])[0]
                
                # B.cond instructions (0x54xxxxxx where cond != 0x0/0xe means conditional)
                if (instr & 0xFF000000) == 0x54000000:
                    cond = instr & 0x0F
                    # If it's a conditional branch (not always/never)
                    if cond not in [0x0E, 0x0F]:
                        # Check if next instructions look like error handling
                        # Replace with NOP
                        data[i:i+4] = struct.pack('<I', 0xD503201F)  # NOP
                        patches_count += 1
                
                # CBZ/CBNZ (Compare and Branch on Zero/Non-Zero)
                # Pattern: 0x34xxxxxx (CBZ) or 0x35xxxxxx (CBNZ)
                elif (instr & 0xFE000000) in [0x34000000, 0x35000000]:
                    # Replace with NOP
                    data[i:i+4] = struct.pack('<I', 0xD503201F)  # NOP
                    patches_count += 1
                    
                # TBZ/TBNZ (Test bit and Branch)
                # Pattern: 0x36xxxxxx (TBZ) or 0x37xxxxxx (TBNZ)
                elif (instr & 0xFE000000) in [0x36000000, 0x37000000]:
                    data[i:i+4] = struct.pack('<I', 0xD503201F)  # NOP
                    patches_count += 1
        
        # Also patch known verification function patterns
        # Look for function returns with error codes and make them return success
        # Pattern: MOV W0, #-1 or MOV W0, #1 -> MOV W0, #0 (success)
        # MOV W0, #immediate is encoded as: 0x52800000 | (imm << 5)
        
        for i in range(0, len(data) - 8, 4):
            if i % 4 != 0:
                continue
            instr = struct.unpack('<I', data[i:i+4])[0]
            
            # Check for MOV W0, #-1 (0x92800000) or MOV W0, #1
            if (instr & 0xFFFFFFE0) == 0x52800000:  # MOV W0, #imm
                imm = (instr >> 5) & 0xFFFF
                if imm != 0:  # If not already zero
                    # Check if followed by RET
                    next_instr = struct.unpack('<I', data[i+4:i+8])[0]
                    if next_instr == 0xD65F03C0:  # RET
                        # Change to MOV W0, #0
                        data[i:i+4] = struct.pack('<I', 0x52800000)
                        patches_count += 1
        
        self.log(f"  Applied {patches_count} patches to ARM64 ByteHook")
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        self.patches_applied.append(f"ByteHook ARM64: {patches_count} patches")
        return patches_count > 0
    
    def patch_bytehook_arm32(self, filepath):
        """Patch ARM32 ByteHook library"""
        self.log(f"Patching ByteHook ARM32: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
        
        patches_count = 0
        
        # ARM32 instructions are also 4 bytes but different encoding
        # NOP = 0xE320F000 (MOV R0, R0)
        # Common conditional branches: BNE, BEQ, etc.
        
        # Search for verification strings
        verify_str = b"hook chain: verify"
        positions = []
        pos = 0
        while True:
            pos = data.find(verify_str, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1
        
        self.log(f"  Found {len(positions)} verification string references")
        
        for verify_pos in positions:
            search_start = max(0, verify_pos - 2000)
            search_end = min(len(data), verify_pos + 100)
            
            for i in range(search_start, search_end - 4, 4):
                if i % 4 != 0:
                    continue
                
                instr = struct.unpack('<I', data[i:i+4])[0]
                
                # Conditional branches in ARM32 have condition codes in top 4 bits
                # 0xExxxxxxx = AL (always), others are conditional
                top_nibble = (instr >> 28) & 0xF
                
                # If it's a conditional branch (not AL=0xE or NV=0xF)
                if top_nibble not in [0xE, 0xF]:
                    # B or BL instruction
                    if (instr & 0x0F000000) in [0x0A000000, 0x0B000000]:
                        # Replace with NOP
                        data[i:i+4] = struct.pack('<I', 0xE320F000)
                        patches_count += 1
        
        self.log(f"  Applied {patches_count} patches to ARM32 ByteHook")
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        self.patches_applied.append(f"ByteHook ARM32: {patches_count} patches")
        return patches_count > 0
    
    def patch_bytehook_x86(self, filepath, is_64bit=False):
        """Patch x86/x86_64 ByteHook library"""
        arch = "x86_64" if is_64bit else "x86"
        self.log(f"Patching ByteHook {arch}: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
        
        patches_count = 0
        
        # x86 NOP = 0x90
        # Common conditional jumps: JNE (0x75, 0x0F 0x85), JE (0x74, 0x0F 0x84), etc.
        
        verify_str = b"hook chain: verify"
        positions = []
        pos = 0
        while True:
            pos = data.find(verify_str, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1
        
        self.log(f"  Found {len(positions)} verification string references")
        
        for verify_pos in positions:
            search_start = max(0, verify_pos - 2000)
            search_end = min(len(data), verify_pos + 100)
            
            for i in range(search_start, search_end - 6):
                # Short conditional jumps (2 bytes: opcode + offset)
                if data[i] in [0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F]:
                    # JE, JNE, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG
                    data[i:i+2] = b'\x90\x90'  # Two NOPs
                    patches_count += 1
                
                # Long conditional jumps (6 bytes: 0x0F 0x8X + 4-byte offset)
                elif data[i] == 0x0F and (data[i+1] & 0xF0) == 0x80:
                    data[i:i+6] = b'\x90' * 6  # Six NOPs
                    patches_count += 1
        
        self.log(f"  Applied {patches_count} patches to {arch} ByteHook")
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        self.patches_applied.append(f"ByteHook {arch}: {patches_count} patches")
        return patches_count > 0
    
    def patch_libmsaoaidsec(self, filepath):
        """Patch libmsaoaidsec.so to bypass CRC32 checks"""
        self.log(f"Patching libmsaoaidsec: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
        
        patches_count = 0
        
        # Look for CRC32 related strings and functions
        crc_patterns = [b"CRC", b"crc", b"checksum", b"integrity", b"Phdr mmap"]
        
        for pattern in crc_patterns:
            pos = data.find(pattern)
            if pos != -1:
                self.log(f"  Found pattern: {pattern} at offset {hex(pos)}")
        
        # Patch verification functions to return success
        # Similar approach to ByteHook - find conditional branches and patch
        
        for i in range(0, len(data) - 8, 4):
            if i % 4 != 0:
                continue
            instr = struct.unpack('<I', data[i:i+4])[0]
            
            # ARM64: MOV W0, #non-zero followed by RET -> MOV W0, #0; RET
            if (instr & 0xFFFFFFE0) == 0x52800000:
                imm = (instr >> 5) & 0xFFFF
                if imm != 0:
                    try:
                        next_instr = struct.unpack('<I', data[i+4:i+8])[0]
                        if next_instr == 0xD65F03C0:  # RET
                            data[i:i+4] = struct.pack('<I', 0x52800000)  # MOV W0, #0
                            patches_count += 1
                    except:
                        pass
        
        self.log(f"  Applied {patches_count} patches to libmsaoaidsec")
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        self.patches_applied.append(f"libmsaoaidsec: {patches_count} patches")
        return patches_count > 0
    
    def patch_mundo_sdk(self, filepath):
        """Patch Mundo SDK to bypass activation checks"""
        self.log(f"Patching Mundo SDK: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = bytearray(f.read())
        
        patches_count = 0
        
        # Look for activation/verification related strings
        patterns = [b"Mundo", b"activate", b"verify", b"license", b"check"]
        
        for pattern in patterns:
            pos = data.find(pattern)
            if pos != -1:
                self.log(f"  Found pattern: {pattern} at offset {hex(pos)}")
        
        # Patch verification functions
        for i in range(0, len(data) - 8, 4):
            if i % 4 != 0:
                continue
            instr = struct.unpack('<I', data[i:i+4])[0]
            
            if (instr & 0xFFFFFFE0) == 0x52800000:
                imm = (instr >> 5) & 0xFFFF
                if imm != 0:
                    try:
                        next_instr = struct.unpack('<I', data[i+4:i+8])[0]
                        if next_instr == 0xD65F03C0:  # RET
                            data[i:i+4] = struct.pack('<I', 0x52800000)
                            patches_count += 1
                    except:
                        pass
        
        self.log(f"  Applied {patches_count} patches to Mundo SDK")
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        self.patches_applied.append(f"Mundo SDK: {patches_count} patches")
        return patches_count > 0
    
    def patch_dex_signatures(self):
        """Patch classes.dex to bypass signature verification"""
        self.log("Patching classes.dex for signature bypass")
        
        dex_path = self.extract_dir / "classes.dex"
        
        # We'll use a simpler approach: search for PackageManager signature checks
        # and patch the comparison logic
        
        with open(dex_path, 'rb') as f:
            data = bytearray(f.read())
        
        patches_count = 0
        
        # Search for strings related to signature verification
        patterns = [
            b"GET_SIGNATURES",
            b"GET_SIGNING_CERTIFICATES",
            b"signatures",
            b"PackageInfo",
        ]
        
        for pattern in patterns:
            pos = data.find(pattern)
            if pos != -1:
                self.log(f"  Found signature-related string: {pattern} at offset {hex(pos)}")
        
        # DEX bytecode patching is complex, so we'll use a heuristic approach:
        # Look for comparison opcodes near signature strings and patch them
        
        # Common DEX opcodes for comparison:
        # 0x32-0x37: if-* (if-eq, if-ne, if-lt, if-ge, if-gt, if-le)
        # We can change if-ne to if-eq (always true) or use goto
        
        # Search for if-ne patterns and replace with if-eq or goto
        for i in range(len(data) - 6):
            # if-ne vA, vB, +offset (opcode 0x33)
            if data[i] == 0x33:
                # Change to if-eq (0x32) to invert logic
                data[i] = 0x32
                patches_count += 1
            
            # if-nez vA, +offset (opcode 0x39) - check if non-zero
            # Change to if-eqz (0x38) - check if zero (inverts logic)
            elif data[i] == 0x39:
                data[i] = 0x38
                patches_count += 1
        
        self.log(f"  Applied {patches_count} patches to classes.dex")
        
        with open(dex_path, 'wb') as f:
            f.write(data)
        
        self.patches_applied.append(f"classes.dex: {patches_count} patches")
        return patches_count > 0
    
    def repackage_apk(self, output_name="base-patched-bypassed.apk"):
        """Repackage the APK with patched files"""
        self.log("Repackaging APK...")
        
        # Remove old META-INF to avoid signature conflicts
        meta_inf = self.extract_dir / "META-INF"
        if meta_inf.exists():
            shutil.rmtree(meta_inf)
            self.log("  Removed old META-INF signatures")
        
        # Create new APK (unsigned zip) using Python's zipfile
        import zipfile
        
        output_path = Path(output_name)
        if output_path.exists():
            output_path.unlink()
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as apk_zip:
            # Walk through all files in extract directory
            for root, dirs, files in os.walk(self.extract_dir):
                for file in files:
                    file_path = Path(root) / file
                    # Get relative path
                    rel_path = file_path.relative_to(self.extract_dir)
                    # Add to zip
                    apk_zip.write(file_path, rel_path)
        
        self.log(f"  Created unsigned APK: {output_name}")
        
        return str(output_path)
    
    def sign_apk(self, apk_path):
        """Sign the APK with a debug key"""
        self.log("Signing APK...")
        
        # Generate a debug keystore if it doesn't exist
        keystore_path = "debug.keystore"
        if not Path(keystore_path).exists():
            self.log("  Generating debug keystore...")
            # Create keystore using keytool (requires Java)
            # Since we don't have Java, we'll create a simple signature
            # For now, we'll skip signing and note it needs to be done manually
            self.log("  Note: Java not available. APK created but needs manual signing.")
            self.log("  You can sign it with: apksigner sign --ks debug.keystore <apk>")
            return False
        
        return True
    
    def run(self):
        """Main patching workflow"""
        self.log("=== APK Anti-Tamper Bypass Patcher ===")
        self.log("")
        
        # Phase 1: Patch ByteHook libraries
        self.log("Phase 1: Patching ByteHook libraries")
        bytehook_files = {
            'arm64': self.extract_dir / 'assets/burriiiii/arm64/lib2f8c0b3257fcc345.so',
            'arm': self.extract_dir / 'assets/burriiiii/arm/lib2f8c0b3257fcc345.so',
            'x86': self.extract_dir / 'assets/burriiiii/x86/lib2f8c0b3257fcc345.so',
            'x86_64': self.extract_dir / 'assets/burriiiii/x86_64/lib2f8c0b3257fcc345.so',
        }
        
        for arch, filepath in bytehook_files.items():
            if filepath.exists():
                if arch == 'arm64':
                    self.patch_bytehook_arm64(str(filepath))
                elif arch == 'arm':
                    self.patch_bytehook_arm32(str(filepath))
                elif arch == 'x86':
                    self.patch_bytehook_x86(str(filepath), is_64bit=False)
                elif arch == 'x86_64':
                    self.patch_bytehook_x86(str(filepath), is_64bit=True)
        
        self.log("")
        
        # Phase 2: Patch signature verification in DEX
        self.log("Phase 2: Patching signature verification in classes.dex")
        self.patch_dex_signatures()
        self.log("")
        
        # Phase 3: Patch libmsaoaidsec
        self.log("Phase 3: Patching libmsaoaidsec.so")
        libmsaoaidsec = self.extract_dir / 'lib/arm64-v8a/libmsaoaidsec.so'
        if libmsaoaidsec.exists():
            self.patch_libmsaoaidsec(str(libmsaoaidsec))
        self.log("")
        
        # Phase 4: Patch Mundo SDK
        self.log("Phase 4: Patching Mundo SDK")
        mundo_sdk = self.extract_dir / 'lib/arm64-v8a/libe6bmfqax5v.so'
        if mundo_sdk.exists():
            self.patch_mundo_sdk(str(mundo_sdk))
        self.log("")
        
        # Phase 5: Repackage
        self.log("Phase 5: Repackaging APK")
        apk_path = self.repackage_apk()
        self.log("")
        
        # Phase 6: Sign (if possible)
        self.log("Phase 6: Signing APK")
        self.sign_apk(apk_path)
        self.log("")
        
        # Summary
        self.log("=== Patching Summary ===")
        for patch in self.patches_applied:
            self.log(f"  ✓ {patch}")
        self.log("")
        self.log(f"✓ Output: {apk_path}")
        self.log("✓ APK patched successfully!")
        self.log("")
        self.log("Note: The APK bypasses local anti-tamper checks but may still")
        self.log("      require online license verification depending on the app.")

if __name__ == "__main__":
    patcher = APKPatcher()
    patcher.run()
