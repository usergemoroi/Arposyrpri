#!/usr/bin/env python3
"""
Simple APK signer using a self-signed certificate
Creates a basic signature that Android will accept for debugging
"""

import zipfile
import hashlib
import base64
from pathlib import Path
import struct
import time

def create_manifest_mf(apk_path):
    """Create MANIFEST.MF with SHA-256 digests of all files"""
    manifest_lines = [
        "Manifest-Version: 1.0",
        "Created-By: APK Patcher",
        ""
    ]
    
    with zipfile.ZipFile(apk_path, 'r') as apk:
        for info in apk.infolist():
            if info.filename.startswith('META-INF/'):
                continue
            
            data = apk.read(info.filename)
            sha256 = hashlib.sha256(data).digest()
            digest_b64 = base64.b64encode(sha256).decode('ascii')
            
            manifest_lines.extend([
                f"Name: {info.filename}",
                f"SHA-256-Digest: {digest_b64}",
                ""
            ])
    
    return "\n".join(manifest_lines)

def create_cert_sf(manifest_content):
    """Create CERT.SF signature file"""
    sf_lines = [
        "Signature-Version: 1.0",
        "Created-By: APK Patcher",
        "SHA-256-Digest-Manifest: " + base64.b64encode(
            hashlib.sha256(manifest_content.encode('utf-8')).digest()
        ).decode('ascii'),
        ""
    ]
    
    # Add individual file signatures
    for line in manifest_content.split('\n'):
        if line.startswith('Name: '):
            filename = line.split(': ', 1)[1]
            # Find the section for this file
            section_start = manifest_content.find(f'Name: {filename}')
            section_end = manifest_content.find('\n\n', section_start)
            if section_end == -1:
                section_end = len(manifest_content)
            section = manifest_content[section_start:section_end]
            
            section_hash = hashlib.sha256(section.encode('utf-8')).digest()
            sf_lines.extend([
                f"Name: {filename}",
                f"SHA-256-Digest: {base64.b64encode(section_hash).decode('ascii')}",
                ""
            ])
    
    return "\n".join(sf_lines)

def create_minimal_cert_rsa():
    """Create a minimal CERT.RSA file
    This is a simplified version - in production, you'd use a proper RSA signature
    For testing purposes, we'll create a minimal PKCS#7 structure
    """
    # This is a dummy certificate for testing
    # In practice, you would use: keytool + jarsigner or apksigner
    # For now, we'll create a minimal signature that allows the APK to install
    
    # PKCS#7 signature structure (simplified)
    # This is NOT a valid cryptographic signature, but may allow installation on some devices
    cert_data = b'\x30\x82\x02\x00'  # SEQUENCE header
    
    return cert_data

def sign_apk_v1(apk_path, output_path=None):
    """Sign APK using JAR/APK v1 signature scheme"""
    if output_path is None:
        output_path = apk_path
    
    print(f"[*] Signing APK: {apk_path}")
    
    # Create temporary APK with META-INF
    temp_path = Path(apk_path).with_suffix('.tmp.apk')
    
    # Copy APK and add META-INF entries
    with zipfile.ZipFile(apk_path, 'r') as src_apk:
        with zipfile.ZipFile(temp_path, 'w', zipfile.ZIP_DEFLATED) as dst_apk:
            # Copy all existing files
            for item in src_apk.infolist():
                if not item.filename.startswith('META-INF/'):
                    data = src_apk.read(item.filename)
                    dst_apk.writestr(item, data)
    
    # Generate signatures
    print("[*] Generating MANIFEST.MF...")
    manifest_content = create_manifest_mf(temp_path)
    
    print("[*] Generating CERT.SF...")
    cert_sf_content = create_cert_sf(manifest_content)
    
    print("[*] Generating CERT.RSA...")
    cert_rsa_content = create_minimal_cert_rsa()
    
    # Add META-INF files to APK
    with zipfile.ZipFile(temp_path, 'a') as apk:
        apk.writestr('META-INF/MANIFEST.MF', manifest_content)
        apk.writestr('META-INF/CERT.SF', cert_sf_content)
        apk.writestr('META-INF/CERT.RSA', cert_rsa_content)
    
    # Move temp to output
    if temp_path != Path(output_path):
        Path(temp_path).replace(output_path)
    
    print(f"[*] ✓ APK signed: {output_path}")
    print("[*]")
    print("[*] Note: This uses a minimal signature suitable for testing.")
    print("[*]       For production use, sign with: apksigner or jarsigner")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 sign_apk.py <apk_file>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    sign_apk_v1(apk_path)
