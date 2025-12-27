#!/usr/bin/env python3
"""
Test script for AWS Enumerator credential validation
Demonstrates proper credential handling without running full enumeration
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aws_enum import AWSEnumerator

def test_credential_validation():
    """Test credential format validation"""
    print("Testing credential validation...\n")
    
    # Test 1: Invalid access key format
    print("[Test 1] Invalid access key format:")
    try:
        enumerator = AWSEnumerator(
            access_key="INVALID123",
            secret_key="a" * 40,
            region="us-east-1"
        )
        print("✗ Should have warned about format")
    except ValueError as e:
        print(f"✓ Caught: {e}")
    except Exception as e:
        print(f"○ Warning issued, continuing: {e}")
    
    # Test 2: Invalid secret key length
    print("\n[Test 2] Invalid secret key length:")
    try:
        enumerator = AWSEnumerator(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="short",
            region="us-east-1"
        )
        print("○ Warning issued, continuing")
    except ValueError as e:
        print(f"✓ Caught: {e}")
    
    # Test 3: Invalid region (should warn but continue)
    print("\n[Test 3] Invalid region:")
    try:
        enumerator = AWSEnumerator(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="invalid-region-99"
        )
        print("○ Warning issued, continuing")
    except ValueError as e:
        print(f"✓ Caught: {e}")
    
    # Test 4: Empty credentials
    print("\n[Test 4] Empty credentials:")
    try:
        enumerator = AWSEnumerator(
            access_key="",
            secret_key="",
            region="us-east-1"
        )
        print("✗ Should have failed validation")
    except ValueError as e:
        print(f"✓ Caught: {e}")
    
    # Test 5: Valid format (will fail at AWS API level with fake creds)
    print("\n[Test 5] Valid format, fake credentials:")
    try:
        enumerator = AWSEnumerator(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-east-1"
        )
        print("✗ Should have failed at credential test")
    except ValueError as e:
        print(f"✓ Caught during credential test: {e}")
    
    print("\n" + "=" * 60)
    print("Credential validation tests complete!")
    print("=" * 60)


def test_environment_loading():
    """Test loading from environment variables"""
    print("\n\nTesting environment variable loading...\n")
    
    # Set test environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = 'AKIAIOSFODNN7EXAMPLE'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    os.environ['AWS_DEFAULT_REGION'] = 'us-west-2'
    
    from aws_enum import get_credentials_from_env
    
    creds = get_credentials_from_env()
    
    print(f"Access Key: {creds['access_key'][:10]}... ✓")
    print(f"Secret Key: {'*' * 20} ✓")
    print(f"Region: {creds['region']} ✓")
    
    print("\n" + "=" * 60)
    print("Environment loading test complete!")
    print("=" * 60)


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════╗
    ║  AWS Enumerator - Validation Tests    ║
    ╚════════════════════════════════════════╝
    """)
    
    test_credential_validation()
    test_environment_loading()
    
    print("\n[*] All tests completed!")
    print("[*] Note: Tests use fake credentials - real enumeration would fail")
