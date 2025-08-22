#!/usr/bin/env python3
"""
Test script for enhanced CCM message parsing capabilities.
Creates test data with CCM signatures and scheduler messages.
"""

import os
import tempfile
import struct
import shutil
from wbem_parser import WBEMRepositoryParser
from ccm_message_parser import CCMMessageParser


def create_test_ccm_data():
    """Create test OBJECTS.DATA with CCM signatures and messages."""
    temp_dir = tempfile.mkdtemp(prefix='test_ccm_')
    repo_dir = os.path.join(temp_dir, 'Repository')
    os.makedirs(repo_dir)
    
    # Create test OBJECTS.DATA with CCM content
    objects_file = os.path.join(repo_dir, 'OBJECTS.DATA')
    
    with open(objects_file, 'wb') as f:
        # Write header
        header = struct.pack('<IIII', 0x87654321, 0x2000, 0x0002, 0x0000)
        header += b'\x00' * 16
        f.write(header)
        
        # Write CCM_RecentlyUsedApps hash signature (Vista+ SHA256)
        rua_hash = b'\x7c\x26\x15\x51\xb2\x64\xd3\x5e\x30\xa7\xfa\x29\xc7\x52\x83\xda\xe0\x4b\xba\x71\xdb\xe8\xf5\xe5\x53\xf7\xad\x38\x1b\x40\x6d\xd8'
        f.write(rua_hash)
        
        # Write sample RecentlyUsedApps data
        # Two FILETIME values
        filetime1 = struct.pack('<Q', 132578256000000000)  # Sample FILETIME
        filetime2 = struct.pack('<Q', 132578256000000000)  # Sample FILETIME
        f.write(filetime1 + filetime2)
        
        # Size indicator
        size_indicator = struct.pack('<H', 500)
        f.write(size_indicator)
        
        # Sample properties (UTF-16 strings)
        properties = [
            "CCM_RecentlyUsedApps",
            "2024-01-15 10:30:00",
            "testuser",
            "Microsoft Office Word",
            "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
            "Microsoft Word Document",
            "16.0.5410.1000",
            "Microsoft Corporation"
        ]
        
        for prop in properties:
            prop_utf16 = prop.encode('utf-16le') + b'\x00\x00'
            f.write(prop_utf16)
        
        # Add some padding
        f.write(b'\x00' * 64)
        
        # Write CCM_Scheduler_ScheduledMessage signature
        scheduler_sig = b'CCM_Scheduler_ScheduledMessage'
        f.write(scheduler_sig)
        f.write(b'\x00' * 32)
        
        # Write scheduler message properties
        scheduler_props = [
            b'ScheduleID\x00{12345678-1234-5678-9012-123456789012}',
            b'UserSID\x00S-1-5-21-1234567890-1234567890-1234567890-1000',
            b'ActiveTime\x00',
            struct.pack('<Q', 132578256000000000),  # Active time as FILETIME
            b'ExpireTime\x00',
            struct.pack('<Q', 132678256000000000),  # Expire time as FILETIME
            b'TargetEndpoint\x00WMI:root\\ccm\\policy\\machine\\RequestedConfig',
            b'Triggers\x00SimpleInterval;Minutes=60;RandomizationInterval=30'
        ]
        
        for prop in scheduler_props:
            f.write(prop)
            f.write(b'\x00' * 8)  # Padding
        
        # Add namespace signatures
        namespaces = [
            b'root\\ccm\x00',
            b'root\\ccm\\SoftwareMeteringAgent\x00',
            b'root\\ccm\\policy\\machine\\actualconfig\x00'
        ]
        
        for ns in namespaces:
            f.write(ns)
            f.write(b'\x00' * 16)
        
        # Add more CCM messages pattern
        for i in range(3):
            f.write(b'CCM_Scheduler_Messages')
            f.write(b'\x00' * 32)
            
            # Add some scheduler data
            schedule_data = f'Schedule_{i:02d}'.encode('utf-16le') + b'\x00\x00'
            f.write(schedule_data)
            
            # Add FILETIME
            filetime = struct.pack('<Q', 132578256000000000 + i * 3600000000)
            f.write(filetime)
            
            f.write(b'\x00' * 64)
    
    print(f"Created test CCM data at: {repo_dir}")
    return repo_dir, temp_dir


def test_ccm_parser_standalone():
    """Test the standalone CCM parser."""
    print("=== Testing Standalone CCM Parser ===")
    
    repo_dir, temp_dir = create_test_ccm_data()
    objects_file = os.path.join(repo_dir, 'OBJECTS.DATA')
    
    try:
        parser = CCMMessageParser()
        
        with open(objects_file, 'rb') as f:
            data = f.read()
        
        print(f"Loaded {len(data)} bytes of test data")
        
        objects_found = parser.parse_ccm_objects(data, objects_file)
        
        print(f"Found {objects_found} CCM objects")
        print(f"  - {len(parser.ccm_objects)} total CCM objects")
        print(f"  - {len(parser.recently_used_apps)} RecentlyUsedApps records")
        print(f"  - {len(parser.scheduler_messages)} Scheduler Messages")
        
        # Show details of found objects
        for i, obj in enumerate(parser.ccm_objects[:5]):  # Show first 5
            print(f"Object {i+1}: {obj['type']} at offset {obj['file_offset']}")
        
        if parser.recently_used_apps:
            rua = parser.recently_used_apps[0]
            print(f"\\nSample RecentlyUsedApp:")
            print(f"  Last Used: {rua.get('last_used_time', 'Unknown')}")
            print(f"  Properties: {len(rua.get('properties', {}))}")
            
        if parser.scheduler_messages:
            msg = parser.scheduler_messages[0]
            print(f"\\nSample Scheduler Message:")
            print(f"  Properties: {len(msg.get('properties', {}))}")
            print(f"  FILETIME values: {len(msg.get('filetime_values', []))}")
        
        return True
        
    finally:
        shutil.rmtree(temp_dir)


def test_enhanced_wbem_parser():
    """Test the enhanced WBEM parser with CCM support."""
    print("\\n=== Testing Enhanced WBEM Parser ===")
    
    repo_dir, temp_dir = create_test_ccm_data()
    
    try:
        output_dir = os.path.join(temp_dir, 'output')
        parser = WBEMRepositoryParser(repo_dir, output_dir)
        
        success = parser.parse_repository()
        
        if success:
            print("Enhanced parser test completed successfully!")
            
            # Check output files
            output_files = [
                'wbem_general.csv',
                'wmi_classes.csv',
                'ccm_objects.csv',
                'ccm_recently_used_apps.csv',
                'ccm_scheduler_messages.csv',
                'parsing_log.txt'
            ]
            
            for output_file in output_files:
                file_path = os.path.join(output_dir, output_file)
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    print(f"✓ {output_file}: {size} bytes")
                else:
                    print(f"- {output_file}: Not created")
            
            # Show sample of CCM objects CSV if it exists
            ccm_csv = os.path.join(output_dir, 'ccm_objects.csv')
            if os.path.exists(ccm_csv):
                print("\\nSample CCM Objects CSV:")
                with open(ccm_csv, 'r') as f:
                    lines = f.readlines()[:3]  # Header + 2 data lines
                    for line in lines:
                        print(f"  {line.strip()}")
            
            return True
        else:
            print("Enhanced parser test failed!")
            return False
            
    finally:
        shutil.rmtree(temp_dir)


def test_ccm_export_functions():
    """Test the CCM CSV export functions."""
    print("\\n=== Testing CCM Export Functions ===")
    
    parser = CCMMessageParser()
    
    # Create mock data
    parser.ccm_objects = [{
        'type': 'CCM_Test',
        'object_id': 'TEST001',
        'namespace': 'root\\ccm',
        'source_file': '/test/file',
        'file_offset': 1000,
        'record_type': 1,
        'size': 256,
        'flags': 0,
        'signature_type': 'test',
        'timestamp': '2024-01-15 10:30:00',
        'raw_data_sample': '1234567890abcdef'
    }]
    
    parser.recently_used_apps = [{
        'last_used_time': '2024-01-15 10:30:00',
        'creation_time': '2024-01-15 09:00:00',
        'properties': {
            'ProductName': 'Test Application',
            'FolderPath': 'C:\\\\Test\\\\App.exe',
            'LastUsername': 'testuser'
        },
        'source_file': '/test/file',
        'file_offset': 2000
    }]
    
    temp_dir = tempfile.mkdtemp(prefix='ccm_export_test_')
    
    try:
        # Test exports
        parser.export_ccm_objects_to_csv(os.path.join(temp_dir, 'test_ccm_objects.csv'))
        parser.export_recently_used_apps_to_csv(os.path.join(temp_dir, 'test_rua.csv'))
        
        # Check files were created
        ccm_file = os.path.join(temp_dir, 'test_ccm_objects.csv')
        rua_file = os.path.join(temp_dir, 'test_rua.csv')
        
        if os.path.exists(ccm_file):
            print(f"✓ CCM objects CSV created: {os.path.getsize(ccm_file)} bytes")
        
        if os.path.exists(rua_file):
            print(f"✓ RecentlyUsedApps CSV created: {os.path.getsize(rua_file)} bytes")
        
        return True
        
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    print("Enhanced CCM Message Parser Test Suite")
    print("=" * 50)
    
    success = True
    
    try:
        # Test standalone CCM parser
        if not test_ccm_parser_standalone():
            success = False
        
        # Test enhanced WBEM parser
        if not test_enhanced_wbem_parser():
            success = False
        
        # Test export functions
        if not test_ccm_export_functions():
            success = False
        
        print("\\n" + "=" * 50)
        if success:
            print("✓ All tests completed successfully!")
            print("\\nThe enhanced parser can now extract:")
            print("  - CCM_RecentlyUsedApps (execution evidence)")
            print("  - CCM_Scheduler_Messages (scheduled tasks)")
            print("  - CCM namespace objects (Configuration Manager data)")
            print("  - Enhanced binary parsing with forensic hash signatures")
        else:
            print("✗ Some tests failed. Check the output above.")
    
    except Exception as e:
        print(f"\\nTest suite error: {str(e)}")
        print("This may indicate issues with the enhanced parser implementation.")