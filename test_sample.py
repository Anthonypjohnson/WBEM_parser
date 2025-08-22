#!/usr/bin/env python3
"""
Test script to create sample data and test the WBEM parser functionality.
"""

import os
import tempfile
import struct
import shutil
from wbem_parser import WBEMRepositoryParser


def create_sample_repository():
    """Create a sample repository structure for testing."""
    temp_dir = tempfile.mkdtemp(prefix='test_wbem_')
    repo_dir = os.path.join(temp_dir, 'Repository')
    os.makedirs(repo_dir)
    
    # Create sample INDEX.BTR file
    index_file = os.path.join(repo_dir, 'INDEX.BTR')
    with open(index_file, 'wb') as f:
        # Simple header
        header = struct.pack('<IIII', 0x12345678, 0x1000, 0x0001, 0x0000)
        header += b'\x00' * 16  # Padding
        f.write(header)
        
        # Sample index entries
        for i in range(10):
            entry_size = 32
            entry_type = 1
            entry_data = struct.pack('<II', entry_size, entry_type)
            entry_data += f"TestClass{i:02d}".encode('utf-16le').ljust(24, b'\x00')
            f.write(entry_data)
    
    # Create sample OBJECTS.DATA file
    objects_file = os.path.join(repo_dir, 'OBJECTS.DATA')
    with open(objects_file, 'wb') as f:
        # Simple header
        header = struct.pack('<IIII', 0x87654321, 0x2000, 0x0002, 0x0000)
        header += b'\x00' * 16  # Padding
        f.write(header)
        
        # Sample object records
        for i in range(5):
            record_size = 64
            record_type = 2
            object_id = 0x1000 + i
            flags = 0
            
            record_header = struct.pack('<IIII', record_size, record_type, object_id, flags)
            class_name = f"Win32_TestClass{i:02d}".encode('utf-16le').ljust(32, b'\x00')
            namespace = "root\\cimv2".encode('utf-16le').ljust(16, b'\x00')
            
            f.write(record_header + class_name + namespace)
    
    # Create sample MAPPING1.MAP file
    mapping_file = os.path.join(repo_dir, 'MAPPING1.MAP')
    with open(mapping_file, 'wb') as f:
        # Simple mapping data
        mapping_data = struct.pack('<' + 'I' * 256, *range(256))
        f.write(mapping_data)
    
    # Create sample MOF file
    mof_file = os.path.join(os.path.dirname(repo_dir), 'test.mof')
    with open(mof_file, 'w') as f:
        f.write('''#pragma namespace("\\\\.\\\\root\\\\cimv2")

[Provider("CIMWin32a")]
class Win32_TestProvider : CIM_Provider
{
    [key] string Name;
    uint32 Version;
};

class Win32_SampleClass : CIM_LogicalElement
{
    [key] string DeviceID;
    string Description;
    uint32 Status;
    
    uint32 TestMethod([in] string InputParam, [out] string OutputParam);
};
''')
    
    print(f"Created sample repository at: {repo_dir}")
    return repo_dir, temp_dir


def test_parser():
    """Test the WBEM parser with sample data."""
    print("Creating sample repository...")
    repo_dir, temp_dir = create_sample_repository()
    
    try:
        print("Testing WBEM parser...")
        output_dir = os.path.join(temp_dir, 'output')
        parser = WBEMRepositoryParser(repo_dir, output_dir)
        
        success = parser.parse_repository()
        
        if success:
            print("\\nParser test completed successfully!")
            
            # Check output files
            general_csv = os.path.join(output_dir, 'wbem_general.csv')
            wmi_csv = os.path.join(output_dir, 'wmi_classes.csv')
            log_file = os.path.join(output_dir, 'parsing_log.txt')
            
            for output_file in [general_csv, wmi_csv, log_file]:
                if os.path.exists(output_file):
                    size = os.path.getsize(output_file)
                    print(f"✓ {os.path.basename(output_file)}: {size} bytes")
                else:
                    print(f"✗ {os.path.basename(output_file)}: Not created")
            
            # Show sample of general CSV
            if os.path.exists(general_csv):
                print("\\nSample of general CSV output:")
                with open(general_csv, 'r') as f:
                    lines = f.readlines()[:5]  # First 5 lines
                    for line in lines:
                        print(f"  {line.strip()}")
        else:
            print("Parser test failed!")
    
    finally:
        # Cleanup
        print(f"\\nCleaning up test files...")
        shutil.rmtree(temp_dir)
        print("Test completed.")


if __name__ == "__main__":
    test_parser()