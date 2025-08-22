#!/usr/bin/env python3
"""
Example usage of the Windows 11 WBEM Repository Parser
"""

import os
import sys
from wbem_parser import WBEMRepositoryParser
from forensic_support import ForensicHandler


def example_basic_usage():
    """Example of basic parser usage."""
    print("=== Basic Usage Example ===")
    
    # Example repository path (adjust for your system)
    repository_path = "/mnt/windows/Windows/System32/wbem/Repository"
    output_directory = "./analysis_output"
    
    print(f"Repository path: {repository_path}")
    print(f"Output directory: {output_directory}")
    
    # Create parser instance
    parser = WBEMRepositoryParser(repository_path, output_directory)
    
    # Parse the repository
    success = parser.parse_repository()
    
    if success:
        print("\\n✓ Parsing completed successfully!")
        print("Output files:")
        print("  - wbem_general.csv: General repository data")
        print("  - wmi_classes.csv: WMI class information")
        print("  - parsing_log.txt: Detailed parsing log")
    else:
        print("\\n✗ Parsing failed. Check the log for details.")


def example_forensic_usage():
    """Example of forensic image analysis."""
    print("\\n=== Forensic Usage Example ===")
    
    # Example forensic image path
    forensic_image = "/path/to/forensic_image.dd"
    output_directory = "./forensic_analysis"
    
    print(f"Forensic image: {forensic_image}")
    print(f"Output directory: {output_directory}")
    
    # The parser automatically handles forensic images
    parser = WBEMRepositoryParser(forensic_image, output_directory)
    
    print("\\nDetecting input type and preparing for analysis...")
    success = parser.parse_repository()
    
    if success:
        print("\\n✓ Forensic analysis completed!")
    else:
        print("\\n✗ Forensic analysis failed.")


def example_input_detection():
    """Example of input type detection."""
    print("\\n=== Input Detection Example ===")
    
    test_paths = [
        "/mnt/windows/Windows/System32/wbem/Repository",
        "/path/to/image.dd",
        "/path/to/evidence.E01",
        "/extracted/windows/files",
        "/media/usb/WINDOWS"
    ]
    
    handler = ForensicHandler()
    
    for path in test_paths:
        input_type = handler.detect_input_type(path)
        print(f"Path: {path}")
        print(f"  Detected type: {input_type}")
        print()


def show_sample_commands():
    """Show sample command-line usage."""
    print("\\n=== Sample Command-Line Usage ===")
    
    commands = [
        # Basic usage
        "python3 wbem_parser.py /mnt/windows/Windows/System32/wbem/Repository",
        
        # With custom output directory
        "python3 wbem_parser.py /mnt/windows/Windows/System32/wbem/Repository ./my_analysis",
        
        # Forensic image analysis
        "python3 wbem_parser.py /forensics/case001/disk_image.dd ./case001_output",
        
        # EnCase image analysis
        "python3 wbem_parser.py /evidence/suspect_drive.E01 ./suspect_analysis",
        
        # Directory analysis
        "python3 wbem_parser.py /extracted_files/Windows ./directory_analysis"
    ]
    
    for i, cmd in enumerate(commands, 1):
        print(f"{i}. {cmd}")
    
    print("\\nNote: Forensic image mounting may require sudo privileges.")


def analyze_output_files(output_dir):
    """Example of analyzing parser output files."""
    print(f"\\n=== Analyzing Output Files in {output_dir} ===")
    
    import csv
    
    # Analyze general CSV
    general_csv = os.path.join(output_dir, "wbem_general.csv")
    if os.path.exists(general_csv):
        print("\\nGeneral Repository Data:")
        with open(general_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            file_types = {}
            record_types = {}
            
            for row in reader:
                file_type = row['File_Type']
                record_type = row['Record_Type']
                
                file_types[file_type] = file_types.get(file_type, 0) + 1
                record_types[record_type] = record_types.get(record_type, 0) + 1
        
        print("  File types found:")
        for ftype, count in file_types.items():
            print(f"    {ftype}: {count} records")
        
        print("  Record types found:")
        for rtype, count in record_types.items():
            print(f"    {rtype}: {count} records")
    
    # Analyze WMI classes CSV
    wmi_csv = os.path.join(output_dir, "wmi_classes.csv")
    if os.path.exists(wmi_csv):
        print("\\nWMI Classes Data:")
        with open(wmi_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            classes = list(reader)
            
        print(f"  Total WMI classes found: {len(classes)}")
        
        if classes:
            namespaces = {}
            for cls in classes:
                namespace = cls['Namespace']
                namespaces[namespace] = namespaces.get(namespace, 0) + 1
            
            print("  Namespaces:")
            for namespace, count in namespaces.items():
                print(f"    {namespace}: {count} classes")


if __name__ == "__main__":
    print("Windows 11 WBEM Repository Parser - Usage Examples")
    print("=" * 55)
    
    # Show different usage examples
    show_sample_commands()
    example_input_detection()
    
    # Note about running examples
    print("\\n" + "=" * 55)
    print("NOTE: The above are examples showing different usage patterns.")
    print("To actually run the parser, use:")
    print("  python3 wbem_parser.py <your_repository_path> [output_dir]")
    print("\\nFor testing with sample data, run:")
    print("  python3 test_sample.py")