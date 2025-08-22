# Windows 11 WBEM Repository Parser

A comprehensive Python tool for parsing Windows 11 WMI (Windows Management Instrumentation) repository files for forensic analysis and security research.

## Features

- **Cross-platform**: Runs on Linux systems without internet connectivity
- **Forensic support**: Handles various input types including forensic images, mounted drives, and direct file access
- **Comprehensive parsing**: Extracts data from INDEX.BTR, OBJECTS.DATA, mapping files, and MOF files
- **Enhanced CCM parsing**: Specialized extraction of CCM_Scheduler_Messages and SCCM objects
- **Multiple CSV outputs**: General repository data, WMI classes, and CCM-specific information
- **Built-in libraries only**: Uses only Python standard library modules
- **Robust error handling**: Continues parsing even with corrupted or incomplete files
- **Forensic hash signatures**: Detects CCM objects using known forensic hash signatures

## Usage

### Basic Usage
```bash
python wbem_parser.py <repository_path> [output_directory]
```

### Examples

```bash
# Parse from mounted Windows system
python wbem_parser.py /mnt/windows/Windows/System32/wbem/Repository

# Parse from forensic image (requires root for mounting)
python wbem_parser.py /path/to/forensic_image.dd ./output

# Parse from EnCase image
python wbem_parser.py /path/to/evidence.E01 ./forensic_output

# Parse from directory structure
python wbem_parser.py /extracted/windows/files ./analysis
```

## Input Types Supported

### Direct Access
- Windows directory structure
- Mounted Windows drives
- Extracted Windows files

### Forensic Images
- Raw disk images (.dd, .img, .raw, .001)
- EnCase images (.e01, .ex01) - requires `ewfmount`
- Virtual disk images (.vmdk, .vhd, .vhdx) - requires `qemu-nbd`
- ISO images (.iso)

### Repository Files Parsed
- **INDEX.BTR**: Binary tree index file
- **OBJECTS.DATA**: Object records and class data (with enhanced CCM parsing)
- **MAPPING*.MAP**: Page mapping files
- **MOF files**: Managed Object Format class definitions
- **CCM Messages**: Configuration Manager scheduler messages and tasks
- **Additional files**: Provider DLLs, logs, and related WMI files

## Output Files

### wbem_general.csv
Contains comprehensive repository data with columns:
- File_Path: Source file location
- File_Type: Type of repository file
- Record_Type: Specific record or data type
- Object_ID: Unique object identifier
- Class_Name: WMI class name (if applicable)
- Namespace: WMI namespace
- Timestamp: File modification time
- Data_Size: Size of data record
- Hash_Value: SHA-256/MD5 hash
- Raw_Data_Sample: Hexadecimal sample of raw data

### wmi_classes.csv
Contains WMI class-specific information:
- Class_Name: WMI class name
- Namespace: WMI namespace path
- Super_Class: Parent class
- Properties: Number and description of properties
- Methods: Number and description of methods
- Provider: WMI provider information
- MOF_Source: Source of class definition
- Registration_Status: Registration state
- Instance_Count: Number of instances (if available)

### ccm_objects.csv
Contains CCM-specific object information:
- Type: CCM object type (e.g., CCM_Scheduler_Messages)
- Object_ID: Unique object identifier
- Namespace: CCM namespace path
- Source_File: Source OBJECTS.DATA file
- File_Offset: Byte offset in source file
- Signature_Type: Forensic signature type used for detection
- Timestamp: Detection timestamp
- Raw_Data_Sample: Hexadecimal sample of raw data

### ccm_recently_used_apps.csv
Contains execution evidence from CCM_RecentlyUsedApps:
- Last_Used_Time: When application was last executed
- Creation_Time: When record was created
- Product_Name: Application name
- Folder_Path: Full path to executable
- File_Description: Application description
- Company_Name: Software vendor
- Last_Username: User who executed the application
- Launch_Count: Number of times launched

### ccm_scheduler_messages.csv
Contains Configuration Manager scheduled tasks:
- Schedule_ID: Unique schedule identifier
- User_SID: User security identifier
- Active_Time: When schedule becomes active
- Expire_Time: When schedule expires
- Target_Endpoint: WMI endpoint for message delivery
- Triggers: Schedule trigger conditions
- Launch_Conditions: Conditions required for execution
- Filetime_Values: Additional timestamp values

### parsing_log.txt
Detailed parsing log with timestamps, errors, and processing information.

## Technical Details

### Repository Format Support
- Windows Vista+ repository format (version 2.2)
- SHA-256 hash-based name identification
- UTF-16 little-endian string parsing
- Binary tree index traversal
- Multi-page object record handling

### Security Features
- Read-only access to all files
- No network connectivity required
- No modification of source data
- Secure handling of corrupted data
- Safe binary data parsing

## Dependencies

### Required (Built-in)
- Python 3.6+
- Standard library modules: `os`, `sys`, `struct`, `csv`, `hashlib`, `binascii`, `datetime`, `re`, `glob`

### Optional (for enhanced forensic support)
- `ewfmount` - For EnCase E01 image mounting
- `qemu-nbd` - For virtual disk image mounting
- `sudo` access - For mounting forensic images

## Installation

1. Clone or download the repository:
```bash
git clone <repository_url>
cd Windows_11_WBEM_parser
```

2. Ensure Python 3.6+ is installed:
```bash
python3 --version
```

3. Run the parser:
```bash
python3 wbem_parser.py <path_to_repository>
```

## Forensic Considerations

### Data Integrity
- All file operations are read-only
- Original data is never modified
- Hash values are calculated for verification
- Detailed logging tracks all operations

### Evidence Handling
- Supports standard forensic image formats
- Preserves timestamps and metadata
- Handles corrupted or incomplete data gracefully
- Provides detailed parsing logs for documentation

### Performance
- Processes large repositories efficiently
- Limits recursion depth to prevent runaway parsing
- Handles files up to several GB in size
- Memory-efficient streaming for large files

## Troubleshooting

### Common Issues

**"Repository path does not exist"**
- Verify the path is correct
- Check if using forensic images that need mounting
- Ensure proper permissions to access files

**"No core repository files found"**
- Repository may be in a subdirectory
- Files may have different case (INDEX.btr vs INDEX.BTR)
- Repository may be corrupted or incomplete

**Mounting failures with forensic images**
- Requires root/sudo access for mounting
- May need additional tools (ewfmount, qemu-nbd)
- Check if image file is corrupted

**Unicode/encoding errors**
- Some MOF files may use different encodings
- Parser attempts multiple encodings automatically
- Check parsing log for specific encoding issues

### Debug Mode
Add detailed debugging by modifying the log level in the source code or checking the parsing_log.txt file for detailed error information.

## Legal and Ethical Use

This tool is designed for:
- **Defensive security analysis**
- **Digital forensics investigations**
- **System administration and troubleshooting**
- **Security research and education**

**Important**: Only use this tool on systems you own or have explicit permission to analyze. This tool is for defensive purposes only and should not be used for unauthorized access or malicious activities.

## License

This tool is provided for educational and defensive security purposes. Users are responsible for ensuring compliance with all applicable laws and regulations.

## Contributing

When contributing:
1. Focus on defensive security applications
2. Maintain compatibility with built-in Python libraries
3. Ensure cross-platform compatibility
4. Add comprehensive error handling
5. Document all changes thoroughly

## Version History

- **v1.0**: Initial release with basic repository parsing
- Current: Enhanced forensic support and comprehensive error handling