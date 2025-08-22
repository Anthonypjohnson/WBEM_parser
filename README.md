# Enhanced Windows 11 WBEM Repository Parser

A comprehensive Python tool for parsing Windows 11 WMI (Windows Management Instrumentation) repository files for forensic analysis and malicious activity detection. Specifically designed for detecting WMI-based persistence mechanisms and advanced persistent threats (APTs).

## 🔒 Security Features

- **🚨 Malicious WMI Detection**: Advanced detection of WMI-based persistence mechanisms
- **🎯 APT Signatures**: Detection patterns for known APT groups (APT29, Turla, Lazarus, etc.)
- **🔍 Threat Intelligence**: Real-time threat analysis with risk scoring
- **🛡️ Persistence Analysis**: Complete FilterToConsumerBinding chain analysis
- **📊 IOC Generation**: Automatic generation of Indicators of Compromise (IOCs)
- **⚠️ Deleted Object Recovery**: Detection of deleted persistence objects in unallocated space

## 🛠️ Core Features

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

#### Comprehensive Repository Analysis
```bash
python wbem_parser.py <repository_path> [output_directory]
```

#### Enhanced Malicious Activity Detection
```bash
python enhanced_wmi_parser.py <OBJECTS.DATA_file> [output_directory]
```

### Examples

```bash
# Complete repository analysis with malicious activity detection
python wbem_parser.py /mnt/windows/Windows/System32/wbem/Repository ./forensic_analysis

# Direct OBJECTS.DATA analysis for threat hunting
python enhanced_wmi_parser.py /path/to/OBJECTS.DATA ./threat_analysis

# Parse from forensic image (requires root for mounting)
python wbem_parser.py /path/to/forensic_image.dd ./output

# Parse from EnCase image
python wbem_parser.py /path/to/evidence.E01 ./forensic_output

# Quick test with sample data
python test_enhanced_parser.py
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

### 🔒 Enhanced Security Analysis Outputs

#### wmi_analysis/wmi_persistence_objects.csv
Comprehensive WMI persistence mechanism detection:
- Type: WMI object type (FilterToConsumerBinding, EventFilter, EventConsumer)
- Object_ID: Unique object identifier
- File_Offset: Location in OBJECTS.DATA file
- Consumer_Type: Specific consumer implementation (ActiveScript, CommandLine)
- Properties: Extracted object properties and configurations
- Raw_Data: Hexadecimal representation of object data

#### wmi_analysis/wmi_threat_analysis.csv
Advanced threat intelligence analysis:
- Source_Object_ID: Reference to analyzed object
- Threat_Level: Risk assessment (LOW, MEDIUM, HIGH, CRITICAL)
- Risk_Score: Numerical risk score (0-100)
- Malware_Family: Detected malware family signatures
- APT_Groups: Associated Advanced Persistent Threat groups
- Attack_Techniques: Identified attack methodologies
- Recommendations: Specific security recommendations

#### wmi_analysis/wmi_persistence_chains.csv
Complete persistence mechanism analysis:
- Chain_ID: Unique persistence chain identifier
- Persistence_Method: Type of persistence mechanism
- Risk_Level: Chain-specific risk assessment
- Filter_Query: WQL query used for event triggering
- Consumer_Type: Type of event consumer
- Consumer_Command: Executed command or script content

#### wmi_analysis/wmi_suspicious_objects.csv
Objects flagged for suspicious content:
- Object_ID: Object identifier
- Suspicious_Keyword: Detected malicious pattern
- Context: Surrounding content for analysis
- Raw_Data_Sample: Hexadecimal sample for further investigation

#### wmi_analysis/wmi_wql_queries.csv
Extracted WQL queries for analysis:
- Object_ID: Source object identifier
- Query: Complete WQL query text
- File_Offset: Location in source file

#### wmi_analysis/wmi_deleted_objects.csv
Potentially deleted persistence objects:
- Pattern: Detected object pattern
- Status: Object status (potentially_deleted)
- Context_Hex: Surrounding data context

#### wmi_analysis/wmi_ioc_report.json
Structured Indicators of Compromise (IOCs):
- Command line indicators
- File path indicators
- Script content indicators
- Network-related indicators
- Attack technique mappings
- Security recommendations

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

### 🚨 Malicious WMI Detection Capabilities

#### Persistence Mechanism Detection
- **FilterToConsumerBinding**: Complete persistence chain analysis
- **Event Filters**: WQL query analysis for suspicious monitoring
- **Event Consumers**: Script and command execution analysis
- **Deleted Objects**: Recovery of deleted persistence mechanisms

#### Threat Intelligence Integration
- **APT Signatures**: Detection patterns for 10+ APT groups
- **Malware Families**: Stuxnet, Carbanak, Duqu, Flame signatures
- **Risk Scoring**: Automated threat level assessment (0-100 scale)
- **Attack Techniques**: MITRE ATT&CK framework mapping

#### Advanced Detection Patterns
- **PowerShell Execution**: Encoded commands, hidden execution
- **Living off the Land**: Regsvr32, MSHTA, BITSAdmin abuse
- **Script Injection**: VBScript, JavaScript, PowerShell payloads
- **Network Activity**: Download strings, web client usage
- **Obfuscation**: Base64 encoding, command line obfuscation

#### Supported APT Groups
- APT29 (Cozy Bear) - PowerShell WMI techniques
- Turla - WMI information gathering
- Lazarus Group - WMI enumeration patterns
- APT1 (Comment Crew) - Remote WMI execution
- Carbanak - Scheduled task WMI creation

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

## 🔍 Threat Hunting Guide

### Quick Threat Assessment
1. **Run enhanced analysis**: `python enhanced_wmi_parser.py /path/to/OBJECTS.DATA ./analysis`
2. **Check threat level**: Look for CRITICAL or HIGH threat assessments in console output
3. **Review persistence chains**: Check `wmi_persistence_chains.csv` for complete attack chains
4. **Analyze IOCs**: Review `wmi_ioc_report.json` for actionable indicators

### Threat Level Interpretation
- **CRITICAL**: Immediate action required - likely active compromise
- **HIGH**: Probable malicious activity - investigate immediately  
- **MEDIUM**: Suspicious patterns detected - review for false positives
- **LOW**: Normal WMI usage - baseline review recommended

### Investigation Workflow
1. **Initial Triage**:
   - Run both parsers: `wbem_parser.py` and `enhanced_wmi_parser.py`
   - Review threat analysis summary for overall risk assessment
   - Identify high-risk persistence chains and suspicious objects

2. **Deep Analysis**:
   - Examine FilterToConsumerBinding objects for complete attack chains
   - Analyze script content in Event Consumers for malicious payloads
   - Cross-reference detected patterns with known APT TTPs
   - Check for deleted persistence objects in unallocated space

3. **Evidence Collection**:
   - Export all CSV files for documentation
   - Use IOC report for hunting across environment
   - Correlate findings with Windows Event Logs and Sysmon
   - Preserve forensic images for court proceedings

4. **Response Actions**:
   - Follow recommendations in threat analysis output
   - Remove malicious WMI subscriptions if confirmed
   - Hunt for lateral movement using extracted IOCs
   - Update detection rules based on findings

### Integration with SIEM/EDR
- Import CSV files into security platforms for correlation
- Use IOC JSON report for automated indicator feeding
- Create custom alerts based on detected APT signatures
- Monitor for similar patterns across environment

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
- **v1.5**: Enhanced CCM parsing and forensic support
- **v2.0**: **Current** - Advanced malicious WMI detection and threat intelligence
  - FilterToConsumerBinding persistence chain analysis
  - APT signature detection (APT29, Turla, Lazarus, etc.)
  - Real-time threat assessment with risk scoring
  - Automated IOC generation and YARA rule creation
  - Deleted object recovery from unallocated space
  - Comprehensive threat hunting workflows

## 🏆 Key Improvements Over Referenced Tools

This enhanced parser builds upon and significantly extends the capabilities of existing WMI forensic tools:

### Compared to [wmie2](https://github.com/vinaypamnani/wmie2):
- ✅ **Malicious Activity Detection**: Advanced threat pattern recognition
- ✅ **APT Signature Library**: Built-in detection for known threat groups  
- ✅ **Persistence Chain Analysis**: Complete FilterToConsumerBinding analysis
- ✅ **Automated Risk Assessment**: Real-time threat level calculation

### Compared to [WMI_Forensics](https://github.com/davidpany/WMI_Forensics):
- ✅ **Enhanced OBJECTS.DATA Parsing**: More comprehensive object extraction
- ✅ **Deleted Object Recovery**: Advanced unallocated space analysis
- ✅ **Threat Intelligence Integration**: Built-in IOC generation
- ✅ **Cross-Platform Forensic Support**: Linux-based analysis capability
- ✅ **Structured Output Formats**: Multiple CSV and JSON export options

### Unique Capabilities:
- 🚨 **Real-time Threat Assessment**: Immediate risk level identification
- 🎯 **APT Attribution**: Automatic detection of nation-state techniques  
- 📊 **IOC Automation**: Structured indicator extraction for hunting
- 🔍 **Forensic Workflow Integration**: Complete investigation guidance
- ⚡ **Performance Optimized**: Efficient parsing of large repositories