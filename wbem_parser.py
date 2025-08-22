#!/usr/bin/env python3
"""
Windows 11 WBEM Repository Parser
Parses Windows WMI repository files for forensic analysis.
Designed to run on Linux systems without internet connectivity.
"""

import os
import sys
import struct
import csv
import hashlib
import binascii
from datetime import datetime
import re
import glob
import traceback
from forensic_support import ForensicHandler, enhanced_repository_finder
from ccm_message_parser import CCMMessageParser
from enhanced_wmi_parser import EnhancedWMIParser


class WBEMRepositoryParser:
    """Main parser class for Windows WBEM repository files."""
    
    def __init__(self, repository_path, output_dir='.'):
        self.original_path = repository_path
        self.repository_path = repository_path
        self.output_dir = output_dir
        self.log_entries = []
        self.general_data = []
        self.wmi_classes = []
        self.forensic_handler = None
        self.ccm_parser = CCMMessageParser()
        self.enhanced_wmi_parser = EnhancedWMIParser()
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
    def log(self, message, level='INFO'):
        """Log messages with timestamp."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {level}: {message}"
        self.log_entries.append(log_entry)
        print(log_entry)
    
    def parse_repository(self):
        """Main parsing function to process all repository files."""
        self.log(f"Starting WBEM repository parsing: {self.original_path}")
        
        try:
            # Handle forensic inputs
            self.forensic_handler = ForensicHandler()
            self.repository_path = self.forensic_handler.prepare_input(self.original_path)
            self.log(f"Using repository path: {self.repository_path}")
            
            # Validate repository path
            if not self._validate_repository_path():
                return False
            
            # Parse core repository files with error handling
            self._safe_parse_component("index files", self._parse_index_file)
            self._safe_parse_component("objects files", self._parse_objects_file)
            self._safe_parse_component("mapping files", self._parse_mapping_files)
            
            # Parse CCM messages with enhanced parser
            self._safe_parse_component("CCM messages", self._parse_ccm_messages)
            
            # Enhanced WMI malicious activity detection
            self._safe_parse_component("WMI persistence analysis", self._parse_wmi_persistence)
            
            # Parse additional files with error handling
            self._safe_parse_component("MOF files", self._parse_mof_files)
            self._safe_parse_component("additional files", self._parse_additional_files)
            
            # Write output CSVs
            self._write_general_csv()
            self._write_wmi_csv()
            self._write_ccm_csvs()
            self._write_enhanced_wmi_csvs()
            self._write_log_file()
            
            self.log("Parsing completed successfully")
            return True
            
        except Exception as e:
            self.log(f"Critical error during parsing: {str(e)}", 'ERROR')
            self.log(f"Traceback: {traceback.format_exc()}", 'ERROR')
            return False
        
        finally:
            # Cleanup forensic handler
            if self.forensic_handler:
                self.forensic_handler.cleanup()
    
    def _validate_repository_path(self):
        """Validate that the repository path exists and contains expected files."""
        if not os.path.exists(self.repository_path):
            self.log(f"Repository path does not exist: {self.repository_path}", 'ERROR')
            return False
        
        # Check for core repository files
        core_files = ['INDEX.BTR', 'OBJECTS.DATA']
        found_files = []
        
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                if file.upper() in core_files:
                    found_files.append(file.upper())
        
        if not found_files:
            self.log("No core repository files found, checking for case variations", 'WARNING')
            # Try case-insensitive search
            for root, dirs, files in os.walk(self.repository_path):
                for file in files:
                    if file.lower() in [f.lower() for f in core_files]:
                        found_files.append(file.upper())
        
        self.log(f"Found repository files: {found_files}")
        return True
    
    def _safe_parse_component(self, component_name, parse_function):
        """Safely execute parsing functions with error handling."""
        try:
            self.log(f"Parsing {component_name}...")
            parse_function()
            self.log(f"Successfully parsed {component_name}")
        except Exception as e:
            self.log(f"Error parsing {component_name}: {str(e)}", 'ERROR')
            self.log(f"Continuing with other components...", 'WARNING')
    
    def _parse_index_file(self):
        """Parse the INDEX.BTR file containing binary tree index."""
        index_files = self._find_files(['INDEX.BTR', 'index.btr'])
        
        for index_file in index_files:
            self.log(f"Parsing index file: {index_file}")
            
            try:
                with open(index_file, 'rb') as f:
                    data = f.read()
                    
                # Parse binary tree header
                if len(data) < 32:
                    self.log(f"Index file too small: {len(data)} bytes", 'WARNING')
                    continue
                
                # Basic header parsing (simplified for robustness)
                header = data[:32]
                file_hash = hashlib.sha256(data).hexdigest()
                
                self.general_data.append({
                    'File_Path': index_file,
                    'File_Type': 'INDEX_BTR',
                    'Record_Type': 'HEADER',
                    'Object_ID': 'N/A',
                    'Class_Name': 'N/A',
                    'Namespace': 'N/A',
                    'Timestamp': datetime.fromtimestamp(os.path.getmtime(index_file)),
                    'Data_Size': len(data),
                    'Hash_Value': file_hash,
                    'Raw_Data_Sample': binascii.hexlify(header[:16]).decode()
                })
                
                # Parse index entries
                self._parse_index_entries(data, index_file)
                
            except Exception as e:
                self.log(f"Error parsing index file {index_file}: {str(e)}", 'ERROR')
    
    def _parse_index_entries(self, data, file_path):
        """Parse individual index entries from the binary tree."""
        offset = 32  # Skip header
        entry_count = 0
        
        while offset < len(data) - 8:
            try:
                # Simple entry parsing - adjust based on actual format
                if offset + 8 > len(data):
                    break
                
                # Read potential entry header
                entry_header = struct.unpack('<II', data[offset:offset+8])
                entry_size = entry_header[0]
                entry_type = entry_header[1]
                
                # Validate entry size
                if entry_size == 0 or entry_size > len(data) - offset:
                    offset += 8
                    continue
                
                if offset + entry_size > len(data):
                    break
                
                entry_data = data[offset:offset+entry_size]
                entry_hash = hashlib.md5(entry_data).hexdigest()
                
                self.general_data.append({
                    'File_Path': file_path,
                    'File_Type': 'INDEX_BTR',
                    'Record_Type': 'INDEX_ENTRY',
                    'Object_ID': entry_hash[:16],
                    'Class_Name': 'N/A',
                    'Namespace': 'N/A',
                    'Timestamp': datetime.fromtimestamp(os.path.getmtime(file_path)),
                    'Data_Size': entry_size,
                    'Hash_Value': entry_hash,
                    'Raw_Data_Sample': binascii.hexlify(entry_data[:16]).decode()
                })
                
                offset += max(entry_size, 8)
                entry_count += 1
                
                if entry_count > 10000:  # Prevent runaway parsing
                    self.log(f"Stopping index parsing after {entry_count} entries", 'WARNING')
                    break
                    
            except (struct.error, ValueError) as e:
                offset += 1  # Move forward byte by byte if struct parsing fails
                continue
        
        self.log(f"Parsed {entry_count} index entries from {file_path}")
    
    def _parse_objects_file(self):
        """Parse the OBJECTS.DATA file containing object records."""
        objects_files = self._find_files(['OBJECTS.DATA', 'objects.data'])
        
        for objects_file in objects_files:
            self.log(f"Parsing objects file: {objects_file}")
            
            try:
                with open(objects_file, 'rb') as f:
                    data = f.read()
                
                file_hash = hashlib.sha256(data).hexdigest()
                
                # Parse objects header
                if len(data) < 32:
                    self.log(f"Objects file too small: {len(data)} bytes", 'WARNING')
                    continue
                
                header = data[:32]
                self.general_data.append({
                    'File_Path': objects_file,
                    'File_Type': 'OBJECTS_DATA',
                    'Record_Type': 'HEADER',
                    'Object_ID': 'N/A',
                    'Class_Name': 'N/A',
                    'Namespace': 'N/A',
                    'Timestamp': datetime.fromtimestamp(os.path.getmtime(objects_file)),
                    'Data_Size': len(data),
                    'Hash_Value': file_hash,
                    'Raw_Data_Sample': binascii.hexlify(header[:16]).decode()
                })
                
                # Parse object records
                self._parse_object_records(data, objects_file)
                
            except Exception as e:
                self.log(f"Error parsing objects file {objects_file}: {str(e)}", 'ERROR')
    
    def _parse_object_records(self, data, file_path):
        """Parse individual object records from the objects data file."""
        offset = 32  # Skip header
        record_count = 0
        page_size = 8196  # Standard page size
        
        while offset < len(data) - 16:
            try:
                # Parse object descriptor
                if offset + 16 > len(data):
                    break
                
                # Basic object record parsing
                descriptor = struct.unpack('<IIII', data[offset:offset+16])
                record_size = descriptor[0]
                record_type = descriptor[1]
                object_id = descriptor[2]
                flags = descriptor[3]
                
                # Validate record size
                if record_size == 0 or record_size > len(data) - offset:
                    offset += 16
                    continue
                
                if offset + record_size > len(data):
                    break
                
                record_data = data[offset:offset+record_size]
                
                # Try to extract string data (UTF-16 LE)
                class_name = self._extract_utf16_string(record_data[16:])
                namespace = self._extract_namespace(record_data)
                
                record_hash = hashlib.md5(record_data).hexdigest()
                
                self.general_data.append({
                    'File_Path': file_path,
                    'File_Type': 'OBJECTS_DATA',
                    'Record_Type': 'OBJECT_RECORD',
                    'Object_ID': f"{object_id:08X}",
                    'Class_Name': class_name or 'Unknown',
                    'Namespace': namespace or 'Unknown',
                    'Timestamp': datetime.fromtimestamp(os.path.getmtime(file_path)),
                    'Data_Size': record_size,
                    'Hash_Value': record_hash,
                    'Raw_Data_Sample': binascii.hexlify(record_data[:32]).decode()
                })
                
                # Add to WMI classes if it looks like a class definition
                if class_name and self._is_class_definition(record_data):
                    self.wmi_classes.append({
                        'Class_Name': class_name,
                        'Namespace': namespace or 'root\\cimv2',
                        'Super_Class': self._extract_superclass(record_data),
                        'Properties': self._extract_properties(record_data),
                        'Methods': self._extract_methods(record_data),
                        'Provider': 'Unknown',
                        'MOF_Source': 'Repository',
                        'Registration_Status': 'Active',
                        'Instance_Count': 'Unknown'
                    })
                
                offset += max(record_size, 16)
                record_count += 1
                
                if record_count > 50000:  # Prevent runaway parsing
                    self.log(f"Stopping object parsing after {record_count} records", 'WARNING')
                    break
                    
            except (struct.error, ValueError) as e:
                offset += 1
                continue
        
        self.log(f"Parsed {record_count} object records from {file_path}")
    
    def _parse_mapping_files(self):
        """Parse mapping files (Mapping1.map, Mapping2.map, Mapping3.map)."""
        mapping_files = self._find_files(['MAPPING1.MAP', 'MAPPING2.MAP', 'MAPPING3.MAP',
                                         'mapping1.map', 'mapping2.map', 'mapping3.map'])
        
        for mapping_file in mapping_files:
            self.log(f"Parsing mapping file: {mapping_file}")
            
            try:
                with open(mapping_file, 'rb') as f:
                    data = f.read()
                
                file_hash = hashlib.sha256(data).hexdigest()
                
                self.general_data.append({
                    'File_Path': mapping_file,
                    'File_Type': 'MAPPING',
                    'Record_Type': 'MAPPING_DATA',
                    'Object_ID': 'N/A',
                    'Class_Name': 'N/A',
                    'Namespace': 'N/A',
                    'Timestamp': datetime.fromtimestamp(os.path.getmtime(mapping_file)),
                    'Data_Size': len(data),
                    'Hash_Value': file_hash,
                    'Raw_Data_Sample': binascii.hexlify(data[:32]).decode() if len(data) >= 32 else binascii.hexlify(data).decode()
                })
                
            except Exception as e:
                self.log(f"Error parsing mapping file {mapping_file}: {str(e)}", 'ERROR')
    
    def _parse_mof_files(self):
        """Parse MOF (Managed Object Format) files in the wbem directory."""
        wbem_dir = os.path.dirname(self.repository_path) if os.path.isfile(self.repository_path) else self.repository_path
        parent_dir = os.path.dirname(wbem_dir)
        
        # Look for MOF files in wbem directory and subdirectories
        mof_patterns = [
            os.path.join(wbem_dir, '*.mof'),
            os.path.join(wbem_dir, '*.MOF'),
            os.path.join(parent_dir, '*.mof'),
            os.path.join(parent_dir, '*.MOF')
        ]
        
        mof_files = []
        for pattern in mof_patterns:
            mof_files.extend(glob.glob(pattern))
        
        for mof_file in mof_files:
            self.log(f"Parsing MOF file: {mof_file}")
            
            try:
                # Try different encodings for MOF files
                content = None
                for encoding in ['utf-8', 'utf-16', 'ascii', 'latin-1']:
                    try:
                        with open(mof_file, 'r', encoding=encoding) as f:
                            content = f.read()
                        break
                    except UnicodeDecodeError:
                        continue
                
                if content is None:
                    self.log(f"Could not decode MOF file: {mof_file}", 'WARNING')
                    continue
                
                # Extract class definitions from MOF content
                classes = self._extract_mof_classes(content)
                
                file_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                
                self.general_data.append({
                    'File_Path': mof_file,
                    'File_Type': 'MOF',
                    'Record_Type': 'MOF_FILE',
                    'Object_ID': 'N/A',
                    'Class_Name': f"{len(classes)} classes",
                    'Namespace': self._extract_mof_namespace(content),
                    'Timestamp': datetime.fromtimestamp(os.path.getmtime(mof_file)),
                    'Data_Size': len(content),
                    'Hash_Value': file_hash,
                    'Raw_Data_Sample': content[:100].replace('\n', ' ').replace('\r', '')
                })
                
                # Add classes to WMI classes list
                for class_info in classes:
                    self.wmi_classes.append(class_info)
                
            except Exception as e:
                self.log(f"Error parsing MOF file {mof_file}: {str(e)}", 'ERROR')
    
    def _parse_additional_files(self):
        """Parse additional Windows system files related to WMI."""
        base_dir = os.path.dirname(self.repository_path) if os.path.isfile(self.repository_path) else self.repository_path
        
        # Look for additional files
        additional_patterns = [
            'WBEMESS.LOG',
            'WMIADAP.LOG',
            '*.dll',
            '*.exe'
        ]
        
        for pattern in additional_patterns:
            files = glob.glob(os.path.join(base_dir, pattern))
            files.extend(glob.glob(os.path.join(base_dir, pattern.lower())))
            
            for file_path in files[:20]:  # Limit to prevent too many files
                try:
                    stat = os.stat(file_path)
                    file_hash = self._calculate_file_hash(file_path)
                    
                    self.general_data.append({
                        'File_Path': file_path,
                        'File_Type': os.path.splitext(file_path)[1].upper().lstrip('.'),
                        'Record_Type': 'ADDITIONAL_FILE',
                        'Object_ID': 'N/A',
                        'Class_Name': 'N/A',
                        'Namespace': 'N/A',
                        'Timestamp': datetime.fromtimestamp(stat.st_mtime),
                        'Data_Size': stat.st_size,
                        'Hash_Value': file_hash,
                        'Raw_Data_Sample': 'Binary file'
                    })
                    
                except Exception as e:
                    self.log(f"Error processing additional file {file_path}: {str(e)}", 'WARNING')
    
    def _parse_ccm_messages(self):
        """Parse CCM messages from OBJECTS.DATA files using enhanced parser."""
        objects_files = self._find_files(['OBJECTS.DATA', 'objects.data'])
        
        for objects_file in objects_files:
            self.log(f"Parsing CCM messages from: {objects_file}")
            
            try:
                with open(objects_file, 'rb') as f:
                    data = f.read()
                
                # Use enhanced CCM parser
                objects_found = self.ccm_parser.parse_ccm_objects(data, objects_file)
                
                self.log(f"Found {objects_found} CCM objects in {objects_file}")
                self.log(f"  - {len(self.ccm_parser.recently_used_apps)} RecentlyUsedApps records")
                self.log(f"  - {len(self.ccm_parser.scheduler_messages)} Scheduler Messages")
                
                # Add CCM objects to general data for comprehensive reporting
                for ccm_obj in self.ccm_parser.ccm_objects:
                    self.general_data.append({
                        'File_Path': ccm_obj.get('source_file', objects_file),
                        'File_Type': 'CCM_OBJECT',
                        'Record_Type': ccm_obj.get('type', 'Unknown'),
                        'Object_ID': ccm_obj.get('object_id', 'N/A'),
                        'Class_Name': ccm_obj.get('type', 'Unknown'),
                        'Namespace': ccm_obj.get('namespace', 'root\\ccm'),
                        'Timestamp': ccm_obj.get('timestamp', datetime.now()),
                        'Data_Size': ccm_obj.get('size', 0),
                        'Hash_Value': hashlib.md5(ccm_obj.get('raw_data_sample', '').encode()).hexdigest(),
                        'Raw_Data_Sample': ccm_obj.get('raw_data_sample', '')
                    })
                
            except Exception as e:
                self.log(f"Error parsing CCM messages from {objects_file}: {str(e)}", 'ERROR')
    
    def _parse_wmi_persistence(self):
        """Parse OBJECTS.DATA files for WMI persistence mechanisms."""
        objects_files = self._find_files(['OBJECTS.DATA', 'objects.data'])
        
        for objects_file in objects_files:
            self.log(f"Analyzing WMI persistence in: {objects_file}")
            
            try:
                success = self.enhanced_wmi_parser.parse_objects_data(objects_file)
                if success:
                    self.log(f"Enhanced WMI analysis completed for {objects_file}")
                    
                    # Log summary of findings
                    self.log(f"  - Persistence objects: {len(self.enhanced_wmi_parser.persistence_objects)}")
                    self.log(f"  - Suspicious objects: {len(self.enhanced_wmi_parser.suspicious_classes)}")
                    self.log(f"  - WQL queries: {len(self.enhanced_wmi_parser.wql_queries)}")
                    self.log(f"  - Deleted objects: {len(self.enhanced_wmi_parser.deleted_objects)}")
                else:
                    self.log(f"Enhanced WMI analysis failed for {objects_file}", 'WARNING')
                    
            except Exception as e:
                self.log(f"Error in enhanced WMI analysis for {objects_file}: {str(e)}", 'ERROR')
    
    def _find_files(self, filenames):
        """Find files with given names in the repository path."""
        found_files = []
        
        for root, dirs, files in os.walk(self.repository_path):
            for file in files:
                if file in filenames:
                    found_files.append(os.path.join(root, file))
        
        return found_files
    
    def _extract_utf16_string(self, data, max_length=256):
        """Extract UTF-16 LE string from binary data."""
        try:
            # Look for string patterns in UTF-16 LE
            for i in range(0, min(len(data) - 1, max_length * 2), 2):
                if data[i] == 0 and data[i + 1] == 0:  # Null terminator
                    if i > 0:
                        string_data = data[:i]
                        return string_data.decode('utf-16le', errors='ignore').strip()
                    break
            
            # Try to decode first part if no null terminator found
            if len(data) >= 2:
                string_data = data[:min(len(data), max_length * 2)]
                if len(string_data) % 2 == 1:
                    string_data = string_data[:-1]
                decoded = string_data.decode('utf-16le', errors='ignore').strip()
                if decoded and all(ord(c) < 256 and ord(c) > 0 for c in decoded[:20]):
                    return decoded
                    
        except Exception:
            pass
        
        return None
    
    def _extract_namespace(self, data):
        """Extract namespace from object record data."""
        # Look for common namespace patterns
        namespace_patterns = [
            b'root\\cimv2',
            b'root\\default',
            b'root\\wmi',
            b'root\\microsoftwmi'
        ]
        
        for pattern in namespace_patterns:
            if pattern in data:
                return pattern.decode('ascii')
        
        # Try to find UTF-16 namespace
        try:
            for i in range(len(data) - 20):
                if data[i:i+8] == b'r\x00o\x00o\x00t\x00':  # "root" in UTF-16
                    # Extract up to next null
                    end = i + 8
                    while end < len(data) - 1 and not (data[end] == 0 and data[end + 1] == 0):
                        end += 2
                    namespace_data = data[i:end]
                    return namespace_data.decode('utf-16le', errors='ignore')
        except Exception:
            pass
        
        return None
    
    def _is_class_definition(self, data):
        """Determine if object record contains a class definition."""
        # Look for class definition indicators
        class_indicators = [
            b'class',
            b'Class',
            b'[key]',
            b'[Key]',
            b'property',
            b'Property'
        ]
        
        for indicator in class_indicators:
            if indicator in data:
                return True
        
        return False
    
    def _extract_superclass(self, data):
        """Extract superclass name from object data."""
        # Simple pattern matching for superclass
        superclass_patterns = [
            b'CIM_',
            b'Win32_',
            b'__SystemClass'
        ]
        
        for pattern in superclass_patterns:
            if pattern in data:
                # Try to extract full name
                start = data.find(pattern)
                if start != -1:
                    end = start
                    while end < len(data) and data[end] not in [0, ord(' '), ord('\n'), ord('\r')]:
                        end += 1
                    return data[start:end].decode('ascii', errors='ignore')
        
        return 'Unknown'
    
    def _extract_properties(self, data):
        """Extract property information from object data."""
        # Count potential properties
        property_count = data.count(b'property') + data.count(b'Property')
        if property_count > 0:
            return f"{property_count} properties"
        return 'Unknown'
    
    def _extract_methods(self, data):
        """Extract method information from object data."""
        # Count potential methods
        method_count = data.count(b'method') + data.count(b'Method')
        if method_count > 0:
            return f"{method_count} methods"
        return 'Unknown'
    
    def _extract_mof_classes(self, content):
        """Extract class definitions from MOF file content."""
        classes = []
        
        # Simple regex to find class definitions
        class_pattern = r'class\s+(\w+)(?:\s*:\s*(\w+))?\s*\{'
        matches = re.finditer(class_pattern, content, re.IGNORECASE)
        
        for match in matches:
            class_name = match.group(1)
            superclass = match.group(2) if match.group(2) else 'Unknown'
            
            # Extract class body
            start = match.end()
            brace_count = 1
            end = start
            
            while end < len(content) and brace_count > 0:
                if content[end] == '{':
                    brace_count += 1
                elif content[end] == '}':
                    brace_count -= 1
                end += 1
            
            class_body = content[start:end-1] if end <= len(content) else ''
            
            # Count properties and methods
            properties = len(re.findall(r'\s*\w+\s+\w+\s*;', class_body))
            methods = len(re.findall(r'\s*\w+\s+\w+\s*\(', class_body))
            
            classes.append({
                'Class_Name': class_name,
                'Namespace': self._extract_mof_namespace(content),
                'Super_Class': superclass,
                'Properties': f"{properties} properties",
                'Methods': f"{methods} methods",
                'Provider': self._extract_mof_provider(content),
                'MOF_Source': 'MOF File',
                'Registration_Status': 'Defined',
                'Instance_Count': 'Unknown'
            })
        
        return classes
    
    def _extract_mof_namespace(self, content):
        """Extract namespace from MOF content."""
        namespace_pattern = r'#pragma\s+namespace\s*\(\s*["\']([^"\']+)["\']'
        match = re.search(namespace_pattern, content, re.IGNORECASE)
        return match.group(1) if match else 'root\\cimv2'
    
    def _extract_mof_provider(self, content):
        """Extract provider information from MOF content."""
        provider_pattern = r'provider\s*\(\s*["\']([^"\']+)["\']'
        match = re.search(provider_pattern, content, re.IGNORECASE)
        return match.group(1) if match else 'Unknown'
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return 'Error'
    
    def _write_general_csv(self):
        """Write general repository data to CSV."""
        output_file = os.path.join(self.output_dir, 'wbem_general.csv')
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['File_Path', 'File_Type', 'Record_Type', 'Object_ID', 
                         'Class_Name', 'Namespace', 'Timestamp', 'Data_Size', 
                         'Hash_Value', 'Raw_Data_Sample']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in self.general_data:
                writer.writerow(row)
        
        self.log(f"Written {len(self.general_data)} records to {output_file}")
    
    def _write_wmi_csv(self):
        """Write WMI-specific data to CSV."""
        output_file = os.path.join(self.output_dir, 'wmi_classes.csv')
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Class_Name', 'Namespace', 'Super_Class', 'Properties', 
                         'Methods', 'Provider', 'MOF_Source', 'Registration_Status', 
                         'Instance_Count']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in self.wmi_classes:
                writer.writerow(row)
        
        self.log(f"Written {len(self.wmi_classes)} WMI classes to {output_file}")
    
    def _write_ccm_csvs(self):
        """Write CCM-specific CSV files."""
        # Write CCM objects overview
        ccm_overview_file = os.path.join(self.output_dir, 'ccm_objects.csv')
        if self.ccm_parser.ccm_objects:
            self.ccm_parser.export_ccm_objects_to_csv(ccm_overview_file)
            self.log(f"Written {len(self.ccm_parser.ccm_objects)} CCM objects to {ccm_overview_file}")
        
        # Write RecentlyUsedApps if any found
        if self.ccm_parser.recently_used_apps:
            rua_file = os.path.join(self.output_dir, 'ccm_recently_used_apps.csv')
            self.ccm_parser.export_recently_used_apps_to_csv(rua_file)
            self.log(f"Written {len(self.ccm_parser.recently_used_apps)} RecentlyUsedApps records to {rua_file}")
        
        # Write SchedulerMessages if any found
        if self.ccm_parser.scheduler_messages:
            scheduler_file = os.path.join(self.output_dir, 'ccm_scheduler_messages.csv')
            self.ccm_parser.export_scheduler_messages_to_csv(scheduler_file)
            self.log(f"Written {len(self.ccm_parser.scheduler_messages)} Scheduler Messages to {scheduler_file}")
    
    def _write_enhanced_wmi_csvs(self):
        """Write enhanced WMI analysis CSV files."""
        # Create subdirectory for WMI analysis results
        wmi_analysis_dir = os.path.join(self.output_dir, 'wmi_analysis')
        
        try:
            # Export enhanced WMI findings
            self.enhanced_wmi_parser.export_results(wmi_analysis_dir)
            
            # Log summary of exported files
            if self.enhanced_wmi_parser.persistence_objects:
                self.log(f"Written {len(self.enhanced_wmi_parser.persistence_objects)} WMI persistence objects")
            if self.enhanced_wmi_parser.suspicious_classes:
                self.log(f"Written {len(self.enhanced_wmi_parser.suspicious_classes)} suspicious WMI objects")
            if self.enhanced_wmi_parser.wql_queries:
                self.log(f"Written {len(self.enhanced_wmi_parser.wql_queries)} WQL queries")
            if self.enhanced_wmi_parser.deleted_objects:
                self.log(f"Written {len(self.enhanced_wmi_parser.deleted_objects)} potentially deleted objects")
                
        except Exception as e:
            self.log(f"Error writing enhanced WMI CSV files: {str(e)}", 'ERROR')
    
    def _write_log_file(self):
        """Write parsing log to file."""
        log_file = os.path.join(self.output_dir, 'parsing_log.txt')
        
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write("WBEM Repository Parser Log\n")
            f.write("=" * 50 + "\n\n")
            
            for entry in self.log_entries:
                f.write(entry + "\n")
        
        self.log(f"Written parsing log to {log_file}")


def main():
    """Main function to run the WBEM parser."""
    if len(sys.argv) < 2:
        print("Usage: python wbem_parser.py <repository_path> [output_directory]")
        print("Example: python wbem_parser.py /mnt/windows/Windows/System32/wbem/Repository")
        sys.exit(1)
    
    repository_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './output'
    
    parser = WBEMRepositoryParser(repository_path, output_dir)
    
    try:
        success = parser.parse_repository()
        if success:
            print(f"\nParsing completed successfully!")
            print(f"Output files written to: {output_dir}")
            print(f"- wbem_general.csv: General repository data")
            print(f"- wmi_classes.csv: WMI class information")
            print(f"- ccm_objects.csv: CCM objects overview (if found)")
            print(f"- ccm_recently_used_apps.csv: Recently used applications (if found)")
            print(f"- ccm_scheduler_messages.csv: Scheduler messages (if found)")
            print(f"- wmi_analysis/: Enhanced WMI malicious activity analysis")
            print(f"  - wmi_persistence_objects.csv: WMI persistence mechanisms")
            print(f"  - wmi_suspicious_objects.csv: Objects with suspicious content")
            print(f"  - wmi_wql_queries.csv: Extracted WQL queries")
            print(f"  - wmi_deleted_objects.csv: Potentially deleted persistence objects")
            print(f"- parsing_log.txt: Detailed parsing log")
        else:
            print("Parsing failed. Check the log for details.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nParsing interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()