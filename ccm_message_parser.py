#!/usr/bin/env python3
"""
Enhanced CCM Message Parser for WBEM Repository
Specifically targets CCM_Scheduler_Messages and other CCM/SCCM objects.
"""

import os
import sys
import struct
import hashlib
import binascii
from datetime import datetime, timedelta
import re


class CCMMessageParser:
    """Enhanced parser for CCM messages and SCCM objects in WMI repository."""
    
    def __init__(self):
        self.ccm_objects = []
        self.scheduler_messages = []
        self.recently_used_apps = []
        
        # Known CCM object hashes and signatures
        self.ccm_signatures = {
            # CCM_RecentlyUsedApps hashes (from forensic research)
            'xp_md5': b'\x6f\xa6\x2f\x46\x2b\xef\x74\x0f\x82\x0d\x72\xd9\x25\x0d\x74\x3c',
            'vista_sha256': b'\x7c\x26\x15\x51\xb2\x64\xd3\x5e\x30\xa7\xfa\x29\xc7\x52\x83\xda\xe0\x4b\xba\x71\xdb\xe8\xf5\xe5\x53\xf7\xad\x38\x1b\x40\x6d\xd8',
            
            # CCM_Scheduler related patterns
            'ccm_scheduler': [
                b'CCM_Scheduler_ScheduledMessage',
                b'CCM_Scheduler_History',
                b'CCM_Scheduler_Messages',
                b'ScheduledMessage',
            ],
            
            # CCM namespace patterns
            'ccm_namespaces': [
                b'root\\ccm',
                b'root\\ccm\\policy',
                b'root\\ccm\\SoftwareMeteringAgent',
                b'root\\ccm\\ClientSDK',
            ]
        }
        
        # CCM_RecentlyUsedApps property mapping (18 properties)
        self.rua_properties = [
            'ClassName', 'LastUsedTime', 'LastUsername', 'ProductName',
            'FolderPath', 'FileDescription', 'FileVersion', 'FileSize',
            'LaunchCount', 'CompanyName', 'ProductVersion', 'AdditionalProductCodes',
            'MSIVersion', 'MSIDisplayName', 'MSIPublisher', 'SoftwarePropertiesHash',
            'ProductLanguage', 'ExplorerFileName'
        ]
    
    def parse_ccm_objects(self, data, file_path):
        """Parse CCM objects from OBJECTS.DATA binary data."""
        offset = 0
        objects_found = 0
        
        while offset < len(data) - 32:
            # Look for CCM signatures
            ccm_object = self._find_ccm_object_at_offset(data, offset)
            if ccm_object:
                objects_found += 1
                ccm_object['source_file'] = file_path
                ccm_object['file_offset'] = offset
                self.ccm_objects.append(ccm_object)
                
                # Parse specific CCM object types
                if ccm_object['type'] == 'CCM_RecentlyUsedApps':
                    rua_data = self._parse_recently_used_apps(data, offset, ccm_object)
                    if rua_data:
                        self.recently_used_apps.append(rua_data)
                
                elif ccm_object['type'] == 'CCM_Scheduler_Messages':
                    scheduler_data = self._parse_scheduler_messages(data, offset, ccm_object)
                    if scheduler_data:
                        self.scheduler_messages.append(scheduler_data)
                
                # Skip ahead to avoid duplicate detections
                offset += max(ccm_object.get('size', 32), 32)
            else:
                offset += 1
        
        return objects_found
    
    def _find_ccm_object_at_offset(self, data, offset):
        """Find CCM object at specific offset."""
        if offset + 32 > len(data):
            return None
        
        # Check for known CCM signatures
        for sig_name, patterns in self.ccm_signatures.items():
            if sig_name in ['ccm_scheduler', 'ccm_namespaces']:
                for pattern in patterns:
                    if self._pattern_match_at_offset(data, offset, pattern):
                        return self._extract_ccm_object_info(data, offset, pattern, sig_name)
        
        # Check for CCM_RecentlyUsedApps hash signatures
        if self._check_rua_hash_signature(data, offset):
            return self._extract_ccm_object_info(data, offset, b'CCM_RecentlyUsedApps', 'rua_hash')
        
        return None
    
    def _pattern_match_at_offset(self, data, offset, pattern):
        """Check if pattern matches at offset (within reasonable range)."""
        search_range = min(128, len(data) - offset)
        return pattern in data[offset:offset + search_range]
    
    def _check_rua_hash_signature(self, data, offset):
        """Check for CCM_RecentlyUsedApps hash signatures."""
        if offset + 32 > len(data):
            return False
        
        # Check for XP MD5 hash
        if data[offset:offset + 16] == self.ccm_signatures['xp_md5']:
            return True
        
        # Check for Vista+ SHA256 hash
        if offset + 32 <= len(data) and data[offset:offset + 32] == self.ccm_signatures['vista_sha256']:
            return True
        
        return False
    
    def _extract_ccm_object_info(self, data, offset, pattern, sig_type):
        """Extract basic CCM object information."""
        try:
            # Try to parse object header if it exists
            if offset + 16 <= len(data):
                header = struct.unpack('<IIII', data[offset:offset + 16])
                record_size = header[0]
                record_type = header[1]
                object_id = header[2]
                flags = header[3]
            else:
                record_size = 0
                record_type = 0
                object_id = 0
                flags = 0
            
            # Determine object type from pattern
            if isinstance(pattern, bytes):
                if b'CCM_RecentlyUsedApps' in pattern:
                    obj_type = 'CCM_RecentlyUsedApps'
                elif b'CCM_Scheduler' in pattern:
                    obj_type = 'CCM_Scheduler_Messages'
                elif b'ScheduledMessage' in pattern:
                    obj_type = 'CCM_Scheduler_ScheduledMessage'
                else:
                    obj_type = pattern.decode('ascii', errors='ignore')
            else:
                obj_type = 'CCM_Unknown'
            
            # Extract namespace if possible
            namespace = self._extract_namespace_at_offset(data, offset)
            
            return {
                'type': obj_type,
                'signature_type': sig_type,
                'size': record_size if record_size > 0 and record_size < 1024*1024 else 256,
                'record_type': record_type,
                'object_id': f"{object_id:08X}" if object_id > 0 else 'Unknown',
                'flags': flags,
                'namespace': namespace,
                'raw_data_sample': binascii.hexlify(data[offset:offset + 32]).decode(),
                'timestamp': datetime.now()
            }
            
        except (struct.error, ValueError, UnicodeDecodeError):
            return None
    
    def _extract_namespace_at_offset(self, data, offset):
        """Extract CCM namespace from data around offset."""
        search_start = max(0, offset - 256)
        search_end = min(len(data), offset + 512)
        search_data = data[search_start:search_end]
        
        for namespace_pattern in self.ccm_signatures['ccm_namespaces']:
            if namespace_pattern in search_data:
                try:
                    # Try to extract the full namespace
                    start_idx = search_data.find(namespace_pattern)
                    if start_idx != -1:
                        # Look for null terminator or end of reasonable namespace
                        end_idx = start_idx + len(namespace_pattern)
                        while end_idx < len(search_data) and search_data[end_idx] not in [0, ord('\n'), ord('\r')]:
                            if end_idx - start_idx > 128:  # Reasonable namespace limit
                                break
                            end_idx += 1
                        
                        namespace = search_data[start_idx:end_idx].decode('ascii', errors='ignore')
                        return namespace
                except UnicodeDecodeError:
                    pass
        
        return 'root\\ccm'
    
    def _parse_recently_used_apps(self, data, offset, ccm_object):
        """Parse CCM_RecentlyUsedApps record structure."""
        try:
            # Start after the hash signature
            if ccm_object['signature_type'] == 'rua_hash':
                if data[offset:offset + 16] == self.ccm_signatures['xp_md5']:
                    data_start = offset + 16
                elif data[offset:offset + 32] == self.ccm_signatures['vista_sha256']:
                    data_start = offset + 32
                else:
                    return None
            else:
                data_start = offset
            
            if data_start + 32 > len(data):
                return None
            
            # Parse FileTimes (two 8-byte values)
            if data_start + 16 <= len(data):
                filetime1, filetime2 = struct.unpack('<QQ', data[data_start:data_start + 16])
                last_used_time = self._filetime_to_datetime(filetime1)
                creation_time = self._filetime_to_datetime(filetime2)
                data_start += 16
            else:
                last_used_time = None
                creation_time = None
            
            # Parse size indicator (2 bytes)
            if data_start + 2 <= len(data):
                size_indicator = struct.unpack('<H', data[data_start:data_start + 2])[0]
                data_start += 2
            else:
                size_indicator = 0
            
            # Parse string properties
            properties = {}
            current_offset = data_start
            
            for i, prop_name in enumerate(self.rua_properties):
                if current_offset >= len(data):
                    break
                
                try:
                    # Try to extract UTF-16 string
                    string_value = self._extract_utf16_string_at_offset(data, current_offset)
                    if string_value:
                        properties[prop_name] = string_value
                        # Move offset past the string (UTF-16 + null terminator)
                        string_bytes = len(string_value.encode('utf-16le')) + 2
                        current_offset += string_bytes
                    else:
                        # Try ASCII string
                        string_value = self._extract_ascii_string_at_offset(data, current_offset)
                        if string_value:
                            properties[prop_name] = string_value
                            current_offset += len(string_value) + 1
                        else:
                            current_offset += 1
                            
                except (UnicodeDecodeError, struct.error):
                    current_offset += 1
                    continue
            
            return {
                'type': 'CCM_RecentlyUsedApps',
                'last_used_time': last_used_time,
                'creation_time': creation_time,
                'size_indicator': size_indicator,
                'properties': properties,
                'source_file': ccm_object['source_file'],
                'file_offset': ccm_object['file_offset'],
                'raw_data_sample': ccm_object['raw_data_sample']
            }
            
        except (struct.error, ValueError, UnicodeDecodeError) as e:
            return None
    
    def _parse_scheduler_messages(self, data, offset, ccm_object):
        """Parse CCM_Scheduler_Messages record structure."""
        try:
            # Look for scheduler message properties
            search_range = min(1024, len(data) - offset)
            search_data = data[offset:offset + search_range]
            
            properties = {}
            
            # Look for common scheduler message properties
            scheduler_patterns = {
                'ScheduleID': [b'ScheduleID', b'scheduleID'],
                'UserSID': [b'UserSID', b'userSID'],
                'ActiveTime': [b'ActiveTime', b'activeTime'],
                'ExpireTime': [b'ExpireTime', b'expireTime'],
                'Triggers': [b'Triggers', b'triggers'],
                'LaunchConditions': [b'LaunchConditions', b'launchConditions'],
                'TargetEndpoint': [b'TargetEndpoint', b'targetEndpoint'],
                'MessageTimeout': [b'MessageTimeout', b'messageTimeout']
            }
            
            for prop_name, patterns in scheduler_patterns.items():
                for pattern in patterns:
                    if pattern in search_data:
                        # Try to extract the value after the property name
                        prop_offset = search_data.find(pattern) + len(pattern)
                        if prop_offset < len(search_data):
                            value = self._extract_property_value(search_data, prop_offset)
                            if value:
                                properties[prop_name] = value
                        break
            
            # Look for FILETIME values (common in scheduler messages)
            filetime_values = []
            for i in range(0, len(search_data) - 8, 4):
                try:
                    potential_filetime = struct.unpack('<Q', search_data[i:i + 8])[0]
                    if self._is_valid_filetime(potential_filetime):
                        dt = self._filetime_to_datetime(potential_filetime)
                        if dt:
                            filetime_values.append(dt)
                except struct.error:
                    continue
            
            return {
                'type': 'CCM_Scheduler_Messages',
                'properties': properties,
                'filetime_values': filetime_values,
                'source_file': ccm_object['source_file'],
                'file_offset': ccm_object['file_offset'],
                'raw_data_sample': ccm_object['raw_data_sample']
            }
            
        except (struct.error, ValueError) as e:
            return None
    
    def _extract_utf16_string_at_offset(self, data, offset):
        """Extract UTF-16 string at specific offset."""
        try:
            max_length = min(256, len(data) - offset)
            for i in range(2, max_length, 2):
                if offset + i + 1 < len(data) and data[offset + i] == 0 and data[offset + i + 1] == 0:
                    string_data = data[offset:offset + i]
                    if len(string_data) % 2 == 0:
                        decoded = string_data.decode('utf-16le', errors='ignore').strip()
                        if decoded and all(ord(c) >= 32 and ord(c) < 127 for c in decoded[:10]):
                            return decoded
                    break
        except (UnicodeDecodeError, IndexError):
            pass
        return None
    
    def _extract_ascii_string_at_offset(self, data, offset):
        """Extract ASCII string at specific offset."""
        try:
            max_length = min(128, len(data) - offset)
            for i in range(1, max_length):
                if offset + i < len(data) and data[offset + i] == 0:
                    string_data = data[offset:offset + i]
                    try:
                        decoded = string_data.decode('ascii').strip()
                        if decoded and all(ord(c) >= 32 and ord(c) < 127 for c in decoded):
                            return decoded
                    except UnicodeDecodeError:
                        return None
                    break
        except IndexError:
            pass
        return None
    
    def _extract_property_value(self, data, offset):
        """Extract property value after property name."""
        # Skip whitespace and delimiters
        while offset < len(data) and data[offset] in [0, ord(' '), ord('='), ord(':'), ord('\t')]:
            offset += 1
        
        if offset >= len(data):
            return None
        
        # Try UTF-16 first
        utf16_value = self._extract_utf16_string_at_offset(data, offset)
        if utf16_value:
            return utf16_value
        
        # Try ASCII
        ascii_value = self._extract_ascii_string_at_offset(data, offset)
        if ascii_value:
            return ascii_value
        
        # Try extracting as hex if it looks like binary data
        if offset + 8 <= len(data):
            hex_value = binascii.hexlify(data[offset:offset + 8]).decode()
            return f"0x{hex_value}"
        
        return None
    
    def _filetime_to_datetime(self, filetime):
        """Convert Windows FILETIME to datetime object."""
        try:
            if filetime == 0:
                return None
            
            # FILETIME is 100-nanosecond intervals since January 1, 1601
            # Convert to seconds since epoch (January 1, 1970)
            epoch_diff = 11644473600  # Seconds between 1601 and 1970
            timestamp = (filetime / 10000000.0) - epoch_diff
            
            # Validate reasonable timestamp range
            if timestamp < 0 or timestamp > 4102444800:  # Year 2100
                return None
            
            return datetime.fromtimestamp(timestamp)
        except (ValueError, OverflowError):
            return None
    
    def _is_valid_filetime(self, filetime):
        """Check if value looks like a valid FILETIME."""
        if filetime == 0:
            return False
        
        # Convert to timestamp to check range
        epoch_diff = 11644473600
        timestamp = (filetime / 10000000.0) - epoch_diff
        
        # Check if timestamp is in reasonable range (1980 to 2100)
        return 315532800 <= timestamp <= 4102444800  # 1980-01-01 to 2100-01-01
    
    def export_ccm_objects_to_csv(self, output_file):
        """Export CCM objects to CSV format."""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Type', 'Object_ID', 'Namespace', 'Source_File', 'File_Offset', 
                         'Record_Type', 'Size', 'Flags', 'Signature_Type', 'Timestamp', 
                         'Raw_Data_Sample']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for obj in self.ccm_objects:
                writer.writerow({
                    'Type': obj.get('type', ''),
                    'Object_ID': obj.get('object_id', ''),
                    'Namespace': obj.get('namespace', ''),
                    'Source_File': obj.get('source_file', ''),
                    'File_Offset': obj.get('file_offset', ''),
                    'Record_Type': obj.get('record_type', ''),
                    'Size': obj.get('size', ''),
                    'Flags': obj.get('flags', ''),
                    'Signature_Type': obj.get('signature_type', ''),
                    'Timestamp': obj.get('timestamp', ''),
                    'Raw_Data_Sample': obj.get('raw_data_sample', '')
                })
    
    def export_recently_used_apps_to_csv(self, output_file):
        """Export CCM_RecentlyUsedApps to CSV format."""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Last_Used_Time', 'Creation_Time', 'Product_Name', 'Folder_Path',
                         'File_Description', 'File_Version', 'Company_Name', 'Last_Username',
                         'Launch_Count', 'Source_File', 'File_Offset', 'All_Properties']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for rua in self.recently_used_apps:
                props = rua.get('properties', {})
                writer.writerow({
                    'Last_Used_Time': rua.get('last_used_time', ''),
                    'Creation_Time': rua.get('creation_time', ''),
                    'Product_Name': props.get('ProductName', ''),
                    'Folder_Path': props.get('FolderPath', ''),
                    'File_Description': props.get('FileDescription', ''),
                    'File_Version': props.get('FileVersion', ''),
                    'Company_Name': props.get('CompanyName', ''),
                    'Last_Username': props.get('LastUsername', ''),
                    'Launch_Count': props.get('LaunchCount', ''),
                    'Source_File': rua.get('source_file', ''),
                    'File_Offset': rua.get('file_offset', ''),
                    'All_Properties': str(props)
                })
    
    def export_scheduler_messages_to_csv(self, output_file):
        """Export CCM_Scheduler_Messages to CSV format."""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Schedule_ID', 'User_SID', 'Active_Time', 'Expire_Time',
                         'Target_Endpoint', 'Message_Timeout', 'Triggers', 'Launch_Conditions',
                         'Filetime_Values', 'Source_File', 'File_Offset', 'All_Properties']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for msg in self.scheduler_messages:
                props = msg.get('properties', {})
                filetime_values = [str(dt) for dt in msg.get('filetime_values', [])]
                
                writer.writerow({
                    'Schedule_ID': props.get('ScheduleID', ''),
                    'User_SID': props.get('UserSID', ''),
                    'Active_Time': props.get('ActiveTime', ''),
                    'Expire_Time': props.get('ExpireTime', ''),
                    'Target_Endpoint': props.get('TargetEndpoint', ''),
                    'Message_Timeout': props.get('MessageTimeout', ''),
                    'Triggers': props.get('Triggers', ''),
                    'Launch_Conditions': props.get('LaunchConditions', ''),
                    'Filetime_Values': '; '.join(filetime_values),
                    'Source_File': msg.get('source_file', ''),
                    'File_Offset': msg.get('file_offset', ''),
                    'All_Properties': str(props)
                })


if __name__ == "__main__":
    """Test the CCM message parser."""
    if len(sys.argv) < 2:
        print("Usage: python ccm_message_parser.py <objects_data_file> [output_prefix]")
        sys.exit(1)
    
    objects_file = sys.argv[1]
    output_prefix = sys.argv[2] if len(sys.argv) > 2 else 'ccm_analysis'
    
    if not os.path.exists(objects_file):
        print(f"Error: File not found: {objects_file}")
        sys.exit(1)
    
    print(f"Parsing CCM objects from: {objects_file}")
    
    parser = CCMMessageParser()
    
    try:
        with open(objects_file, 'rb') as f:
            data = f.read()
        
        print(f"Loaded {len(data)} bytes from OBJECTS.DATA file")
        
        objects_found = parser.parse_ccm_objects(data, objects_file)
        print(f"Found {objects_found} CCM objects")
        print(f"  - {len(parser.recently_used_apps)} RecentlyUsedApps records")
        print(f"  - {len(parser.scheduler_messages)} Scheduler Messages")
        
        # Export results
        parser.export_ccm_objects_to_csv(f"{output_prefix}_ccm_objects.csv")
        if parser.recently_used_apps:
            parser.export_recently_used_apps_to_csv(f"{output_prefix}_recently_used_apps.csv")
        if parser.scheduler_messages:
            parser.export_scheduler_messages_to_csv(f"{output_prefix}_scheduler_messages.csv")
        
        print(f"Results exported to {output_prefix}_*.csv files")
        
    except Exception as e:
        print(f"Error parsing file: {str(e)}")
        sys.exit(1)