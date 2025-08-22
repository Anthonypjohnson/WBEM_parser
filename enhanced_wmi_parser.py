#!/usr/bin/env python3
"""
Enhanced WMI Forensic Parser
Comprehensive parsing of WMI OBJECTS.DATA for malicious activity detection.
Based on research from Mandiant and other WMI forensic tools.
"""

import os
import sys
import struct
import hashlib
import binascii
from datetime import datetime
import re
import csv
from wmi_threat_intelligence import WMIThreatIntelligence, WMIPersistenceAnalyzer


class EnhancedWMIParser:
    """Enhanced WMI parser focusing on malicious activity detection."""
    
    def __init__(self):
        self.persistence_objects = []
        self.event_consumers = []
        self.event_filters = []
        self.filter_bindings = []
        self.suspicious_classes = []
        self.wql_queries = []
        self.deleted_objects = []
        self.threat_analysis_results = []
        
        # Initialize threat intelligence modules
        self.threat_intel = WMIThreatIntelligence()
        self.persistence_analyzer = WMIPersistenceAnalyzer()
        
        # Known malicious WMI patterns
        self.malicious_patterns = {
            'persistence_classes': [
                b'__FilterToConsumerBinding',
                b'__EventFilter',
                b'__EventConsumer',
                b'ActiveScriptEventConsumer',
                b'CommandLineEventConsumer',
                b'LogFileEventConsumer',
                b'NTEventLogEventConsumer',
                b'SMTPEventConsumer'
            ],
            'suspicious_namespaces': [
                b'root\\subscription',
                b'root\\cimv2',
                b'root\\default'
            ],
            'malicious_keywords': [
                b'powershell',
                b'cmd.exe',
                b'wscript',
                b'cscript',
                b'rundll32',
                b'regsvr32',
                b'mshta',
                b'bitsadmin',
                b'certutil',
                b'InstallUtil',
                b'MSBuild',
                b'invoke-expression',
                b'iex',
                b'downloadstring',
                b'base64',
                b'frombase64string'
            ],
            'persistence_properties': [
                b'CommandLineTemplate',
                b'ExecutablePath',
                b'ScriptText',
                b'ScriptingEngine',
                b'WorkingDirectory',
                b'Name',
                b'Query',
                b'QueryLanguage',
                b'EventNamespace'
            ]
        }
        
        # WMI repository structure constants
        self.OBJECT_HEADER_SIZE = 16
        self.PAGE_SIZE = 8192
        self.MAX_OBJECT_SIZE = 1024 * 1024  # 1MB safety limit
    
    def parse_objects_data(self, file_path):
        """Parse OBJECTS.DATA file for comprehensive WMI analysis."""
        print(f"[+] Parsing OBJECTS.DATA: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            print(f"[+] Loaded {len(data)} bytes")
            
            # Parse repository header
            self._parse_repository_header(data)
            
            # Parse object records
            self._parse_object_records(data, file_path)
            
            # Parse unallocated space for deleted objects
            self._parse_unallocated_space(data, file_path)
            
            # Analyze for persistence mechanisms
            persistence_chains = self._analyze_persistence_mechanisms()
            
            # Perform advanced threat analysis
            self._perform_threat_analysis()
            
            # Generate threat intelligence report
            self._generate_threat_analysis()
            
            return True
            
        except Exception as e:
            print(f"[!] Error parsing OBJECTS.DATA: {str(e)}")
            return False
    
    def _parse_repository_header(self, data):
        """Parse WMI repository header information."""
        if len(data) < 32:
            print("[!] File too small to contain valid header")
            return
        
        try:
            # Parse basic header structure
            header = struct.unpack('<8I', data[:32])
            print(f"[+] Repository Header:")
            print(f"    Signature: 0x{header[0]:08X}")
            print(f"    Version: {header[1]}")
            print(f"    Page Count: {header[2]}")
            print(f"    First Free Page: {header[3]}")
            
        except struct.error as e:
            print(f"[!] Error parsing header: {str(e)}")
    
    def _parse_object_records(self, data, file_path):
        """Parse individual WMI object records."""
        offset = 32  # Skip header
        object_count = 0
        
        print("[+] Parsing object records...")
        
        while offset < len(data) - self.OBJECT_HEADER_SIZE:
            try:
                # Parse object header
                if offset + self.OBJECT_HEADER_SIZE > len(data):
                    break
                
                header = struct.unpack('<IIII', data[offset:offset + self.OBJECT_HEADER_SIZE])
                record_size = header[0]
                record_type = header[1]
                object_id = header[2]
                flags = header[3]
                
                # Validate record size
                if record_size == 0 or record_size > self.MAX_OBJECT_SIZE:
                    offset += 1
                    continue
                
                if offset + record_size > len(data):
                    break
                
                # Extract object data
                object_data = data[offset:offset + record_size]
                
                # Analyze object for malicious content
                self._analyze_object(object_data, offset, file_path, object_id)
                
                offset += record_size
                object_count += 1
                
                if object_count % 1000 == 0:
                    print(f"[+] Processed {object_count} objects...")
                
            except struct.error:
                offset += 1
                continue
        
        print(f"[+] Parsed {object_count} object records")
    
    def _analyze_object(self, object_data, offset, file_path, object_id):
        """Analyze individual object for malicious patterns."""
        # Check for persistence classes
        for pattern in self.malicious_patterns['persistence_classes']:
            if pattern in object_data:
                self._extract_persistence_object(object_data, offset, file_path, pattern, object_id)
        
        # Check for suspicious content
        for keyword in self.malicious_patterns['malicious_keywords']:
            if keyword.lower() in object_data.lower():
                self._flag_suspicious_object(object_data, offset, file_path, keyword, object_id)
        
        # Extract WQL queries
        if b'SELECT' in object_data.upper() or b'select' in object_data:
            self._extract_wql_query(object_data, offset, file_path, object_id)
    
    def _extract_persistence_object(self, data, offset, file_path, pattern, object_id):
        """Extract detailed information about persistence objects."""
        persistence_obj = {
            'type': pattern.decode('ascii', errors='ignore'),
            'object_id': f"0x{object_id:08X}",
            'file_offset': offset,
            'source_file': file_path,
            'timestamp': datetime.now(),
            'raw_data': binascii.hexlify(data[:128]).decode(),
            'properties': {}
        }
        
        # Extract properties based on object type
        if b'FilterToConsumerBinding' in pattern:
            self._parse_filter_binding(data, persistence_obj)
        elif b'EventFilter' in pattern:
            self._parse_event_filter(data, persistence_obj)
        elif b'EventConsumer' in pattern:
            self._parse_event_consumer(data, persistence_obj)
        
        self.persistence_objects.append(persistence_obj)
    
    def _parse_filter_binding(self, data, obj):
        """Parse __FilterToConsumerBinding object."""
        obj['binding_type'] = 'FilterToConsumerBinding'
        
        # Look for Consumer and Filter references
        consumer_ref = self._extract_string_property(data, b'Consumer')
        filter_ref = self._extract_string_property(data, b'Filter')
        
        if consumer_ref:
            obj['properties']['Consumer'] = consumer_ref
        if filter_ref:
            obj['properties']['Filter'] = filter_ref
        
        # Check for specific binding patterns
        if b'ActiveScriptEventConsumer' in data:
            obj['consumer_type'] = 'ActiveScript'
        elif b'CommandLineEventConsumer' in data:
            obj['consumer_type'] = 'CommandLine'
        
        self.filter_bindings.append(obj)
    
    def _parse_event_filter(self, data, obj):
        """Parse __EventFilter object."""
        obj['filter_type'] = 'EventFilter'
        
        # Extract common filter properties
        name = self._extract_string_property(data, b'Name')
        query = self._extract_string_property(data, b'Query')
        query_language = self._extract_string_property(data, b'QueryLanguage')
        event_namespace = self._extract_string_property(data, b'EventNamespace')
        
        if name:
            obj['properties']['Name'] = name
        if query:
            obj['properties']['Query'] = query
        if query_language:
            obj['properties']['QueryLanguage'] = query_language
        if event_namespace:
            obj['properties']['EventNamespace'] = event_namespace
        
        self.event_filters.append(obj)
    
    def _parse_event_consumer(self, data, obj):
        """Parse __EventConsumer objects."""
        obj['consumer_type'] = 'EventConsumer'
        
        # Determine specific consumer type
        if b'ActiveScriptEventConsumer' in data:
            obj['specific_type'] = 'ActiveScript'
            script_text = self._extract_string_property(data, b'ScriptText')
            scripting_engine = self._extract_string_property(data, b'ScriptingEngine')
            if script_text:
                obj['properties']['ScriptText'] = script_text
            if scripting_engine:
                obj['properties']['ScriptingEngine'] = scripting_engine
                
        elif b'CommandLineEventConsumer' in data:
            obj['specific_type'] = 'CommandLine'
            command_line = self._extract_string_property(data, b'CommandLineTemplate')
            executable_path = self._extract_string_property(data, b'ExecutablePath')
            working_dir = self._extract_string_property(data, b'WorkingDirectory')
            if command_line:
                obj['properties']['CommandLineTemplate'] = command_line
            if executable_path:
                obj['properties']['ExecutablePath'] = executable_path
            if working_dir:
                obj['properties']['WorkingDirectory'] = working_dir
        
        # Extract common properties
        name = self._extract_string_property(data, b'Name')
        if name:
            obj['properties']['Name'] = name
        
        self.event_consumers.append(obj)
    
    def _extract_string_property(self, data, property_name):
        """Extract string property value from object data."""
        try:
            # Look for property name in data
            prop_offset = data.find(property_name)
            if prop_offset == -1:
                return None
            
            # Move past property name and look for string data
            search_start = prop_offset + len(property_name)
            
            # Try UTF-16 string extraction
            for i in range(search_start, min(search_start + 512, len(data) - 1), 2):
                if data[i] == 0 and data[i + 1] == 0:  # Null terminator
                    if i > search_start:
                        try:
                            string_data = data[search_start:i]
                            if len(string_data) % 2 == 1:
                                string_data = string_data[:-1]
                            decoded = string_data.decode('utf-16le', errors='ignore').strip()
                            if decoded and len(decoded) > 0 and all(ord(c) >= 32 or c in '\r\n\t' for c in decoded):
                                return decoded
                        except UnicodeDecodeError:
                            pass
                    break
            
            # Try ASCII string extraction
            for i in range(search_start, min(search_start + 256, len(data))):
                if data[i] == 0:  # Null terminator
                    if i > search_start:
                        try:
                            string_data = data[search_start:i]
                            decoded = string_data.decode('ascii', errors='ignore').strip()
                            if decoded and len(decoded) > 0 and all(ord(c) >= 32 or c in '\r\n\t' for c in decoded):
                                return decoded
                        except UnicodeDecodeError:
                            pass
                    break
            
        except Exception:
            pass
        
        return None
    
    def _flag_suspicious_object(self, data, offset, file_path, keyword, object_id):
        """Flag objects containing suspicious keywords."""
        suspicious_obj = {
            'object_id': f"0x{object_id:08X}",
            'file_offset': offset,
            'source_file': file_path,
            'suspicious_keyword': keyword.decode('ascii', errors='ignore'),
            'timestamp': datetime.now(),
            'context': self._extract_context(data, keyword),
            'raw_data_sample': binascii.hexlify(data[:64]).decode()
        }
        
        self.suspicious_classes.append(suspicious_obj)
    
    def _extract_context(self, data, keyword):
        """Extract context around suspicious keyword."""
        try:
            keyword_offset = data.lower().find(keyword.lower())
            if keyword_offset == -1:
                return "Context not found"
            
            start = max(0, keyword_offset - 64)
            end = min(len(data), keyword_offset + len(keyword) + 64)
            context_data = data[start:end]
            
            # Try to decode as text
            try:
                context = context_data.decode('utf-16le', errors='ignore')
                if not context.strip():
                    context = context_data.decode('ascii', errors='ignore')
                return context.strip()[:200]  # Limit context length
            except UnicodeDecodeError:
                return binascii.hexlify(context_data).decode()[:200]
                
        except Exception:
            return "Context extraction failed"
    
    def _extract_wql_query(self, data, offset, file_path, object_id):
        """Extract WQL queries from objects."""
        try:
            # Look for SELECT statements
            select_patterns = [b'SELECT', b'select', b'Select']
            
            for pattern in select_patterns:
                query_offset = data.find(pattern)
                if query_offset != -1:
                    # Extract query text
                    query_end = data.find(b'\x00', query_offset)
                    if query_end == -1:
                        query_end = min(query_offset + 512, len(data))
                    
                    query_data = data[query_offset:query_end]
                    
                    try:
                        # Try different decodings
                        query_text = None
                        for encoding in ['utf-16le', 'ascii', 'utf-8']:
                            try:
                                query_text = query_data.decode(encoding, errors='ignore').strip()
                                if query_text and 'SELECT' in query_text.upper():
                                    break
                            except UnicodeDecodeError:
                                continue
                        
                        if query_text:
                            wql_obj = {
                                'object_id': f"0x{object_id:08X}",
                                'file_offset': offset,
                                'source_file': file_path,
                                'query': query_text[:500],  # Limit query length
                                'timestamp': datetime.now()
                            }
                            self.wql_queries.append(wql_obj)
                            break
                            
                    except Exception:
                        continue
                        
        except Exception:
            pass
    
    def _parse_unallocated_space(self, data, file_path):
        """Parse unallocated space for deleted objects."""
        print("[+] Scanning unallocated space for deleted objects...")
        
        # Look for object signatures in unallocated space
        # This is a simplified approach - full implementation would need
        # detailed knowledge of WMI repository page structure
        
        deleted_count = 0
        
        for pattern in self.malicious_patterns['persistence_classes']:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break
                
                # Check if this is in allocated space by looking for valid object header
                header_offset = offset - 16
                if header_offset >= 0:
                    try:
                        header = struct.unpack('<IIII', data[header_offset:header_offset + 16])
                        record_size = header[0]
                        
                        # If record size is invalid, this might be deleted data
                        if record_size == 0 or record_size > self.MAX_OBJECT_SIZE:
                            deleted_obj = {
                                'pattern': pattern.decode('ascii', errors='ignore'),
                                'file_offset': offset,
                                'source_file': file_path,
                                'timestamp': datetime.now(),
                                'context': data[max(0, offset-32):offset+64],
                                'status': 'potentially_deleted'
                            }
                            self.deleted_objects.append(deleted_obj)
                            deleted_count += 1
                            
                    except struct.error:
                        pass
                
                offset += 1
        
        print(f"[+] Found {deleted_count} potentially deleted persistence objects")
    
    def _perform_threat_analysis(self):
        """Perform advanced threat analysis on all discovered objects."""
        print("[+] Performing threat intelligence analysis...")
        
        # Analyze all persistence objects
        for obj in self.persistence_objects:
            raw_data = obj.get('raw_data', '')
            if raw_data:
                try:
                    data_bytes = bytes.fromhex(raw_data)
                    analysis = self.threat_intel.analyze_object(data_bytes, obj.get('type', 'unknown'))
                    analysis['source_object'] = obj
                    self.threat_analysis_results.append(analysis)
                except ValueError:
                    pass
        
        # Analyze suspicious objects
        for obj in self.suspicious_classes:
            raw_data = obj.get('raw_data_sample', '')
            if raw_data:
                try:
                    data_bytes = bytes.fromhex(raw_data)
                    analysis = self.threat_intel.analyze_object(data_bytes, 'suspicious')
                    analysis['source_object'] = obj
                    self.threat_analysis_results.append(analysis)
                except ValueError:
                    pass
        
        print(f"[+] Completed threat analysis on {len(self.threat_analysis_results)} objects")
    
    def _analyze_persistence_mechanisms(self):
        """Analyze found objects for complete persistence mechanisms."""
        print("\n[+] Analyzing persistence mechanisms...")
        
        # Use advanced persistence analyzer
        complete_mechanisms = self.persistence_analyzer.analyze_persistence_chain(
            self.event_filters, self.event_consumers, self.filter_bindings
        )
        
        print(f"[+] Found {len(complete_mechanisms)} binding mechanisms")
        print(f"[+] Complete mechanisms: {len(complete_mechanisms)}")
        
        # Log risk assessments
        for mechanism in complete_mechanisms:
            risk_assessment = mechanism.get('risk_assessment', {})
            risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
            persistence_method = mechanism.get('persistence_method', 'Unknown')
            print(f"[+] Mechanism: {persistence_method} - Risk: {risk_level}")
        
        return complete_mechanisms
    
    def _generate_threat_analysis(self):
        """Generate comprehensive threat analysis report."""
        print("\n" + "="*60)
        print("ENHANCED THREAT ANALYSIS SUMMARY")
        print("="*60)
        
        print(f"Persistence Objects Found: {len(self.persistence_objects)}")
        print(f"  - FilterToConsumerBindings: {len(self.filter_bindings)}")
        print(f"  - Event Filters: {len(self.event_filters)}")
        print(f"  - Event Consumers: {len(self.event_consumers)}")
        
        print(f"\nSuspicious Objects: {len(self.suspicious_classes)}")
        print(f"WQL Queries Found: {len(self.wql_queries)}")
        print(f"Potentially Deleted Objects: {len(self.deleted_objects)}")
        print(f"Threat Intelligence Analysis: {len(self.threat_analysis_results)}")
        
        # Advanced threat level calculation
        critical_threats = [r for r in self.threat_analysis_results if r['threat_level'] == 'CRITICAL']
        high_threats = [r for r in self.threat_analysis_results if r['threat_level'] == 'HIGH']
        medium_threats = [r for r in self.threat_analysis_results if r['threat_level'] == 'MEDIUM']
        
        overall_threat_level = "LOW"
        if critical_threats:
            overall_threat_level = "CRITICAL"
        elif high_threats or len(self.filter_bindings) > 0:
            overall_threat_level = "HIGH"
        elif medium_threats or len(self.event_consumers) > 0 or len(self.suspicious_classes) > 5:
            overall_threat_level = "MEDIUM"
        
        print(f"\nTHREAT LEVEL BREAKDOWN:")
        print(f"  - CRITICAL: {len(critical_threats)}")
        print(f"  - HIGH: {len(high_threats)}")
        print(f"  - MEDIUM: {len(medium_threats)}")
        print(f"\nOVERALL THREAT LEVEL: {overall_threat_level}")
        
        # Malware family detection
        malware_families = [r['malware_family'] for r in self.threat_analysis_results if r.get('malware_family')]
        if malware_families:
            print(f"\nMALWARE FAMILIES DETECTED:")
            for family in set([mf['name'] for mf in malware_families]):
                print(f"  - {family}")
        
        # APT indicators
        apt_indicators = []
        for result in self.threat_analysis_results:
            for indicator in result.get('indicators', []):
                if indicator.get('type') == 'apt_signature':
                    apt_indicators.append(indicator.get('apt_group'))
        
        if apt_indicators:
            print(f"\nAPT INDICATORS DETECTED:")
            for apt_group in set(apt_indicators):
                print(f"  - {apt_group}")
        
        # Persistence chain analysis
        high_risk_chains = len([chain for chain in self.persistence_analyzer.persistence_chains 
                               if chain.get('risk_assessment', {}).get('risk_level') in ['HIGH', 'CRITICAL']])
        
        if high_risk_chains:
            print(f"\nHIGH-RISK PERSISTENCE CHAINS: {high_risk_chains}")
        
        # Generate recommendations
        print(f"\nRECOMMENDATIONS:")
        if overall_threat_level == "CRITICAL":
            print("🚨 IMMEDIATE ACTION REQUIRED:")
            print("- ISOLATE the system from the network immediately")
            print("- PRESERVE forensic evidence before any remediation")
            print("- ACTIVATE incident response procedures")
            print("- NOTIFY security team and stakeholders")
        
        if overall_threat_level in ["CRITICAL", "HIGH"]:
            print("📋 INVESTIGATION PRIORITIES:")
            print("- Review all FilterToConsumerBinding objects")
            print("- Analyze Event Consumer scripts/commands for IOCs")
            print("- Check for lateral movement to other systems")
            print("- Correlate with network logs for C2 communication")
            print("- Examine PowerShell and WMI event logs")
        
        if overall_threat_level in ["HIGH", "MEDIUM"]:
            print("🔍 ANALYSIS TASKS:")
            print("- Review Windows Event Logs (5857-5861 for WMI)")
            print("- Check Sysmon logs for WMI activity (Event ID 19-21)")
            print("- Verify system file integrity")
            print("- Hunt for similar patterns across environment")
        
        # Consolidate all recommendations from threat analysis
        all_recommendations = set()
        for result in self.threat_analysis_results:
            all_recommendations.update(result.get('recommendations', []))
        
        if all_recommendations:
            print("💡 ADDITIONAL RECOMMENDATIONS:")
            for rec in sorted(all_recommendations):
                print(f"- {rec}")
    
    def export_results(self, output_dir):
        """Export all findings to CSV files."""
        os.makedirs(output_dir, exist_ok=True)
        
        # Export persistence objects
        if self.persistence_objects:
            self._export_persistence_objects(os.path.join(output_dir, 'wmi_persistence_objects.csv'))
        
        # Export suspicious objects
        if self.suspicious_classes:
            self._export_suspicious_objects(os.path.join(output_dir, 'wmi_suspicious_objects.csv'))
        
        # Export WQL queries
        if self.wql_queries:
            self._export_wql_queries(os.path.join(output_dir, 'wmi_wql_queries.csv'))
        
        # Export deleted objects
        if self.deleted_objects:
            self._export_deleted_objects(os.path.join(output_dir, 'wmi_deleted_objects.csv'))
        
        # Export threat analysis results
        if self.threat_analysis_results:
            self._export_threat_analysis(os.path.join(output_dir, 'wmi_threat_analysis.csv'))
        
        # Export persistence chain analysis
        if self.persistence_analyzer.persistence_chains:
            self._export_persistence_chains(os.path.join(output_dir, 'wmi_persistence_chains.csv'))
        
        # Generate IOC report
        if self.threat_analysis_results:
            self._export_ioc_report(os.path.join(output_dir, 'wmi_ioc_report.json'))
        
        print(f"\n[+] Results exported to: {output_dir}")
    
    def _export_persistence_objects(self, output_file):
        """Export persistence objects to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Type', 'Object_ID', 'File_Offset', 'Source_File', 'Timestamp',
                         'Consumer_Type', 'Properties', 'Raw_Data']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for obj in self.persistence_objects:
                writer.writerow({
                    'Type': obj.get('type', ''),
                    'Object_ID': obj.get('object_id', ''),
                    'File_Offset': obj.get('file_offset', ''),
                    'Source_File': obj.get('source_file', ''),
                    'Timestamp': obj.get('timestamp', ''),
                    'Consumer_Type': obj.get('consumer_type', obj.get('specific_type', '')),
                    'Properties': str(obj.get('properties', {})),
                    'Raw_Data': obj.get('raw_data', '')
                })
    
    def _export_suspicious_objects(self, output_file):
        """Export suspicious objects to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Object_ID', 'File_Offset', 'Source_File', 'Suspicious_Keyword',
                         'Context', 'Timestamp', 'Raw_Data_Sample']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for obj in self.suspicious_classes:
                writer.writerow({
                    'Object_ID': obj.get('object_id', ''),
                    'File_Offset': obj.get('file_offset', ''),
                    'Source_File': obj.get('source_file', ''),
                    'Suspicious_Keyword': obj.get('suspicious_keyword', ''),
                    'Context': obj.get('context', ''),
                    'Timestamp': obj.get('timestamp', ''),
                    'Raw_Data_Sample': obj.get('raw_data_sample', '')
                })
    
    def _export_wql_queries(self, output_file):
        """Export WQL queries to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Object_ID', 'File_Offset', 'Source_File', 'Query', 'Timestamp']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for obj in self.wql_queries:
                writer.writerow({
                    'Object_ID': obj.get('object_id', ''),
                    'File_Offset': obj.get('file_offset', ''),
                    'Source_File': obj.get('source_file', ''),
                    'Query': obj.get('query', ''),
                    'Timestamp': obj.get('timestamp', '')
                })
    
    def _export_deleted_objects(self, output_file):
        """Export potentially deleted objects to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Pattern', 'File_Offset', 'Source_File', 'Status', 
                         'Context_Hex', 'Timestamp']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for obj in self.deleted_objects:
                writer.writerow({
                    'Pattern': obj.get('pattern', ''),
                    'File_Offset': obj.get('file_offset', ''),
                    'Source_File': obj.get('source_file', ''),
                    'Status': obj.get('status', ''),
                    'Context_Hex': binascii.hexlify(obj.get('context', b'')).decode(),
                    'Timestamp': obj.get('timestamp', '')
                })
    
    def _export_threat_analysis(self, output_file):
        """Export threat analysis results to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Source_Object_ID', 'Threat_Level', 'Risk_Score', 'Malware_Family',
                         'APT_Groups', 'Indicators_Count', 'Attack_Techniques', 'Recommendations']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.threat_analysis_results:
                source_obj = result.get('source_object', {})
                apt_groups = [ind.get('apt_group', '') for ind in result.get('indicators', []) 
                             if ind.get('type') == 'apt_signature']
                
                writer.writerow({
                    'Source_Object_ID': source_obj.get('object_id', ''),
                    'Threat_Level': result.get('threat_level', ''),
                    'Risk_Score': result.get('risk_score', 0),
                    'Malware_Family': result.get('malware_family', {}).get('name', '') if result.get('malware_family') else '',
                    'APT_Groups': '; '.join(set(apt_groups)),
                    'Indicators_Count': len(result.get('indicators', [])),
                    'Attack_Techniques': '; '.join(result.get('attack_techniques', [])),
                    'Recommendations': '; '.join(result.get('recommendations', []))[:500]  # Limit length
                })
    
    def _export_persistence_chains(self, output_file):
        """Export persistence chain analysis to CSV."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Chain_ID', 'Persistence_Method', 'Risk_Level', 'Risk_Score',
                         'Filter_Query', 'Consumer_Type', 'Consumer_Command', 'Binding_Name']
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for i, chain in enumerate(self.persistence_analyzer.persistence_chains):
                risk_assessment = chain.get('risk_assessment', {})
                wmi_filter = chain.get('filter', {})
                consumer = chain.get('consumer', {})
                binding = chain.get('binding', {})
                
                filter_query = wmi_filter.get('properties', {}).get('Query', '')
                consumer_command = (consumer.get('properties', {}).get('CommandLineTemplate', '') or
                                  consumer.get('properties', {}).get('ScriptText', ''))[:200]
                
                writer.writerow({
                    'Chain_ID': f"chain_{i+1}",
                    'Persistence_Method': chain.get('persistence_method', ''),
                    'Risk_Level': risk_assessment.get('risk_level', ''),
                    'Risk_Score': risk_assessment.get('overall_risk_score', 0),
                    'Filter_Query': filter_query[:300],  # Limit length
                    'Consumer_Type': consumer.get('specific_type', ''),
                    'Consumer_Command': consumer_command,
                    'Binding_Name': binding.get('properties', {}).get('Name', '')
                })
    
    def _export_ioc_report(self, output_file):
        """Export IOC report in JSON format."""
        import json
        
        # Generate IOC report using threat intelligence
        ioc_report = self.threat_intel.generate_ioc_report(self.threat_analysis_results)
        
        # Add additional context
        ioc_report['metadata']['parser_version'] = 'Enhanced WMI Parser v1.0'
        ioc_report['metadata']['analysis_timestamp'] = datetime.now().isoformat()
        ioc_report['metadata']['persistence_chains'] = len(self.persistence_analyzer.persistence_chains)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(ioc_report, f, indent=2, default=str)


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Enhanced WMI Forensic Parser")
        print("Usage: python enhanced_wmi_parser.py <OBJECTS.DATA_file> [output_directory]")
        print("Example: python enhanced_wmi_parser.py /path/to/OBJECTS.DATA ./wmi_analysis")
        sys.exit(1)
    
    objects_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './enhanced_wmi_output'
    
    if not os.path.exists(objects_file):
        print(f"[!] Error: File not found: {objects_file}")
        sys.exit(1)
    
    print("Enhanced WMI Forensic Parser v1.0")
    print("Analyzing for malicious WMI persistence and attacks...\n")
    
    parser = EnhancedWMIParser()
    
    try:
        success = parser.parse_objects_data(objects_file)
        
        if success:
            parser.export_results(output_dir)
            print("\n[+] Analysis complete!")
        else:
            print("\n[!] Analysis failed!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()