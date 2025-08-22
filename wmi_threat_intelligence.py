#!/usr/bin/env python3
"""
WMI Threat Intelligence Module
Advanced detection patterns for malicious WMI activity and persistence mechanisms.
"""

import re
import hashlib
from datetime import datetime


class WMIThreatIntelligence:
    """Advanced threat intelligence for WMI-based attacks."""
    
    def __init__(self):
        # Known malicious WMI attack patterns
        self.attack_patterns = {
            'persistence_indicators': {
                'high_risk': [
                    # PowerShell execution patterns
                    b'powershell.exe -enc',
                    b'powershell -e ',
                    b'powershell -encodedcommand',
                    b'powershell -w hidden',
                    b'powershell -windowstyle hidden',
                    b'invoke-expression',
                    b'iex ',
                    b'downloadstring',
                    b'net.webclient',
                    b'system.net.webclient',
                    
                    # Script execution patterns
                    b'wscript.exe',
                    b'cscript.exe',
                    b'mshta.exe',
                    b'regsvr32.exe /s /u /i:',
                    b'rundll32.exe javascript:',
                    b'bitsadmin /transfer',
                    b'certutil -urlcache',
                    
                    # Base64 and encoding indicators
                    b'frombase64string',
                    b'convert::frombase64string',
                    b'system.convert::frombase64string',
                    b'[system.text.encoding]::utf8.getstring',
                    
                    # Living off the land binaries
                    b'installutil.exe',
                    b'msbuild.exe',
                    b'cmstp.exe',
                    b'dllhost.exe /processid:',
                ]
                
            },
            
            'suspicious_wql_queries': [
                # Process monitoring for evasion
                r'SELECT.*FROM.*Win32_Process.*WHERE.*CommandLine.*LIKE.*powershell',
                r'SELECT.*FROM.*Win32_ProcessStartTrace',
                r'SELECT.*FROM.*Win32_ProcessStopTrace',
                r'SELECT.*FROM.*Win32_ModuleLoadTrace',
                
                # System monitoring
                r'SELECT.*FROM.*Win32_VolumeChangeEvent',
                r'SELECT.*FROM.*Win32_DeviceChangeEvent',
                r'SELECT.*FROM.*Win32_LoggedOnUser',
                r'SELECT.*FROM.*Win32_LogonSession',
                
                # Registry monitoring
                r'SELECT.*FROM.*RegistryKeyChangeEvent',
                r'SELECT.*FROM.*RegistryValueChangeEvent',
                
                # File system monitoring
                r'SELECT.*FROM.*CIM_DirectoryContainsFile',
                r'SELECT.*FROM.*Win32_FileDirectoryChange',
            ],
            
            'malicious_consumers': {
                'script_consumers': [
                    # VBScript patterns
                    b'CreateObject("WScript.Shell")',
                    b'CreateObject("Scripting.FileSystemObject")',
                    b'CreateObject("Microsoft.XMLHTTP")',
                    b'CreateObject("WinHttp.WinHttpRequest")',
                    b'Shell.Application',
                    
                    # JavaScript patterns
                    b'new ActiveXObject("WScript.Shell")',
                    b'new ActiveXObject("Scripting.FileSystemObject")',
                    b'new ActiveXObject("Microsoft.XMLHTTP")',
                    b'eval(',
                    b'unescape(',
                    
                    # PowerShell script block patterns
                    b'Invoke-Command',
                    b'Start-Process',
                    b'New-Object System.Net.WebClient',
                    b'Add-Type',
                    b'Reflection.Assembly',
                ],
                
                'command_line_patterns': [
                    # Obfuscation techniques
                    b'cmd /c echo',
                    b'cmd.exe /c echo',
                    b'for /f',
                    b'&echo',
                    b'^&echo',
                    
                    # Network activity
                    b'curl ',
                    b'wget ',
                    b'Invoke-WebRequest',
                    b'Net.WebClient',
                    
                    # File operations
                    b'copy /y',
                    b'move /y',
                    b'del /f /q',
                    b'rd /s /q',
                ]
            },
            
            'apt_signatures': {
                # Known APT group techniques
                'apt29_cozy_bear': [
                    b'WmiPrvSE.exe',
                    b'wmic process call create',
                    b'powershell -nop -w hidden -c',
                ],
                
                'apt1_comment_crew': [
                    b'wmic /node:',
                    b'wmic computersystem',
                    b'wmic process where',
                ],
                
                'lazarus_group': [
                    b'wmic product',
                    b'wmic qfe',
                    b'wmic startup',
                ],
                
                'turla': [
                    b'select * from win32_process',
                    b'select * from win32_service',
                    b'wmic logicaldisk',
                ]
            }
        }
        
        # WMI-based malware families
        self.malware_families = {
            'stuxnet': {
                'indicators': [b'MrxCls', b'MrxNet', b'.stub'],
                'description': 'Stuxnet-style WMI persistence'
            },
            'carbanak': {
                'indicators': [b'taskschd', b'at.exe', b'schtasks'],
                'description': 'Carbanak-style scheduled task creation'
            },
            'duqu': {
                'indicators': [b'jminet7.dll', b'netp192.dll'],
                'description': 'Duqu-style driver installation via WMI'
            },
            'flame': {
                'indicators': [b'mssecmgr.ocx', b'msgslang.dll'],
                'description': 'Flame-style component installation'
            }
        }
    
    def analyze_object(self, obj_data, obj_type='unknown'):
        """Analyze a WMI object for malicious indicators."""
        analysis_result = {
            'threat_level': 'LOW',
            'indicators': [],
            'attack_techniques': [],
            'malware_family': None,
            'risk_score': 0,
            'recommendations': []
        }
        
        try:
            # Convert to lowercase for case-insensitive matching
            data_lower = obj_data.lower()
            
            # Check for high-risk patterns
            for pattern in self.attack_patterns['persistence_indicators']['high_risk']:
                if pattern.lower() in data_lower:
                    analysis_result['indicators'].append({
                        'type': 'high_risk_pattern',
                        'pattern': pattern.decode('ascii', errors='ignore'),
                        'severity': 'HIGH'
                    })
                    analysis_result['risk_score'] += 25
            
            # Check for suspicious WQL queries
            for pattern in self.attack_patterns['suspicious_wql_queries']:
                if re.search(pattern, obj_data.decode('ascii', errors='ignore'), re.IGNORECASE):
                    analysis_result['indicators'].append({
                        'type': 'suspicious_wql',
                        'pattern': pattern,
                        'severity': 'MEDIUM'
                    })
                    analysis_result['risk_score'] += 15
            
            # Check script consumer patterns
            if obj_type in ['ActiveScriptEventConsumer', 'script_consumer']:
                for pattern in self.attack_patterns['malicious_consumers']['script_consumers']:
                    if pattern.lower() in data_lower:
                        analysis_result['indicators'].append({
                            'type': 'malicious_script',
                            'pattern': pattern.decode('ascii', errors='ignore'),
                            'severity': 'HIGH'
                        })
                        analysis_result['risk_score'] += 30
            
            # Check command line patterns
            if obj_type in ['CommandLineEventConsumer', 'command_consumer']:
                for pattern in self.attack_patterns['malicious_consumers']['command_line_patterns']:
                    if pattern.lower() in data_lower:
                        analysis_result['indicators'].append({
                            'type': 'suspicious_command',
                            'pattern': pattern.decode('ascii', errors='ignore'),
                            'severity': 'MEDIUM'
                        })
                        analysis_result['risk_score'] += 20
            
            # Check for APT signatures
            for apt_group, signatures in self.attack_patterns['apt_signatures'].items():
                for signature in signatures:
                    if signature.lower() in data_lower:
                        analysis_result['indicators'].append({
                            'type': 'apt_signature',
                            'pattern': signature.decode('ascii', errors='ignore'),
                            'apt_group': apt_group,
                            'severity': 'CRITICAL'
                        })
                        analysis_result['risk_score'] += 50
                        analysis_result['attack_techniques'].append(f'APT technique: {apt_group}')
            
            # Check for malware family indicators
            for family_name, family_data in self.malware_families.items():
                for indicator in family_data['indicators']:
                    if indicator.lower() in data_lower:
                        analysis_result['malware_family'] = {
                            'name': family_name,
                            'description': family_data['description'],
                            'confidence': 'HIGH'
                        }
                        analysis_result['risk_score'] += 40
                        break
            
            # Determine threat level based on risk score
            if analysis_result['risk_score'] >= 50:
                analysis_result['threat_level'] = 'CRITICAL'
            elif analysis_result['risk_score'] >= 30:
                analysis_result['threat_level'] = 'HIGH'
            elif analysis_result['risk_score'] >= 15:
                analysis_result['threat_level'] = 'MEDIUM'
            
            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
        except Exception as e:
            analysis_result['error'] = str(e)
        
        return analysis_result
    
    def _generate_recommendations(self, analysis_result):
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        if analysis_result['threat_level'] in ['CRITICAL', 'HIGH']:
            recommendations.extend([
                'IMMEDIATE: Isolate the affected system from the network',
                'IMMEDIATE: Collect forensic images before any remediation',
                'Analyze network logs for command and control communication',
                'Check for lateral movement to other systems',
                'Review all WMI event subscriptions system-wide'
            ])
        
        if analysis_result['threat_level'] in ['HIGH', 'MEDIUM']:
            recommendations.extend([
                'Review Windows Event Logs (Event ID 5857-5861 for WMI)',
                'Check Sysmon logs for WMI activity (Event ID 19-21)',
                'Examine PowerShell logs for encoded commands',
                'Verify integrity of system files and registry'
            ])
        
        # Specific recommendations based on indicators
        for indicator in analysis_result['indicators']:
            if indicator['type'] == 'malicious_script':
                recommendations.append('Analyze script content for IOCs and TTPs')
            elif indicator['type'] == 'suspicious_command':
                recommendations.append('Trace command execution through process monitoring')
            elif indicator['type'] == 'apt_signature':
                recommendations.append(f'Apply APT-specific hunting rules for {indicator["apt_group"]}')
        
        if analysis_result['malware_family']:
            family_name = analysis_result['malware_family']['name']
            recommendations.append(f'Apply {family_name}-specific detection and hunting rules')
        
        return list(set(recommendations))  # Remove duplicates
    
    def generate_yara_rules(self, analysis_results):
        """Generate YARA rules based on analysis results."""
        yara_rules = []
        
        rule_template = '''rule WMI_Malicious_Activity_{rule_id}
{{
    meta:
        description = "{description}"
        threat_level = "{threat_level}"
        created = "{date}"
        
    strings:
{strings}
        
    condition:
        any of them
}}'''
        
        rule_counter = 1
        for result in analysis_results:
            if result['threat_level'] in ['HIGH', 'CRITICAL']:
                strings_section = ""
                for i, indicator in enumerate(result['indicators']):
                    pattern = indicator['pattern'].replace('"', '\\"')
                    strings_section += f'        $s{i} = "{pattern}" nocase\n'
                
                if strings_section:
                    rule = rule_template.format(
                        rule_id=rule_counter,
                        description=f"Malicious WMI activity - {result['threat_level']} risk",
                        threat_level=result['threat_level'],
                        date=datetime.now().strftime('%Y-%m-%d'),
                        strings=strings_section
                    )
                    yara_rules.append(rule)
                    rule_counter += 1
        
        return yara_rules
    
    def generate_ioc_report(self, analysis_results):
        """Generate IOC report in structured format."""
        ioc_report = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_objects_analyzed': len(analysis_results),
                'high_risk_objects': len([r for r in analysis_results if r['threat_level'] in ['HIGH', 'CRITICAL']]),
                'malware_families_detected': list(set([r['malware_family']['name'] for r in analysis_results if r['malware_family']]))
            },
            'indicators': {
                'file_hashes': [],
                'network_indicators': [],
                'registry_keys': [],
                'file_paths': [],
                'command_lines': [],
                'scripts': []
            },
            'attack_techniques': [],
            'recommendations': []
        }
        
        # Extract IOCs from analysis results
        for result in analysis_results:
            if result['threat_level'] in ['HIGH', 'CRITICAL']:
                for indicator in result['indicators']:
                    pattern = indicator['pattern']
                    
                    # Categorize indicators
                    if any(cmd in pattern.lower() for cmd in ['powershell', 'cmd', 'wscript', 'cscript']):
                        ioc_report['indicators']['command_lines'].append(pattern)
                    elif any(path in pattern.lower() for path in ['\\', '/', 'c:', 'temp', 'appdata']):
                        ioc_report['indicators']['file_paths'].append(pattern)
                    elif 'script' in indicator['type'].lower():
                        ioc_report['indicators']['scripts'].append(pattern)
                
                # Collect attack techniques
                ioc_report['attack_techniques'].extend(result['attack_techniques'])
                ioc_report['recommendations'].extend(result['recommendations'])
        
        # Remove duplicates
        for category in ioc_report['indicators']:
            ioc_report['indicators'][category] = list(set(ioc_report['indicators'][category]))
        
        ioc_report['attack_techniques'] = list(set(ioc_report['attack_techniques']))
        ioc_report['recommendations'] = list(set(ioc_report['recommendations']))
        
        return ioc_report


class WMIPersistenceAnalyzer:
    """Specialized analyzer for WMI persistence mechanisms."""
    
    def __init__(self):
        self.persistence_chains = []
        self.incomplete_chains = []
    
    def analyze_persistence_chain(self, filters, consumers, bindings):
        """Analyze complete WMI persistence chains."""
        complete_chains = []
        
        for binding in bindings:
            chain = {
                'binding': binding,
                'filter': None,
                'consumer': None,
                'risk_assessment': {},
                'persistence_method': 'unknown'
            }
            
            # Find associated filter
            filter_ref = binding.get('properties', {}).get('Filter', '')
            for wmi_filter in filters:
                if wmi_filter.get('properties', {}).get('Name', '') in filter_ref:
                    chain['filter'] = wmi_filter
                    break
            
            # Find associated consumer
            consumer_ref = binding.get('properties', {}).get('Consumer', '')
            for consumer in consumers:
                if consumer.get('properties', {}).get('Name', '') in consumer_ref:
                    chain['consumer'] = consumer
                    break
            
            # Assess the complete chain
            chain['risk_assessment'] = self._assess_persistence_risk(chain)
            chain['persistence_method'] = self._identify_persistence_method(chain)
            
            if chain['filter'] and chain['consumer']:
                complete_chains.append(chain)
            else:
                self.incomplete_chains.append(chain)
        
        self.persistence_chains = complete_chains
        return complete_chains
    
    def _assess_persistence_risk(self, chain):
        """Assess the risk level of a persistence chain."""
        risk_factors = {
            'execution_capability': 0,
            'stealth_level': 0,
            'persistence_strength': 0,
            'privilege_escalation': 0
        }
        
        # Analyze consumer for execution capability
        consumer = chain.get('consumer', {})
        consumer_type = consumer.get('specific_type', '')
        
        if consumer_type == 'ActiveScript':
            script_text = consumer.get('properties', {}).get('ScriptText', '')
            if any(dangerous in script_text.lower() for dangerous in ['powershell', 'cmd', 'wscript']):
                risk_factors['execution_capability'] = 9
            else:
                risk_factors['execution_capability'] = 6
        elif consumer_type == 'CommandLine':
            cmd_template = consumer.get('properties', {}).get('CommandLineTemplate', '')
            if any(dangerous in cmd_template.lower() for dangerous in ['powershell', 'cmd.exe']):
                risk_factors['execution_capability'] = 8
            else:
                risk_factors['execution_capability'] = 5
        
        # Analyze filter for trigger conditions
        wmi_filter = chain.get('filter', {})
        query = wmi_filter.get('properties', {}).get('Query', '')
        
        if 'boot' in query.lower() or 'startup' in query.lower():
            risk_factors['persistence_strength'] = 9
        elif 'logon' in query.lower():
            risk_factors['persistence_strength'] = 7
        elif 'process' in query.lower():
            risk_factors['persistence_strength'] = 5
        
        # Calculate overall risk score
        overall_risk = sum(risk_factors.values()) / len(risk_factors)
        
        return {
            'risk_factors': risk_factors,
            'overall_risk_score': overall_risk,
            'risk_level': 'CRITICAL' if overall_risk >= 8 else 'HIGH' if overall_risk >= 6 else 'MEDIUM' if overall_risk >= 4 else 'LOW'
        }
    
    def _identify_persistence_method(self, chain):
        """Identify the specific persistence method used."""
        consumer = chain.get('consumer', {})
        wmi_filter = chain.get('filter', {})
        
        consumer_type = consumer.get('specific_type', '')
        query = wmi_filter.get('properties', {}).get('Query', '').lower()
        
        if 'win32_process' in query and 'create' in query:
            return 'Process Execution Persistence'
        elif 'win32_computersystem' in query and 'boot' in query:
            return 'Boot Time Persistence'
        elif 'win32_logonsession' in query:
            return 'Logon Event Persistence'
        elif consumer_type == 'ActiveScript':
            return 'Script-based Persistence'
        elif consumer_type == 'CommandLine':
            return 'Command-line Persistence'
        else:
            return 'Unknown Persistence Method'


def main():
    """Test the threat intelligence module."""
    ti = WMIThreatIntelligence()
    
    # Test sample malicious content
    test_samples = [
        b'powershell.exe -enc SGVsbG8gV29ybGQ=',
        b'SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName="cmd.exe"',
        b'CreateObject("WScript.Shell").Run("cmd.exe")',
        b'wmic process call create "powershell -w hidden"'
    ]
    
    print("WMI Threat Intelligence Test")
    print("=" * 40)
    
    for i, sample in enumerate(test_samples):
        print(f"\nTest Sample {i+1}:")
        print(f"Data: {sample.decode('ascii', errors='ignore')}")
        
        result = ti.analyze_object(sample)
        print(f"Threat Level: {result['threat_level']}")
        print(f"Risk Score: {result['risk_score']}")
        print(f"Indicators: {len(result['indicators'])}")
        
        for indicator in result['indicators']:
            print(f"  - {indicator['type']}: {indicator['pattern']} ({indicator['severity']})")


if __name__ == "__main__":
    main()