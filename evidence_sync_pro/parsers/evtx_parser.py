"""
EVTX (Windows Event Log) parser for Evidence Sync Pro.
Parses .evtx files and normalizes events into the standard Event format.
"""

from evtx import PyEvtxParser
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from .base_parser import BaseParser, Event
import winreg
from loguru import logger
import json
import re
from datetime import timedelta

class EvtxParser(BaseParser):
    CORRUPTION_THRESHOLD = 0.02  # If more than 2% of events are corrupted, flag artifact as corrupted
    HIGH_PRIORITY_EVENTS = [4625, 4624, 4720, 4728, 4732, 4898]  # Event IDs that are considered high priority for forensic analysis (e.g., failed logins, account creations, privilege escalations)
    MEDIUM_PRIORITY_EVENTS = [4648, 4771] # Event IDs that are considered medium priority (e.g., successful logins, Kerberos pre-auth failures)
    IP_CATEGORIES = {"127.X.X.X": "Loopback", 
                     "192.168.X.X": "Private Network", 
                     "10.X.X.X": "Private Network", 
                     "172.16.X.X - 172.31.X.X": "Private Network",
                     "169.254.x.x": "APIPA", 
                     "0.0.0.0": "unspecified"}
    FAILURE_REASON_MAPPING = {"0xC000005E": "There is no such user",
                              "0xC000006A": "Incorrect password",
                              "0xC0000234": "Account locked"}
    
    def __init__(self, artifact_path: str, system_hive_path: str):
        """Initialize EVTX parser with path to EVTX file and system hive for timezone extraction."""

        # Initialize base parser and set system hive path for timezone extraction
        super().__init__(artifact_path)
        self.system_hive_path = system_hive_path
        
        # Initialize: system_timezone, corruption_log (list), events_count
        self.system_timezone = self._get_system_timezone(self.system_hive_path)
        self.corruption_log: List[Dict[str, Any]] = []
        self.events_count = 0
    
    def parse(self) -> List[Event]:
        if not Path(self.artifact_path).is_file():
            raise FileNotFoundError(f"EVTX file not found: {self.artifact_path}")
        
        try:
            parser = PyEvtxParser(self.artifact_path)
            logger.info(f"Successfully opened EVTX file: {self.artifact_path}")
        except Exception as e:
            logger.error(f"Failed to open EVTX file: {e}")
            self.corruption_log.append({"error": str(e), "stage": "file_open"})
            return []
        
        for record in parser.records_json():
            self.events_count += 1
            try:
                event = self._normalize_event(record)
                if event is not None:
                    self.events.append(event)
                else:
                    logger.warning(f"Event normalization returned None for record {record['event_record_id']}")
                    self.corruption_log.append({"error": "Event normalization returned None", "event_record_id": record['event_record_id'], "stage": "event_normalization"})
            except Exception as e:
                logger.error(f"Exception in event normalization: {e}")
                self.corruption_log.append({"error": str(e), "event_record_id": record['event_record_id'], "stage": "event_normalization"})
        
        logger.info(f"Parsed {len(self.events)} events from {self.events_count} records")
        
        if self.events_count > 0 and len(self.corruption_log) / self.events_count >= self.CORRUPTION_THRESHOLD:
            self._build_corruption_audit_log()
        
        return self.events
    
    def _get_system_timezone(self, system_hive_path: str) -> str:
        """
        Extract system timezone from SYSTEM hive using Bias value.
        Bias is stored in minutes; negative = UTC+, positive = UTC-
        """
        if not Path(system_hive_path).is_file():
            if Path(r"C:\Windows\System32\config\SYSTEM").is_file():
                system_hive_path = r"C:\Windows\System32\config\SYSTEM"
            else:
                return "UTC+0"
        
        try:
            registry_path = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as key:
                bias_minutes = winreg.QueryValueEx(key, "Bias")[0]
                
                if abs(bias_minutes) > 2000:
                    logger.warning(f"Insane registry bias detected ({bias_minutes}). Defaulting to UTC+0.")
                    return "UTC+0"

                # Bias is negative for UTC+, positive for UTC-
                # Convert minutes to hours
                offset_hours = -bias_minutes / 60
                
                # Format as "UTC+X" or "UTC-X"
                if offset_hours == int(offset_hours):
                    return f"UTC{int(offset_hours):+d}"
                else:
                    return f"UTC{offset_hours:+.1f}"
                    
        except Exception as e:
            logger.warning(f"Could not detect timezone: {e}")
            return "UTC+0"
        
    def _normalize_event(self, raw_record) -> Optional[Event]:
        """Convert raw EVTX record to normalized Event object with defensive schema checks."""
        try:
           # 1. Handle string serialization from records_json() automatically
            if isinstance(raw_record, str):
                try:
                    raw_record = json.loads(raw_record)
                except Exception:
                    return None

            if not isinstance(raw_record, dict):
                return None
                
            event_record_id = raw_record.get('event_record_id', 0)
            
            timestamp_utc_str = raw_record.get('timestamp') or raw_record.get('TimeCreated', {}).get('@SystemTime')
            
            raw_data = raw_record.get('data', {})
            if isinstance(raw_data, str):
                try:
                    raw_data = json.loads(raw_data)
                except Exception:
                    return None  
            
            if not isinstance(raw_data, dict):
                return None
                
            # If the parser output structure is completely flat, wrap it so structural paths don't break
            if 'Event' not in raw_data and 'event' not in raw_data:
                if 'System' in raw_data or 'system' in raw_data:
                    raw_data = {'Event': raw_data}
                else:
                    # Inject a safe layout structural mock for raw values
                    raw_data = {'Event': {'System': raw_data, 'EventData': raw_data.get('EventData', raw_data)}}
                
            event_dict = raw_data.get('Event') or raw_data.get('event', {})
            if not isinstance(event_dict, dict):
                return None

            system_dict = event_dict.get('System') or event_dict.get('system', {})
            if not isinstance(system_dict, dict):
                return None

            event_data_dict = event_dict.get('EventData') or event_dict.get('event_data')
            if not isinstance(event_data_dict, dict):
                event_data_dict = {}

            if not timestamp_utc_str:
                time_created = system_dict.get('TimeCreated', {})
                if isinstance(time_created, dict):
                    timestamp_utc_str = time_created.get('@SystemTime') or time_created.get('#text')
                elif isinstance(time_created, str):
                    timestamp_utc_str = time_created

            if not timestamp_utc_str:
                return None

            # 2. Extract metadata safely
            event_id = system_dict.get('EventID', 0)
            if isinstance(event_id, dict):
                event_id = event_id.get('#text', 0)
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                event_id = 0

            # Safe extraction of Computer context from varying System layouts
            computer = "Unknown"
            comp_val = system_dict.get('Computer') or system_dict.get('ComputerName')
            if isinstance(comp_val, dict):
                computer = comp_val.get('#text', 'Unknown')
            elif comp_val:
                computer = str(comp_val)

            # 3. Field Extraction Helper (Kept local as per your parser structure)
            def _get_field(data_block, field_name):
                if not isinstance(data_block, dict): 
                    return 'UNKNOWN'
                if field_name in data_block:
                    v = data_block[field_name]
                    return v.get('#text', str(v)) if isinstance(v, dict) else str(v)
                
                data_list = data_block.get('Data', [])
                if isinstance(data_list, list):
                    for item in data_list:
                        if isinstance(item, dict) and item.get('@Name') == field_name:
                            return str(item.get('#text', 'UNKNOWN'))
                return 'UNKNOWN'

            # Extract user safely
            if event_id in [4624, 4625, 4798]:
                user = _get_field(event_data_dict, 'TargetUserName')
            else:
                user = _get_field(event_data_dict, 'SubjectUserName')

            # Parse timestamp
            timestamp_utc = self._validate_timestamp(timestamp_utc_str)
            if timestamp_utc is None:
                return None

            # Calculate local timestamp
            local_timestamp = self._calculate_local_timestamp(timestamp_utc, self.system_timezone)

            # Extract IPs
            ips = self._extract_ips_from_event(event_id, event_data_dict)

            # Extract failure reason
            if event_id in [4625, 4647, 4648, 4798]:
                failure_reason = self._extract_failure_reason(event_data_dict)
            else:
                failure_reason = None

            # Calculate priority
            priority = self._calculate_forensic_priority(event_id)

            # Create Event
            return Event(
                timestamp=timestamp_utc,
                source_device=computer,
                source_type="EVTX",
                event_type=str(event_id),
                user=user,
                payload=event_data_dict,
                timezone_offset=self.system_timezone,
                local_timestamp=local_timestamp,
                extracted_ips=ips,
                forensic_priority=priority,
                failure_reason=failure_reason,
                corruption_detected=False,
                corruption_details=None,
                confidence_score=1.0
            )
        
        except Exception as e:
            logger.error(f"Error normalizing event: {e}")
            return None 
    
    def _extract_ips_from_event(self, event_id, event_data):
        """Extract IP addresses from event data based on known field names and patterns."""
        if not isinstance(event_data, dict):
            return []
        
        ip_found = []
        
        # Check for direct IP field
        if 'IpAddress' in event_data:
            ip = event_data['IpAddress']
            if ip and ip not in ['-', '::1', '0.0.0.0']:
                ip_found.append(ip)
        
        # Check for source IP (network events)
        if event_id == 5140 and 'SourceIPAddress' in event_data:
            ip = event_data['SourceIPAddress']
            if ip and ip not in ['-', '::1', '0.0.0.0']:
                ip_found.append(ip)
        
        # Fallback: regex scan
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        for key, value in event_data.items():
            if isinstance(value, str):
                matches = ip_pattern.findall(value)
                ip_found.extend(matches)
        
        # Normalize IPs
        normalised_ips = []
        for ip in ip_found:
            normalised_ip = self._normalize_ip(ip)
            if normalised_ip:
                normalised_ips.append(normalised_ip)
        
        # Remove duplicates
        return list(set(normalised_ips))

    def _normalize_ip(self, ip):
        """
        Normalize IP address and categorize it based on known patterns.
        """
        if ip in self.IP_CATEGORIES:
            return f"{ip} ({self.IP_CATEGORIES[ip]})"
        elif re.match(r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return f"{ip} (localhost)"
        elif re.match(r'^192\.168\.\d{1,3}\.\d{1,3}$', ip):
            return f"{ip} (Private Network)"
        elif re.match(r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return f"{ip} (Private Network)"
        elif re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$', ip):
            return f"{ip} (Private Network)"
        elif re.match(r'^169\.254\.\d{1,3}\.\d{1,3}$', ip):
            return f"{ip} (APIPA)"
        elif re.match(r'^0\.0\.0\.0$', ip):
            return f"{ip} (unspecified)"
        elif re.match(r'^255\.255\.255\.255$', ip):
            return f"{ip} (broadcast)"
        elif re.match(r'^224\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return f"{ip} (multicast)"
        else:
            return f"{ip} (Public)"  # Return as-is if it doesn't match known patterns          
        
    def _extract_failure_reason(self, event_data):
        """Extract failure reason checking both flat keys and list structures."""
        # Use a localized look up helper compatible with the new schema parsing requirements
        def _get_field(data_block, field_name):
            if not isinstance(data_block, dict): return None
            if field_name in data_block:
                v = data_block[field_name]
                return v.get('#text', str(v)) if isinstance(v, dict) else str(v)
            data_list = data_block.get('Data', [])
            if isinstance(data_list, list):
                for item in data_list:
                    if isinstance(item, dict) and item.get('@Name') == field_name:
                        return str(item.get('#text', None))
            return None

        reason_code = _get_field(event_data, 'FailureReason') or _get_field(event_data, 'Status')
        if not reason_code:
            return None

        CODE_MAPPING = {
            "0xC000005E": "No such user",
            "0xC000006A": "Incorrect password",
            "0xC0000234": "Account locked",
            "0xC0000133": "Time difference too large",
            "0xC000006D": "Incorrect user name or password",
            "0xC0000193": "Account expired"
        }

        reason_code = str(reason_code).strip()
        return CODE_MAPPING.get(reason_code, f"Unknown failure reason (code: {reason_code})")
        
    def _calculate_local_timestamp(self, utc_dt: datetime, offset_str: str) -> datetime:
        """
        Calculate local timestamp from UTC based on string offset format (e.g., 'UTC+5:30', 'UTC-5').
        """
        if not utc_dt:
            return utc_dt
            
        try:
            clean_offset = offset_str.upper().replace("UTC", "").strip()
            if not clean_offset or clean_offset == "+0" or clean_offset == "-0":
                return utc_dt

            # Determine sign
            sign = -1 if clean_offset.startswith("-") else 1
            clean_offset = clean_offset.lstrip("+-")

            # Parse hours and minutes safely
            if ":" in clean_offset:
                hours_part, minutes_part = clean_offset.split(":", 1)
                hours = int(hours_part)
                minutes = int(minutes_part)
            else:
                hours = int(clean_offset)
                minutes = 0

            # Calculate delta and apply
            delta = timedelta(hours=hours, minutes=minutes)
            if sign == -1:
                return utc_dt - delta
            else:
                return utc_dt + delta

        except Exception:
            # Fallback to returning original UTC datetime if format parsing errors out
            return utc_dt
        
    def _calculate_forensic_priority(self, event_id):
        """
        Calculate forensic priority based on event ID and known high/medium priority events.
        """
        if event_id in self.HIGH_PRIORITY_EVENTS:
            return "HIGH"
        elif event_id in self.MEDIUM_PRIORITY_EVENTS:
            return "MEDIUM"
        else:
            return "LOW"
        
    def _validate_timestamp(self, timestamp_str):
        """
        Validate and parse timestamp string from EVTX record.
        """
        try:
            # 1. Strip trailing ' UTC' if present
            clean_str = timestamp_str.strip()
            if clean_str.endswith(" UTC"):
                clean_str = clean_str[:-4].strip()

            # 2. Handle Windows 7-digit nanosecond precision (Python handles max 6 digits)
            # Matches a dot followed by digits before the timezone specifier
            if '.' in clean_str:
                base, fraction = clean_str.split('.', 1)
                # Separate the digits from the timezone indicator (Z, +, -)
                match = re.match(r'^(\d+)(.*)$', fraction)
                if match:
                    digits, tz = match.groups()
                    if len(digits) > 6:
                        # Truncate to 6 digits (microseconds) to satisfy Python parsing rules
                        clean_str = f"{base}.{digits[:6]}{tz}"

            # EVTX timestamps are typically in ISO 8601 format
            timestamp_utc = datetime.fromisoformat(clean_str.replace('Z', '+00:00'))
            
            # Checking if the timestamp is in the future or before Windows epoch (January 1, 1601)
            now = datetime.now(timezone.utc)
            if timestamp_utc > now + timedelta(days=1) or timestamp_utc < datetime(1601, 1, 1, tzinfo=timezone.utc):
                self.corruption_log.append({"error": f"Timestamp out of valid range: {timestamp_str}", "stage": "timestamp_validation"})
                return timestamp_utc  # Return as-is but log the anomaly
            
            return timestamp_utc
        except Exception as e:
            self.corruption_log.append({"error": str(e), "timestamp_str": timestamp_str, "stage": "timestamp_parsing"})
            return None
                
    def _build_corruption_audit_log(self, corruption_threshold=None):
        """
        Build a detailed corruption audit log file if corruption threshold is exceeded using logger model of loguru.
        """
        if corruption_threshold is None:
            corruption_threshold = self.CORRUPTION_THRESHOLD
                    
        total_records_attempted = self.events_count
        corrupted_count = len(self.corruption_log)
        corruption_percentage = (corrupted_count / total_records_attempted)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if corruption_percentage >= corruption_threshold:
            logger.add(
                f"logs/evtx_corruption_audit_{timestamp}.log",
                format="{message}",
                level = "WARNING")
            logger.warning("=== EVTX Corruption Audit Trail ===")
            logger.warning(f"File: {self.artifact_path}")
            logger.warning(f"Total Records: {total_records_attempted}")
            logger.warning(f"Corruption: {corrupted_count} ({corruption_percentage*100}%)")
            logger.warning("Status: POTENTIAL TAMPERING DETECTED")
            logger.warning("\n")
            logger.warning("Detailed Corruption Log:")
            for corr in self.corruption_log:
                logger.warning(f"{json.dumps(corr, indent=2)}\n")
            print("High corruption in EVTX, audit log created")

        elif corruption_percentage > 0:
            print("Corruption in EVTX")
        else:
            return
        