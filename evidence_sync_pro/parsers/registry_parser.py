from Registry import Registry                           # Read Windows registry hives
from pathlib import Path                                # File path handling
from datetime import datetime, timezone, timedelta      # Timestamp conversion
from typing import List, Dict, Any, Optional            # Type hints
from .base_parser import BaseParser, Event              # Our base class
import struct                                           # For binary data unpacking (SAM V field)
import hashlib                                          # For chain of custody (MD5/SHA256)
from loguru import logger                               # Logging
import re                                               # Regex for IP extraction
import subprocess

class RegistryParser(BaseParser):
    """
    Complete Windows Registry Parser
    - Parses 8 registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, COMPONENTS, 
      DEFAULT, NTUSER.DAT, USRCLASS.DAT)
    - Extracts 7 categories of forensic artifacts
    - Prioritized parsing (highest forensic value first)
    - Chain of custody tracking
    """
    
    # === PRIORITY CONSTANTS ===
    PRIORITY_1_HIVES = ["SAM", "NTUSER.DAT", "SYSTEM"]
    PRIORITY_2_HIVES = ["SOFTWARE", "SECURITY"]
    PRIORITY_3_HIVES = ["USRCLASS.DAT", "COMPONENTS"]
    PRIORITY_4_HIVES = ["DEFAULT"]
    
    # === REGISTRY PATHS (by priority) ===
    
    # Priority 1
    SAM_USERS_PATH = r"SAM\Domains\Account\Users"
    RUN_MRU_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    TYPED_PATHS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
    RECENT_DOCS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Recent Documents"
    MOUNTPOINTS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    USB_ENUM_PATH = r"SYSTEM\CurrentControlSet\Enum\USB"
    NETWORK_ADAPTERS_PATH = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    
    # Priority 2
    UNINSTALL_PATH = r"Microsoft\Windows\CurrentVersion\Uninstall"
    RUN_KEY_PATH = r"Microsoft\Windows\CurrentVersion\Run"
    RUNONCE_KEY_PATH = r"Microsoft\Windows\CurrentVersion\RunOnce"
    SERVICES_PATH = r"SYSTEM\CurrentControlSet\Services"
    BHO_PATH = r"Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    LSA_SECRETS_PATH = r"SECURITY\Policy\Secrets"
    
    # Priority 3
    SHELL_EXT_PATH = r"Local Settings\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
    FILE_EXTS_PATH = r"Local Settings\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
    
    # === METHODS (by priority) ===
    
    def __init__(self, 
                 system_hive_path: str,
                 software_hive_path: str,
                 sam_hive_path: str,
                 security_hive_path: str,
                 ntuser_dat_paths: List[str],
                 usrclass_dat_paths: List[str] = None,
                 components_hive_path: str = None,
                 default_hive_path: str = None,
                 computer_name: str = "UNKNOWN_HOST",
                 system_timezone: str = "UTC+0"):
        """Initialize with all hive paths (prioritized order)"""
        # Initialize base parser and set system hive path for timezone extraction
        self.system_hive_path = system_hive_path
        self.software_hive_path = software_hive_path
        self.sam_hive_path = sam_hive_path
        self.security_hive_path = security_hive_path
        self.ntuser_dat_path = ntuser_dat_paths
        self.usrclass_dat_paths = usrclass_dat_paths
        self.components_hive_path = components_hive_path
        self.default_hive_path = default_hive_path
        self.system_timezone = system_timezone
        self.computer_name = computer_name

        self.corruption_log: List[Dict[str, Any]] = []
        self.events_count = 0

    
    def parse(self) -> List[Event]:
        """
        Main entry point: parse all hives in priority order.
        
        Extracts forensic artifacts from all 8 registry hives in priority order:
        Priority 1: SAM, NTUSER.DAT, SYSTEM (user accounts + activity + USB timeline)
        Priority 2: SOFTWARE, SECURITY (services, programs, LSA secrets)
        Priority 3: USRCLASS.DAT, COMPONENTS (shell extensions, updates)
        Priority 4: DEFAULT (system defaults)
        
        Returns:
            List[Event]: All extracted forensic events in priority order
        """
        
        all_events = []
        
        try:
            logger.info("="*80)
            logger.info("EVIDENCESYNC PRO REGISTRY PARSER - STARTING FULL EXTRACTION")
            logger.info("="*80)
            
            # === PRIORITY 1: SAM, NTUSER.DAT, SYSTEM ===
            logger.info("\n[PRIORITY 1] Loading hives: SAM, NTUSER.DAT, SYSTEM")
            
            sam_hive = self._load_hive(self.sam_hive_path)
            system_hive = self._load_hive(self.system_hive_path)
            ntuser_hives = [self._load_hive(path) for path in self.ntuser_dat_path] if self.ntuser_dat_path else []
            
            # Extract user accounts (Bit 1)
            if sam_hive:
                logger.info("[Bit 1] Extracting user accounts from SAM...")
                sam_events = self._extract_user_accounts(sam_hive)
                all_events.extend(sam_events)
                logger.info(f"  ✓ Extracted {len(sam_events)} user account events")
            
            # Extract user activity (Bit 2)
            if ntuser_hives:
                logger.info("[Bit 2] Extracting user activity from NTUSER.DAT...")
                
                # Get usernames from SAM if available
                usernames = []
                if all_events:
                    for event in all_events:
                        if event.event_type == "user_account_info":
                            usernames.append(event.payload.get("username", "Unknown"))
                
                # If no usernames found, use generic name
                if not usernames:
                    usernames = ["DefaultUser"]
                
                for ntuser_hive, username in zip(ntuser_hives, usernames):
                    if ntuser_hive:
                        user_activity = self._extract_user_activity(ntuser_hive, username)
                        all_events.extend(user_activity)
                        logger.info(f"  ✓ Extracted {len(user_activity)} user activity events for {username}")
            
            # Extract USB timeline (Bit 3 partial - SYSTEM hive)
            if system_hive:
                logger.info("[Bit 3 - SYSTEM] Extracting USB timeline and network adapters...")
                usb_events = self._extract_usb_timeline(system_hive)
                net_events = self._extract_network_adapters(system_hive)
                all_events.extend(usb_events)
                all_events.extend(net_events)
                logger.info(f"  ✓ Extracted {len(usb_events)} USB events and {len(net_events)} network adapter events")
            
            # === PRIORITY 2: SOFTWARE, SECURITY ===
            logger.info("\n[PRIORITY 2] Loading hives: SOFTWARE, SECURITY")
            
            software_hive = self._load_hive(self.software_hive_path)
            security_hive = self._load_hive(self.security_hive_path)
            
            if software_hive and system_hive:
                logger.info("[Bit 3 - SOFTWARE] Extracting installed programs, startup programs, BHOs, services...")
                
                prog_events = self._extract_installed_programs(software_hive)
                startup_events = self._extract_startup_programs(software_hive)
                bho_events = self._extract_browser_helper_objects(software_hive)
                service_events = self._extract_services(software_hive, system_hive)
                
                all_events.extend(prog_events)
                all_events.extend(startup_events)
                all_events.extend(bho_events)
                all_events.extend(service_events)
                
                logger.info(f"  ✓ Extracted {len(prog_events)} program, {len(startup_events)} startup, "
                        f"{len(bho_events)} BHO, {len(service_events)} service events")
            
            if security_hive:
                logger.info("[Bit 3 - SECURITY] Extracting LSA secrets...")
                lsa_events = self._extract_lsa_secrets(security_hive)
                all_events.extend(lsa_events)
                logger.info(f"  ✓ Extracted {len(lsa_events)} LSA secret events")
            
            # === PRIORITY 3: USRCLASS.DAT, COMPONENTS ===
            logger.info("\n[PRIORITY 3] Loading hives: USRCLASS.DAT, COMPONENTS")
            
            usrclass_hives = [self._load_hive(path) for path in self.usrclass_dat_paths] if self.usrclass_dat_paths else []
            components_hive = self._load_hive(self.components_hive_path) if self.components_hive_path else None
            
            if usrclass_hives:
                logger.info("[Bit 4 - USRCLASS] Extracting shell extensions and file associations...")
                
                for usrclass_hive, username in zip(usrclass_hives, usernames):
                    if usrclass_hive:
                        shell_events = self._extract_shell_extensions(usrclass_hive, username)
                        assoc_events = self._extract_file_associations(usrclass_hive, username)
                        all_events.extend(shell_events)
                        all_events.extend(assoc_events)
                        logger.info(f"  ✓ Extracted {len(shell_events)} shell extension and {len(assoc_events)} "
                                f"file association events for {username}")
            
            if components_hive:
                logger.info("[Bit 5 - COMPONENTS] Extracting Windows updates and components...")
                update_events = self._extract_windows_updates(components_hive)
                all_events.extend(update_events)
                logger.info(f"  ✓ Extracted {len(update_events)} component/update events")
            
            # === PRIORITY 4: DEFAULT ===
            # DEFAULT hive parsing not yet implemented
            
            # === FINAL SUMMARY ===
            logger.info("\n" + "="*80)
            logger.info("REGISTRY PARSER EXTRACTION COMPLETE")
            logger.info("="*80)
            logger.info(f"Total events extracted: {len(all_events)}")
            logger.info(f"Corruption log entries: {len(self.corruption_log)}")
            logger.info(f"Parser state - events_count: {self.events_count}")
            logger.info("="*80 + "\n")
            
            return all_events
        
        except Exception as e:
            logger.error(f"Fatal error in parse(): {e}")
            logger.error(f"Partially extracted: {len(all_events)} events before failure")
            self.corruption_log.append({
                "error": str(e),
                "stage": "parse_main_entry_point",
                "events_extracted_before_failure": len(all_events)
            })
            return all_events  # Return partial results
    
    # PRIORITY 1
    def _extract_user_accounts(self, sam_hive) -> List[Event]:
        """
        Extract user accounts from SAM hive.
        
        Returns events for each user with:
        - Username
        - RID (Relative ID)
        - Creation date
        - Last login timestamp
        - Failed login count
        - Account enabled/disabled
        """
        
        events = []
        try:
            # Step 1: Navigate to SAM\Domains\Account\Users
            sam_root = sam_hive.root()
            users_key = self._get_registry_key(sam_hive, self.SAM_USERS_PATH)

            if users_key is None:
                logger.warning("SAM Users key not found")
                return []
            
            # Step 2: Get the names subkey to extract usernames
            names_key = users_key.subkey("Names")
            username_map = {}

            if names_key is not None:
                for value in names_key.values():
                    username = value.name()
                    rid = self._extract_rid_from_value(value)

                    if rid is not None:
                        username_map[rid] = username    # Map RID to username
            
            # Step 3: Iterate through numeric RID keys
            for subkey in users_key.subkeys():
                
                if subkey is None:
                    continue

                subkey_name = subkey.name()

                # Skip non-numeric subkeys
                if not self._is_numeric_rid(subkey_name):
                    continue

                try:
                    rid = int(subkey_name, 16)      # Convert hex to decimal

                    # Get username from our map
                    username = username_map.get(rid, f"Unknown_RID_{rid}")

                    # Step 4: Extract V field
                    v_value = self._get_value(subkey, "V")
                    if v_value is None:
                        continue

                    # Step 5: Parse V field binary structure
                    parsed_v = self._parse_sam_v_field(v_value)

                    # Extract critical timestamps
                    last_login = parsed_v.get("last_login_time")
                    last_password_set = parsed_v.get("last_password_set_time")
                    failed_login_count = parsed_v.get("failed_login_count", 0)
                    login_count = parsed_v.get("login_count", 0)
                    account_disabled = parsed_v.get("account_disabled", False)
                    account_locked = parsed_v.get("account_locked", False)

                    # Step 6: Create Event object
                    events.append(Event(
                        timestamp = last_login if last_login else datetime.now(timezone.utc),
                        source_device = self.computer_name,
                        source_type = "REGISTRY",
                        event_type = "user_account_info",
                        user = "SYSTEM",     # SAM is system-level
                        payload = {
                            "username": username,
                        "rid": rid,
                        "last_login": last_login,
                        "last_password_set": last_password_set,
                        "failed_login_count": failed_login_count,
                        "login_count": login_count,
                        "account_disabled": account_disabled,
                        "account_locked": account_locked,
                        "registry_path": f"HKLM\\SAM\\SAM\\Domains\\Account\\Users\\{subkey_name}",
                        "hive_source": self.sam_hive_path,
                        "hive_hash_sha256": self._get_chain_of_custody_metadata(self.sam_hive_path)["sha256"]
                        },
                        timezone_offset = self.system_timezone,
                        local_timestamp = self._calculate_local_timestamp(last_login, self.system_timezone) if last_login else None,
                        forensic_priority = "HIGH",
                        confidence_score = 0.95,        # SAM is high-fidelity source
                        corruption_detected = False

                    ))
                    self.events_count += 1
                    return events

                except Exception as e:
                    logger.warning(f"Error parsing user RID {subkey_name}: {e}")
                    self.corruption_log.append({
                    "error": str(e),
                    "stage": "sam_user_parsing",
                    "rid": subkey_name
                })

        except Exception as e:
            logger.warning(f"Error extracting user accounts from SAM: {e}")
    
    def _extract_user_activity(self, ntuser_hive, username: str) -> List[Event]:
        """
        Extract ALL user activity from NTUSER.DAT hive.
        
        Calls all 5 extraction methods and combines results.
        """
        events = []

        try:
            logger.info(f"Extracting user activity for: {username}")
        
            # Extract search history
            events += self._extract_search_history(ntuser_hive, username)
            logger.debug(f"Search history: {len(self._extract_search_history(ntuser_hive, username))} entries")
            
            # Extract typed URLs/paths
            events += self._extract_typed_paths(ntuser_hive, username)
            logger.debug(f"Typed paths: {len(self._extract_typed_paths(ntuser_hive, username))} entries")
            
            # Extract recent documents
            events += self._extract_recent_documents(ntuser_hive, username)
            logger.debug(f"Recent documents: {len(self._extract_recent_documents(ntuser_hive, username))} entries")
            
            # Extract recent programs
            events += self._extract_recent_programs(ntuser_hive, username)
            logger.debug(f"Recent programs: {len(self._extract_recent_programs(ntuser_hive, username))} entries")
            
            # Extract network shares
            events += self._extract_network_shares(ntuser_hive, username)
            logger.debug(f"Network shares: {len(self._extract_network_shares(ntuser_hive, username))} entries")
            
            logger.info(f"Total user activity events for {username}: {len(events)}")
            
            return events

        except Exception as e:
            return

    def _extract_usb_timeline(self, system_hive) -> List[Event]:
        r"""
        Extract USB device enumeration history from SYSTEM hive.
        
        Path: SYSTEM\CurrentControlSet\Enum\USB
        
        Structure:
        USB/
        ├── VID_1234&PID_5678  (Device ID)
        │   ├── FriendlyName = "Kingston DataTraveler 3.0"
        │   ├── SerialNumber = "ABC123XYZ"
        │   ├── Class = "USB Mass Storage Device"
        │   └── (Timestamp of last write = enumeration time)
        ├── VID_ABCD&PID_EF01
        └── ...
        
        Each subkey's last-write timestamp indicates when device was plugged in
        """

        events = []
        try:
            # Step 1: Navigate to USB enum key
            usb_key = None
            # Try numbered control sets
            for cs_num in ['001', '002', '003']:
                usb_key = self._get_registry_key(
                    system_hive,
                    f"ControlSet{cs_num}\\Enum\\USB"
                )
                if usb_key is not None:
                    break
            
            if usb_key is None:
                logger.debug("USB enum key not found")
                return events
                    
            # Step 2: Iterate through device subkeys
            for device_subkey in usb_key.subkeys():
                device_id = device_subkey.name()
                device_timestamp = device_subkey.timestamp()

                # Step 3: Extract device properties
                friendly_name = self._get_value(device_subkey, "FriendlyName") or device_id or "Unknown"
                serial_number = self._get_value(device_subkey, "SerialNumber")
                class_name = self._get_value(device_subkey, "Class")

                # Step 4: Extract Vendor/Product IDs
                vid = self._extract_vid_from_device_id(device_id)  # "1234" from VID_1234
                pid = self._extract_pid_from_device_id(device_id)  # "5678" from PID_5678

                # Step 5: Create Event
                event = Event(
                    timestamp= device_timestamp,
                    source_device= self.computer_name,
                    source_type= "REGISTRY",
                    event_type= "usb_device_enumerated",
                    user= "SYSTEM",
                    payload= {
                        "device_id": device_id,
                        "vendor_id": vid,
                        "product_id": pid,
                        "friendly_name": friendly_name,
                        "serial_number": serial_number,
                        "class": class_name,
                        "registry_path": self.USB_ENUM_PATH,
                        "hive_source": self.system_hive_path,
                    },
                    timezone_offset= self.system_timezone,
                    local_timestamp= self._calculate_local_timestamp(device_timestamp, self.system_timezone),
                    forensic_priority= "HIGH",  # Physical access timeline!
                    confidence_score= 0.95,
                    corruption_detected= False
                )
                events.append(event)
                self.events_count += 1
            
            return events

        except Exception as e:
            logger.warning(f"Error extracting USB timeline: {e}")
            return[]
    
    def _extract_network_adapters(self, system_hive) -> List[Event]:
        r"""
        Extract network adapter configurations from SYSTEM hive.
        
        Path: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\interfaces
        
        Structure:
        interfaces/
        ├── {GUID-1234-5678-90AB}
        │   ├── DhcpEnabled = 1 (0=static, 1=DHCP)
        │   ├── Dhcp5Result = 0 (DHCP result code)
        │   ├── DhcpIPAddress = "192.168.1.50"
        │   ├── DhcpServer = "192.168.1.1"
        │   ├── DhcpDefaultGateway = "192.168.1.1"
        │   ├── DhcpNameServers = "8.8.8.8 8.8.4.4"
        │   ├── LeaseObtainedTime = (FILETIME)
        │   ├── T1 = (FILETIME - DHCP renewal time)
        │   └── T2 = (FILETIME - DHCP rebind time)
        └── {GUID-ABCD-EF01-2345}
            └── ...
        
        Contains both DHCP and static IP configuration
        """
        
        events = []
        
        try:
            # Step 1: Navigate to network adapters key
            adapters_key = None
            # Try numbered control sets
            for cs_num in ['001', '002', '003']:
                adapters_key = self._get_registry_key(
                    system_hive,
                    f"ControlSet{cs_num}\Services\Tcpip\Parameters\Interfaces"
                )
                if adapters_key is not None:
                    break
            
            if adapters_key is None:
                logger.debug("Network adapters key not found")
                return events

            
            # Step 2: Iterate through adapter GUIDs
            for adapter_subkey in adapters_key.subkeys():
                adapter_guid = adapter_subkey.name()
                adapter_timestamp = adapter_subkey.timestamp()
                
                # Step 3: Extract DHCP status
                dhcp_enabled = self._get_value(adapter_subkey, "DhcpEnabled")
                
                # Step 4: Extract IP addresses (both static and DHCP)
                ip_addresses = []
                
                if dhcp_enabled == 1:
                    # DHCP-assigned IP
                    dhcp_ip = self._get_value(adapter_subkey, "DhcpIPAddress")
                    if dhcp_ip:
                        ip_addresses.append({
                            "type": "DHCP",
                            "address": dhcp_ip
                        })
                    
                    dhcp_server = self._get_value(adapter_subkey, "DhcpServer")
                    dhcp_gateway = self._get_value(adapter_subkey, "DhcpDefaultGateway")
                
                else:
                    # Static IP
                    static_ip = self._get_value(adapter_subkey, "IPAddress")
                    if static_ip:
                        ip_addresses.append({
                            "type": "Static",
                            "address": static_ip
                        })
                
                # Step 5: Extract DNS servers
                dns_servers = self._get_value(adapter_subkey, "NameServer")
                
                # Step 6: Extract DHCP lease times
                lease_obtained = self._get_value(adapter_subkey, "LeaseObtainedTime")
                
                # Step 7: Extract IPs for forensic relevance
                extracted_ips = []
                for ip_info in ip_addresses:
                    extracted_ips.append(ip_info["address"])
                if dhcp_server:
                    extracted_ips.append(dhcp_server)
                if dns_servers:
                    for dns in dns_servers.split(" "):
                        extracted_ips.append(dns)
                
                # Step 8: Create Event
                event = Event(
                    timestamp= adapter_timestamp,
                    source_device= self.computer_name,
                    source_type= "REGISTRY",
                    event_type= "network_adapter_config",
                    user= "SYSTEM",
                    payload= {
                        "adapter_guid": adapter_guid,
                        "dhcp_enabled": dhcp_enabled,
                        "ip_addresses": ip_addresses,
                        "dhcp_server": dhcp_server,
                        "dns_servers": dns_servers,
                        "lease_obtained": lease_obtained,
                        "registry_path": self.NETWORK_ADAPTERS_PATH,
                        "hive_source": self.system_hive_path,
                    },
                    extracted_ips= list(set(extracted_ips)),  # Deduplicate
                    timezone_offset= self.system_timezone,
                    local_timestamp= self._calculate_local_timestamp(adapter_timestamp, self.system_timezone),
                    forensic_priority= "MEDIUM",
                    confidence_score= 0.90,
                    corruption_detected= False
                )
                
                events.append(event)
                self.events_count += 1

            return events
        
        except Exception as e:
            logger.warning(f"Error extracting network adapters: {e}")
            return []

    # PRIORITY 2
    def _extract_system_info(self, system_hive, software_hive, security_hive) -> List[Event]:
        """
        Extract ALL system-wide registry artifacts (Bit 3).
        
        Calls all extraction methods and returns combined timeline.
        """
        
        events = []
        
        try:
            logger.info("Extracting system-wide registry artifacts (Bit 3)")
            
            # SYSTEM hive extractions
            logger.info("Extracting USB timeline...")
            usb_events = self._extract_usb_timeline(system_hive)
            events.extend(usb_events)
            
            logger.info("Extracting network adapters...")
            net_events = self._extract_network_adapters(system_hive)
            events.extend(net_events)
            
            logger.info("Extracting services...")
            service_events = self._extract_services(software_hive, system_hive)
            events.extend(service_events)
            
            # SOFTWARE hive extractions
            logger.info("Extracting installed programs...")
            prog_events = self._extract_installed_programs(software_hive)
            events.extend(prog_events)
            
            logger.info("Extracting startup programs...")
            startup_events = self._extract_startup_programs(software_hive)
            events.extend(startup_events)
            
            logger.info("Extracting Browser Helper Objects...")
            bho_events = self._extract_browser_helper_objects(software_hive)
            events.extend(bho_events)
            
            # SECURITY hive extractions
            logger.info("Extracting LSA secrets...")
            lsa_events = self._extract_lsa_secrets(security_hive)
            events.extend(lsa_events)
            
            logger.info(f"Total Bit 3 events extracted: {len(events)}")
            
            return events
        
        except Exception as e:
            logger.error(f"Fatal error in Bit 3 extraction: {e}")
            return []
   
    def _extract_installed_programs(self, software_hive) -> List[Event]:
        r"""
        Extract installed programs from SOFTWARE hive.
        
        Path: Microsoft\Windows\CurrentVersion\Uninstall
        
        Structure:
        Uninstall/
        ├── {GUID-1234-5678}
        │   ├── DisplayName = "Microsoft Office 2019"
        │   ├── DisplayVersion = "16.0.1234"
        │   ├── Publisher = "Microsoft Corporation"
        │   ├── installDate = "20240608"  (YYYYMMDD format)
        │   ├── UninstallString = "..."
        │   └── (Last write time = when registry was updated)
        ├── Adobe Reader
        │   ├── DisplayName = "Adobe Acrobat Reader"
        │   ├── DisplayVersion = "24.001.20629"
        │   └── ...
        └── ...
        
        installDate may not be accurate (user can modify)
        Last-write timestamp is more reliable
        """
        
        events = []
        
        try:
            # Step 1: Navigate to Uninstall key
            uninstall_key = self._get_registry_key(software_hive, self.UNINSTALL_PATH)
            
            if uninstall_key is None:
                logger.debug("Uninstall key not found")
                return []
            
            # Step 2: Iterate through program subkeys
            for program_subkey in uninstall_key.subkeys():
                program_guid = program_subkey.name()
                registry_timestamp = program_subkey.timestamp()  # Most reliable
                
                # Step 3: Extract program metadata
                display_name = self._get_value(program_subkey, "DisplayName")
                display_version = self._get_value(program_subkey, "DisplayVersion") or "Unknown"
                publisher = self._get_value(program_subkey, "Publisher")
                install_date_str = self._get_value(program_subkey, "installDate")
                
                # Skip if no display name (empty entry)
                if not display_name:
                    continue
                
                # Step 4: Parse install date if available
                install_date = None
                if install_date_str:
                    try:
                        # Convert "20240608" to datetime
                        install_date = datetime.strptime(install_date_str, "%Y%m%d")
                    except:
                        install_date = None
                
                # Use registry timestamp if install date unavailable
                event_timestamp = install_date if install_date else registry_timestamp
                
                # Step 5: Create Event
                event = Event(
                    timestamp= event_timestamp,
                    source_device= self.computer_name,
                    source_type= "REGISTRY",
                    event_type= "program_installed",
                    user= "SYSTEM",
                    payload= {
                        "program_name": display_name,
                        "program_guid": program_guid,
                        "version": display_version,
                        "publisher": publisher,
                        "install_date": install_date_str,
                        "registry_timestamp": registry_timestamp,
                        "registry_path": self.UNINSTALL_PATH,
                        "hive_source": self.software_hive_path,
                    },
                    timezone_offset= self.system_timezone,
                    local_timestamp= self._calculate_local_timestamp(event_timestamp, self.system_timezone),
                    forensic_priority= "MEDIUM",
                    confidence_score= 0.70,  # installDate can be spoofed
                    corruption_detected= False
                )
                
                events.append(event)
                self.events_count += 1

            return events
        
        except Exception as e:
            logger.warning(f"Error extracting installed programs: {e}")
            return []

    def _extract_startup_programs(self, software_hive) -> List[Event]:
        r"""
        Extract startup programs from Run/RunOnce registry keys.
        
        These are PERSISTENCE MECHANISMS - programs that auto-start
        
        Paths:
        - Microsoft\Windows\CurrentVersion\Run (runs every boot)
        - Microsoft\Windows\CurrentVersion\RunOnce (runs once, then deletes)
        
        Structure:
        Run/
        ├── "Windows Defender" = "C:\Program Files\Windows Defender\..."
        ├── "CCleaner" = "C:\Program Files\CCleaner\CCleaner.exe"
        ├── "Malware.exe" = "C:\AppData\Local\Temp\evil.exe"  ← SUSPICIOUS!
        └── ...
        
        RunOnce/
        ├── "Update" = "C:\Updates\install.exe"
        └── ...
        
        FORENSIC SIGNIFICANCE: Malware often uses Run keys for persistence
        """
        
        events = []
        try:
            # Extract from both Run and RunOnce keys
            for key_path in [self.RUN_KEY_PATH, self.RUNONCE_KEY_PATH]:
                run_key = self._get_registry_key(software_hive, key_path)

                if run_key is None:
                  continue

                key_type = "RunOnce" if "RunOnce" in key_path else "Run"
                key_timestamp = run_key.timestamp()  
                
                # Step 2: Iterate through values
                for value in run_key.values():
                    program_name = value.name()
                    command = value.value()

                    # Skip empty or none values
                    if not command:
                        continue

                    # Step 3: Analyze command for suspicion indicators
                    suspicion_score = 0

                    if "\\Temp\\" in command.upper() or "\\AppData\\" in command.upper():
                        suspicion_score += 30

                    if "powershell" in command.lower() or "cmd /c" in command.lower():
                        suspicion_score += 20

                    # Check if program exists (missing = cleaned or disabled)
                    program_path = self._extract_executable_path(command)

                    if program_path and not Path(program_path).exists():
                        suspicion_score += 10

                    # Step 4: Adjust priority based on suspicion
                    priority = "HIGH" if suspicion_score > 40 else "MEDIUM"

                    # Step 5: Create Event
                    event = Event(
                        timestamp= key_timestamp,
                        source_device= self.computer_name,
                        source_type= "REGISTRY",
                        event_type= "startup_program_configured",
                        user= "SYSTEM",
                        payload= {
                            "program_name": program_name,
                            "command": command,
                            "key_type": key_type,
                            "suspicious_score": suspicion_score,
                            "registry_path": key_path,
                            "hive_source": self.software_hive_path,
                        },
                        timezone_offset = self.system_timezone,
                        local_timestamp = self._calculate_local_timestamp(key_timestamp, self.system_timezone),
                        forensic_priority = priority,       # Dynamic based on suspicion!
                        confidence_score = 0.92,
                        corruption_detected = False
                    )
                    events.append(event)
                    self.events_count += 1
                
                return events

        except Exception as e:
            logger.warning(f"Error extracting startup programs: {e}")
            return []
    
    def _extract_services(self, software_hive, system_hive) -> List[Event]:
        r"""
        Extract Windows services and drivers configuration.
        
        Path: SYSTEM\CurrentControlSet\Services
        
        Structure:
        Services/
        ├── Acme  (Service/Driver name)
        │   ├── DisplayName = "Acme Inc. Service"
        │   ├── Description = "Provides functionality for Acme"
        │   ├── ImagePath = "C:\Program Files\Acme\acme.exe"  or "System32\drivers\acme.sys"
        │   ├── Start = 2  (0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled)
        │   ├── Type = 16  (1=kernel driver, 16=file system driver, 32=service)
        │   ├── ServiceDll = "C:\Program Files\Acme\service.dll"
        │   └── (Last write time = when service was installed/modified)
        │
        ├── WinDefend  (Windows Defender)
        │   ├── DisplayName = "Windows Defender Service"
        │   ├── Start = 2  (Auto-start)
        │   └── ...
        │
        ├── MalwareService  ← SUSPICIOUS!
        │   ├── DisplayName = "MalwareService"
        │   ├── ImagePath = "C:\Windows\Temp\malware.exe"
        │   ├── Start = 2  (Auto-start)
        │   └── ...
        └── ...
        
        Key forensic indicators:
        - Services with Start=0 or Start=1 (kernel-level persistence)
        - Services in temp folders (suspicious)
        - Services with non-existent ImagePath (cleaned/disabled)
        - Services installed recently
        - Hidden services (DisplayName missing)
        """
        
        events = []

        if system_hive is None:
            logger.debug("SYSTEM hive not provided for services extraction")
            return events
        
        # Services are in SYSTEM hive, not SOFTWARE
        services_key = None
        for cs_num in ['001', '002', '003']:
            services_key = self._get_registry_key(
                system_hive,
                f"ControlSet{cs_num}\\Services"
            )
            if services_key is not None:
                break
        
        if services_key is None:
            logger.debug("Services key not found")
            return events
        
        # Iterate through service subkeys
        try:
            for service_subkey in services_key.subkeys():
                
                # Extract service details
                display_name = self._get_value(service_subkey, "DisplayName")
                image_path = self._get_value(service_subkey, "ImagePath")
                start_type = self._get_value(service_subkey, "Start")
                service_type = self._get_value(service_subkey, "Type")
                
                # Skip if no display name (many driver/system services don't have one)
                if not display_name:
                    continue
                
                # Calculating suspcious_score
                suspicious_score = 0
                
                if image_path:
                    # Check for execution from temp folders or AppData
                    if "\\TEMP\\" in image_path.upper() or "\\APPDATA\\" in image_path.upper():
                        suspicious_score += 30
                    
                    # Check for script execution hosts often abused by malware
                    if "powershell" in image_path.lower() or "cmd.exe" in image_path.lower():
                        suspicious_score += 20

                # Get service key timestamp
                service_timestamp = service_subkey.timestamp()
                
                # Create Event with all required fields
                event = Event(
                    timestamp=service_timestamp,
                    source_device=self.computer_name,
                    source_type="REGISTRY",
                    event_type="service_configured",
                    user="SYSTEM",
                    payload={
                        "service_name": service_subkey.name(),
                        "display_name": display_name,
                        "image_path": image_path,
                        "suspicious_score": suspicious_score,
                        "start_type": self._convert_start_type(start_type),
                        "service_type": self._convert_service_type(service_type),
                        "registry_path": self.SERVICES_PATH,
                        "hive_source": self.system_hive_path,
                    },
                    timezone_offset=self.system_timezone,
                    local_timestamp=self._calculate_local_timestamp(service_timestamp, self.system_timezone),
                    forensic_priority="MEDIUM",
                    confidence_score=0.85,
                    corruption_detected=False
                )
                events.append(event)
                self.events_count += 1
        
        except Exception as e:
            logger.warning(f"Error extracting services: {e}")
            self.corruption_log.append({
                "error": str(e),
                "stage": "services_extraction"
            })
        
        return events
  
    def _extract_browser_helper_objects(self, software_hive) -> List[Event]:
        r"""
        Extract Browser Helper Objects (BHOs) from SOFTWARE hive.
        
        BHOs are COM objects that load into Internet Explorer/Edge
        They can modify search results, inject ads, steal credentials, etc.
        
        Path: Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
        
        Structure:
        Browser Helper Objects/
        ├── {GUID-1234-5678-90AB}  (CLSID)
        │   (No values, just the key itself indicates BHO is registered)
        │
        ├── {92EF2EAD-A7CE-4424-B922-BF4402E5E436}  (Real BHO example)
        │   └── (Registered = BHO is active)
        │
        └── {MALWARE-GUID-12345}  ← MALICIOUS BHO
            └── (Points to DLL in AppData)
        
        To find the actual DLL:
        Look in: HKEY_CLASSES_ROOT\CLSID\{GUID}\InprocServer32
        └── (Default) = "C:\Path\To\malware.dll"
        
        Common malicious BHOs:
        - Toolbars (search hijacking)
        - Ad injectors
        - Credential stealers
        - Tracking/spyware
        """
        
        events = []
        
        try:
            # Step 1: Navigate to BHO key
            bho_key = self._get_registry_key(software_hive, self.BHO_PATH)
            
            if bho_key is None:
                logger.debug("BHO key not found")
                return []
            
            # Step 2: Get all registered CLASSIDs
            bho_guids = []
            for subkey in bho_key.subkeys():
                bho_guid = subkey.name()
                
                # CLSID format: {12345678-1234-1234-1234-123456789012}
                if bho_guid.startswith("{") and bho_guid.endswith("}"):
                    bho_guids.append(bho_guid)
            
            # Step 3: For each BHO CLSID, find the actual DLL
            for bho_guid in bho_guids:
                
                # Navigate to CLSID definition
                # HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32
                clsid_path = f"CLASSES\\CLSID\\{bho_guid}\\InprocServer32"
                
                try:
                    clsid_key = self._get_registry_key(software_hive, clsid_path)
                    
                    if clsid_key is None:
                        continue
                    
                    # Step 4: Extract DLL path and metadata
                    dll_path = self._get_value(clsid_key, None)  # Default value = DLL path
                    
                    if not dll_path:
                        continue
                    
                    # Step 5: Get BHO name from CLSID
                    bho_name_path = f"CLASSES\\CLSID\\{bho_guid}"
                    bho_name_key = self._get_registry_key(software_hive, bho_name_path)
                    bho_name = self._get_value(bho_name_key, None) if bho_name_key else bho_guid
                    
                    # Step 6: Calculate suspicion score
                    suspicion_score = 0
                    
                    # DLL in AppData/Temp = VERY suspicious
                    if "\\AppData\\" in dll_path.upper() or "\\Temp\\" in dll_path.upper():
                        suspicion_score += 50
                    
                    # DLL doesn't exist = cleaned malware
                    if not Path(dll_path).exists():
                        suspicion_score += 30
                    
                    # DLL is unsigned
                    if not self._is_dll_signed(dll_path):
                        suspicion_score += 25
                    
                    # Known malicious BHO name patterns
                    if any(pattern in bho_name.lower() for pattern in ["toolbar", "search", "web", "deals", "coupon"]):
                        suspicion_score += 20
                    
                    # Step 7: Determine priority
                    priority = "HIGH" if suspicion_score > 60 else "MEDIUM"
                    
                    # Step 8: Get timestamp from CLSID key
                    timestamp = clsid_key.timestamp() if clsid_key else datetime.now(timezone.utc)
                    
                    # Step 9: Create Event
                    event = Event(
                        timestamp=timestamp,
                        source_device=self.computer_name,
                        source_type="REGISTRY",
                        event_type="browser_helper_object_installed",
                        user="SYSTEM",
                        payload={
                            "bho_name": bho_name,
                            "bho_clsid": bho_guid,
                            "dll_path": dll_path,
                            "suspicious_score": suspicion_score,
                            "dll_exists": Path(dll_path).exists(),
                            "dll_signed": self._is_dll_signed(dll_path),
                            "registry_path": self.BHO_PATH,
                            "hive_source": self.software_hive_path,
                        },
                        timezone_offset=self.system_timezone,
                        local_timestamp=self._calculate_local_timestamp(timestamp, self.system_timezone),
                        forensic_priority=priority,  # HIGH for suspicious BHOs
                        confidence_score=0.88,
                        corruption_detected=False
                    )
                    
                    events.append(event)
                
                except Exception as e:
                    logger.warning(f"Error processing BHO {bho_guid}: {e}")
                    continue
            
            return events
        
        except Exception as e:
            logger.warning(f"Error extracting BHOs: {e}")
            self.corruption_log.append({
                "error": str(e),
                "stage": "bho_extraction"
            })
            return []
        
    def _extract_lsa_secrets(self, security_hive) -> List[Event]:
        r"""
        Extract LSA (Local Security Authority) secrets from SECURITY hive.
        
        Path: SECURITY\Policy\Secrets
        
        Structure:
        Secrets/
        ├── ASPNET_WP_PASSWORD  (IIS application pool password)
        ├── L$_RTONE  (RAS dial-up credentials)
        ├── NL$KM  (Network logon key material)
        ├── DefaultPassword  (Cached default user password)
        ├── DPAPI_SYSTEM  (Data Protection API master key)
        └── ...
        
        Note: Requires SYSTEM privileges to read and decrypt
        These secrets are encrypted, but their presence is forensically significant
        
        Examples of secrets found:
        - Cached domain credentials
        - Service account passwords
        - VPN passwords
        - SQL Server passwords
        """
        
        events = []
        
        try:
            # Step 1: Navigate to LSA Secrets
            lsa_secrets_key = self._get_registry_key(security_hive, r"Policy\Secrets")

            if lsa_secrets_key is None:
                logger.debug("LSA Secrets key not found (may require SYSTEM privileges)")
                return []
            
            # Step 2: Iterate through secret subkeys
            for secret_subkey in lsa_secrets_key.subkeys():
                secret_name = secret_subkey.name()
                secret_timestamp = secret_subkey.timestamp()

                # Step 3: Categorize secret by name
                secret_type = self._categorize_secret(secret_name)
                
                # Step 4: Try to decrypt (requires SYSTEM privileges)
                secret_value = self._decrypt_lsa_secret(secret_subkey)

                # Step 5: Check for presence of specific secrets
                current_value = self._get_value(secret_subkey, "CurrentValue")
                old_value = self._get_value(secret_subkey, "OldValue")

                # Step 6: Create Event
                event = Event(
                    timestamp= secret_timestamp,
                    source_device= self.computer_name,
                    source_type= "REGISTRY",
                    event_type= "lsa_secret_found",
                    user= "SYSTEM",
                    payload= {
                        "secret_name": secret_name,
                        "secret_type": secret_type,
                        "secret_decrypted": secret_value is not None,
                        "current_value_exists": current_value is not None,
                        "old_value_exists": old_value is not None,
                        "registry_path": self.LSA_SECRETS_PATH,
                        "hive_source": self.security_hive_path
                    },
                    timezone_offset= self.system_timezone,
                    local_timestamp= self._calculate_local_timestamp(secret_timestamp, self.system_timezone),
                    forensic_priority= "HIGH",  # Credentials = HIGH priority!
                    confidence_score= 0.98,     # Registry is authoritative source
                    corruption_detected= False
                )

                events.append(event)
                self.events_count += 1
            
            return events

        except Exception as e:
            logger.warning(f"Error extracting LSA secrets (may require SYSTEM privileges): {e}")
            return []
        
    # PRIORITY 3
    def _extract_advanced_artifacts(self, usrclass_hive, components_hive, username: str) -> List[Event]:

        events = []

        events.extend(
            self._extract_shell_extensions(
                usrclass_hive,
                username
            )
        )

        events.extend(
            self._extract_file_associations(
                usrclass_hive,
                username
            )
        )

        events.extend(
            self._extract_windows_updates(
                components_hive
            )
        )

        return events

    def _extract_shell_extensions(self, usrclass_hive, username: str) -> List[Event]:
        """
        Extract approved shell extensions from USRCLASS.DAT.

        Useful for:
        - Persistence detection
        - Explorer hijacking
        - Malware shell extensions
        """

        events = []

        try:
            shell_key = self._get_registry_key(
                usrclass_hive,
                self.SHELL_EXT_PATH
            )

            if shell_key is None:
                return events

            for value in shell_key.values():

                extension_guid = value.name()
                extension_name = value.value()

                timestamp = shell_key.timestamp()

                suspicious_score = 0

                if extension_name:
                    lower_name = str(extension_name).lower()

                    if any(x in lower_name for x in [
                        "toolbar",
                        "coupon",
                        "search",
                        "inject",
                        "adware"
                    ]):
                        suspicious_score += 30

                event = Event(
                    timestamp=timestamp,
                    source_device=self.computer_name,
                    source_type="REGISTRY",
                    event_type="shell_extension_registered",
                    user=username,
                    payload={
                        "extension_guid": extension_guid,
                        "extension_name": extension_name,
                        "suspicious_score": suspicious_score,
                        "registry_path": self.SHELL_EXT_PATH,
                        "hive_source": "USRCLASS.DAT"
                    },
                    timezone_offset=self.system_timezone,
                    local_timestamp=self._calculate_local_timestamp(
                        timestamp,
                        self.system_timezone
                    ),
                    forensic_priority="MEDIUM",
                    confidence_score=0.85,
                    corruption_detected=False
                )

                events.append(event)
                self.events_count += 1

            return events

        except Exception as e:
            logger.warning(f"Shell extension extraction failed: {e}")
            return []
        
    def _extract_file_associations(self, usrclass_hive, username: str) -> List[Event]:
        """
        Extract user file association changes.

        Valuable because malware often hijacks:
        .pdf
        .docx
        .html
        .exe
        """

        events = []

        try:
            fileexts_key = self._get_registry_key(
                usrclass_hive,
                self.FILE_EXTS_PATH
            )

            if fileexts_key is None:
                return events

            for extension_key in fileexts_key.subkeys():

                extension = extension_key.name()
                timestamp = extension_key.timestamp()

                user_choice = None

                try:
                    user_choice_key = extension_key.subkey("UserChoice")
                    user_choice = self._get_value(user_choice_key, "ProgId")
                except:
                    pass

                event = Event(
                    timestamp=timestamp,
                    source_device=self.computer_name,
                    source_type="REGISTRY",
                    event_type="file_association_modified",
                    user=username,
                    payload={
                        "extension": extension,
                        "associated_program": user_choice,
                        "registry_path": self.FILE_EXTS_PATH,
                        "hive_source": "USRCLASS.DAT"
                    },
                    timezone_offset=self.system_timezone,
                    local_timestamp=self._calculate_local_timestamp(
                        timestamp,
                        self.system_timezone
                    ),
                    forensic_priority="MEDIUM",
                    confidence_score=0.90,
                    corruption_detected=False
                )

                events.append(event)
                self.events_count += 1

            return events

        except Exception as e:
            logger.warning(f"File association extraction failed: {e}")
            return []
        
    def _extract_windows_updates(self, components_hive) -> List[Event]:
        """
        Extract Windows servicing information from COMPONENTS hive.

        Useful for:
        - Patch timeline
        - Update reconstruction
        - .NET installation history
        """

        events = []

        try:

            root = components_hive.root()

            for subkey in root.subkeys():

                name = subkey.name()

                if not (
                    "Package" in name or
                    "Microsoft-Windows" in name or
                    ".NET" in name
                ):
                    continue

                timestamp = subkey.timestamp()

                event = Event(
                    timestamp=timestamp,
                    source_device=self.computer_name,
                    source_type="REGISTRY",
                    event_type="windows_component_registered",
                    user="SYSTEM",
                    payload={
                        "component_name": name,
                        "registry_path": subkey.path(),
                        "hive_source": self.components_hive_path
                    },
                    timezone_offset=self.system_timezone,
                    local_timestamp=self._calculate_local_timestamp(
                        timestamp,
                        self.system_timezone
                    ),
                    forensic_priority="LOW",
                    confidence_score=0.95,
                    corruption_detected=False
                )

                events.append(event)
                self.events_count += 1

            return events

        except Exception as e:
            logger.warning(f"Windows update extraction failed: {e}")
            return []
    
    # GENERAL HELPERS
    def _load_hive(self, hive_path: str):
        r"""
        Load a Windows registry hive file.
        
        Args:
            hive_path: Full path to hive file (e.g., "C:\Windows\System32\config\SYSTEM")
        
        Returns:
            Registry.RegistryHive object if successful, None if error
        
        Error handling:
            - File not found
            - File locked (in use)
            - Invalid hive format
            - Permission denied
        """
        try:
            # Step 1: Validate that file exists
            hive_file_path = Path(hive_path)
            if not hive_file_path.is_file():
                logger.error(f"Hive file not found: {hive_path}")
                self.corruption_log.append({
                    "error": f"Hive file not found",
                    "stage": "hive_load",
                    "hive_path": hive_path
                })
                return None
            
            # Step 2: Check file size (sanity check - registry hives are usually > 4KB)
            file_size = hive_file_path.stat().st_size
            if file_size < 4096:    # 4Kb minimum
                logger.warning(f"Hive file suspiciously small: {hive_path} ({file_size} bytes)")
                self.corruption_log.append({
                    "error": f"Hive file too small: {file_size} bytes",
                    "stage": "hive_load",
                    "hive_path": hive_path
                })

            # Step 3: Open file for binary reading
            try:
                hive_file_handle = open(hive_path, 'rb')
            except FileNotFoundError as e:
                logger.error(f"Cannot open hive file (not found): {hive_path}")
                return None
            except PermissionError as e:
                logger.error(f"Permission denied reading hive: {hive_path}")
                logger.info("Tip: Run as Administrator or copy hive to temp location")
                self.corruption_log.append({
                    "error": f"Permission denied: {str(e)}",
                    "stage": "hive_load",
                    "hive_path": hive_path
                })
                return None
            except IOError as e:
                logger.error(f"I/O error reading hive: {hive_path} - {str(e)}")
                logger.info("File may be locked. Close it or use shadow copy.")
                return None
            
            # Step 4: Validate hive signature (registry hives start with "regf")
            first_bytes = hive_file_handle.read(4)
            hive_file_handle.seek(0)

            if first_bytes != b'regf':
                logger.error(f"Invalid hive signature: {hive_path}")
                logger.debug(f"Expected: b'regf', got: {first_bytes}")
                self.corruption_log.append({
                    "error": f"Invalid hive signature: {first_bytes}",
                    "stage": "hive_load",
                    "hive_path": hive_path
                })
                hive_file_handle.close()
                return None
            
            # Step 5: Load hive using python-registry
            try:
                hive = Registry.Registry(hive_file_handle)
                logger.info(f"Successfully loaded hive: {hive_path}")
                hive_file_handle.close()
                return hive
            
            except Exception as e:
                logger.error(f"Unexpected error loading hive {hive_path}: {str(e)}")
                self.corruption_log.append({
                    "error": f"Unexpected error: {str(e)}",
                    "stage": "hive_load",
                    "hive_path": hive_path
                })
                hive_file_handle.close()
                return None

        except Exception as e:
            logger.error(f"Fatal error in load_hive: {str(e)}")
            return None
    
    def _get_registry_key(self, hive, key_path: str):
        r"""
        Navigate registry hive and return key object.
        
        Args:
            hive: Registry.RegistryHive object (from load_hive)
            key_path: Registry key path
                    Examples:
                    - "SAM\Domains\Account\Users"
                    - "SYSTEM\CurrentControlSet\Enum\USB"
                    - "Software\Microsoft\Windows\CurrentVersion\Run"
        
        Returns:
            Registry.RegistryKey object if found, None if not found
        
        Example usage:
            users_key = get_registry_key(hive, "SAM\Domains\Account\Users")
            FOR each subkey IN users_key.subkeys():
                print(subkey.name())
        """
        try:
            # Step 1: Get root key of hive
            current_key = hive.root()

            if current_key is None:
                logger.error(f"Cannot get root key from hive {hive}")
                return None
            
            # Step 2: Split path by backslash
            path_parts = key_path.split("\\")
            logger.debug(f"Navigating to: {key_path} (parts: {path_parts})")

            # Step 3: Iterate through each part and navigate deeper
            for i, part in enumerate(path_parts):

                # Skip empty parts
                if part == "":
                    continue
                logger.debug(f"  Step {i}: Navigating to subkey '{part}'")

                try:
                    # Attempting to get subkey
                    current_key  = current_key.subkey(part)

                    if current_key is None:
                        logger.warning(f"Registry key not found: {key_path}")
                        logger.debug(f"  Failed at part: {part}")
                        return None

                except Exception as e:
                    logger.error(f"Error navigating to key '{part}' in {key_path}: {str(e)}")
                    return None
                
            # Step 4: Return the final key (MOVED OUTSIDE OF FOR LOOP)
            logger.debug(f"Successfully navigated to: {key_path}")
            return current_key

        except Exception as e:
            logger.error(f"Fatal error in get_registry_key({key_path}): {str(e)}")
            return None
    
    def _get_value(self, key, value_name: str):
        """
        Extract a single registry value from a registry key.
        
        Args:
            key: Registry.RegistryKey object
            value_name: Name of the value to extract
                        Examples: "FriendlyName", "LastWriteTime", "V", "F"
        
        Returns:
            Value data (could be string, int, bytes, list, etc.)
            Returns None if value not found
        
        Example usage:
            computer_name = get_value(subkey, "ComputerName")
            IF computer_name is not None:
                print(f"Device: {computer_name}")
            ELSE:
                print("ComputerName not found")
        """
        try:
            # Step 1: Validate input
            if key is None:
                logger.debug("get_value: Key is None")
                return None
            
            if value_name is None:
                logger.debug("get_value: value_name is empty")
                return None
            
            # Step 2: Iterate through all the values in the key
            for value in key.values():

                # Step 3: Check if this is the value we are searching for
                if value.name() == value_name:
                    try:
                        # Step 4: Extract and return the value data
                        value_data = value.value()
                        logger.debug(f"Found value '{value_name}': type={type(value_data).__name__}")
                        return value_data

                    except Exception as e:
                        logger.error(f"Error extracting value '{value_name}': {str(e)}")
                        return None
            
            # Step 5: Value isn't found if the following code is being executed
            logger.debug(f"Registry value not found: {value_name}")
            return None

        except Exception as e:
            logger.error(f"Fatal error in get_value('{value_name}'): {str(e)}")
            return None
    
    def _calculate_forensic_priority(self, event_type: str) -> str:
        """Assign priority based on event type"""
        pass
    
    def _get_chain_of_custody_metadata(self, hive_path: str) -> Dict:
        r"""
        Calculate hash and metadata of registry hive for chain of custody.
        
        Chain of Custody = Prove that evidence hasn't been tampered with
        
        Returns:
            {
                "hive_path": "C:\Windows\System32\config\SYSTEM",
                "hive_name": "SYSTEM",
                "sha256": "a1b2c3d4e5f6...",
                "md5": "f1e2d3c4b5a6...",  (for legacy compatibility)
                "file_size": 524288,
                "parse_timestamp": "2024-06-08T15:30:45.123456Z",
                "parse_duration_seconds": 0.523,
                "parser_version": "1.0.0"
            }
        
        Usage:
            FOR each hive extracted:
                metadata = self.get_chain_of_custody_metadata(hive_path)
                event.payload["chain_of_custody"] = metadata
        
        Legal Context:
            When expert testifies in court:
            "Your Honor, I parsed the SYSTEM registry hive. Here is the
            SHA256 hash: a1b2c3d4e5f6... This hash proves the evidence
            hasn't been modified since collection."
        """
        
        try:
            # Step 1: Validate file exists
            file_path = Path(hive_path)
            
            if not file_path.is_file():
                logger.warning(f"Cannot calculate hash - file not found: {hive_path}")
                return {
                    "hive_path": hive_path,
                    "error": "File not found",
                    "sha256": None,
                    "md5": None
                }
            
            # Step 2: Get file metadata
            file_stats = file_path.stat()
            file_size = file_stats.st_size
            file_modified_time = file_stats.st_mtime  # Last modification time
            
            logger.info(f"Calculating hash of {hive_path} ({file_size} bytes)")
            
            # Step 3: Calculate SHA256 hash (read file in chunks for efficiency)
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            CHUNK_SIZE = 8192  # Read 8KB at a time
            
            try:
                with open(hive_path, 'rb') as hive_file:
                    
                    while True:
                        chunk = hive_file.read(CHUNK_SIZE)
                        
                        if not chunk:
                            break  # End of file
                        
                        sha256_hash.update(chunk)
                        md5_hash.update(chunk)
                
                sha256_digest = sha256_hash.hexdigest()  # Convert to hex string
                md5_digest = md5_hash.hexdigest()
                
                logger.info(f"SHA256: {sha256_digest}")
                logger.info(f"MD5: {md5_digest}")
            
            except Exception as e:
                logger.error(f"Error calculating hash: {str(e)}")
                return {
                    "hive_path": hive_path,
                    "error": f"Hash calculation failed: {str(e)}",
                    "sha256": None,
                    "md5": None
                }
            
            # Step 4: Extract hive name from path
            # Input: "C:\Windows\System32\config\SYSTEM"
            # Output: "SYSTEM"
            hive_name = file_path.stem  # filename without extension
            
            # Special handling for NTUSER.DAT (keep full name)
            if file_path.name.lower() == "ntuser.dat":
                hive_name = "NTUSER.DAT"
            elif file_path.name.lower() == "usrclass.dat":
                hive_name = "USRCLasS.DAT"
            
            # Step 5: Build metadata dictionary
            metadata = {
                "hive_path": str(hive_path),
                "hive_name": hive_name,
                "file_size": file_size,
                "sha256": sha256_digest,
                "md5": md5_digest,
                "file_modified_time": datetime.fromtimestamp(file_modified_time, tz=timezone.utc),
                "parse_timestamp": datetime.now(timezone.utc),
                "parser_version": "1.0.0",
                "parser_name": "EvidenceSync Pro Registry Parser"
            }
            
            logger.debug(f"Chain of custody metadata: {metadata}")
            
            return metadata
        
        except Exception as e:
            logger.error(f"Fatal error in get_chain_of_custody_metadata: {str(e)}")
            
            return {
                "hive_path": hive_path,
                "error": f"Fatal error: {str(e)}",
                "sha256": None,
                "md5": None
            }
        
    def _calculate_local_timestamp(self, utc_dt: datetime, offset_str: str) -> datetime:
        """
        Calculate local timestamp from UTC based on string offset format.
        
        (Same implementation from evtx_parser.py)
        """
        if not utc_dt:
            return utc_dt
            
        try:
            clean_offset = offset_str.upper().replace("UTC", "").strip()
            if not clean_offset or clean_offset == "+0" or clean_offset == "-0":
                return utc_dt

            sign = -1 if clean_offset.startswith("-") else 1
            clean_offset = clean_offset.lstrip("+-")

            if ":" in clean_offset:
                hours_part, minutes_part = clean_offset.split(":", 1)
                hours = int(hours_part)
                minutes = int(minutes_part)
            else:
                hours = int(clean_offset)
                minutes = 0

            delta = timedelta(hours=hours, minutes=minutes)
            if sign == -1:
                return utc_dt - delta
            else:
                return utc_dt + delta

        except Exception:
            return utc_dt
        
    # SAM HELPERS functions
    def _filetime_to_datetime(self, filetime_int: int) -> Optional[datetime]:
        """
        Convert Windows FILETIME to Python datetime.
        
        FILETIME = 100-nanosecond intervals since 1601-01-01 00:00:00 UTC
        If filetime_int = 0, it means "never" (no event occurred)
        """
        if filetime_int <= 0:
            return None     # Never happened
        
        try:
            # Windows epoch starts at 1601-01-01
            # Python epoch starts at 1970-01-01
            # Difference: 116444736000000000 in 100-nanosecond units
            WINDOWS_EPOCH_DIFF = 116444736000000000
            
            # Convert 100-nanosecond units to microseconds
            unix_timestamp = (filetime_int - WINDOWS_EPOCH_DIFF) / 10_000_000
            dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
            return dt

        except Exception as e:
            logger.warning(f"FILETIME conversion failed: {e}")
            return None

    def _parse_sam_v_field(self, v_data: bytes) -> Dict[str, Any]:
        """
        Parse the SAM V field binary structure.
        
        The V field contains account metadata in binary format.
        Each field is at a specific byte offset.
        
        Returns dict with extracted fields:
        - last_login_time: datetime or None
        - last_password_set_time: datetime or None
        - failed_login_count: int
        - login_count: int
        - account_disabled: bool
        - account_locked: bool
        """
    
        parsed = {
            "last_login_time": None,
            "last_password_set_time": None,
            "failed_login_count": 0,
            "login_count": 0,
            "account_disabled": False,
            "account_locked": False,
        }

        # Ensure we have enough bytes
        try:
            if len(v_data) < 0x60:
                return parsed
            
            # Offset 0x30 (48): Last login time (FILETIME, 8 bytes)
            last_login_filetime = struct.unpack("<Q", v_data[0x30:0x30+8])[0]
            parsed["last_login_time"] = self._filetime_to_datetime(last_login_filetime)

            # Offset 0x40 (64): Last password set time (FILETIME, 8 bytes)
            last_password_filetime = struct.unpack("<Q", v_data[0x40:0x40+8])[0]
            parsed["last_password_set_time"] = self._filetime_to_datetime(last_password_filetime)

            # Offset 0x58 (88): Failed login count (DWORD, 4 bytes)
            failed_logins = struct.unpack("<I", v_data[0x58:0x58+4])[0]
            parsed["failed_login_count"] = failed_logins

            # Offset 0x5C (92): Login count (DWORD, 4 bytes)
            login_count = struct.unpack("<I", v_data[0x5C:0x5C+4])[0]
            parsed["login_count"] = login_count

            # Offset 0x38 (56): ACB flags (WORD / 2 bytes)
            acb_flags = struct.unpack("<H", v_data[0x38:0x38+2])[0]
            
            # Bitmask 0x0001: USER_ACCOUNT_DISABLED
            parsed["account_disabled"] = bool(acb_flags & 0x0001)
            
            # Bitmask 0x0010: USER_ACCOUNT_LOCKED
            parsed["account_locked"] = bool(acb_flags & 0x0010)

            return parsed

        except Exception as e:
            logger.warning(f"Error parsing SAM V field: {e}")
            return parsed

    def _extract_rid_from_value(self, registry_value) -> Optional[int]:
        """
        Extracts the Relative Identifier (RID) from a SAM Names subkey value.
        
        In the SAM Names structure (e.g., SAM\\Domains\\Account\\Users\\Names\\Administrator),
        the RID is typically stored within the 'Value Type' (Data Type DWORD) of the 
        registry value object rather than the raw data payload itself.
        
        Args:
            registry_value: A Registry.RegistryValue object, or raw bytes as a fallback.
            
        Returns:
            int: The decimal RID if found, or None if extraction fails.
        """
        if registry_value is None:
            return None

        try:
            # Approach 1: Check if it's a python-registry Value object (Standard Use Case)
            # python-registry exposes the registry data type via value_type()
            if hasattr(registry_value, 'value_type'):
                rid = registry_value.value_type()
                logger.debug(f"Extracted RID {rid} from registry value type header.")
                return int(rid)

            # Approach 2: Fallback if raw bytes were passed instead of the Value object
            # Some automated extraction tools dump the raw value descriptor block.
            # The RID is often at the very beginning or offset 0x04 depending on the buffer dump.
            if isinstance(registry_value, (bytes, bytearray)):
                if len(registry_value) >= 4:
                    # Unpack a 32-bit unsigned little-endian integer
                    rid = struct.unpack("<I", registry_value[:4])[0]
                    logger.debug(f"Extracted RID {rid} from raw binary fallback path.")
                    return int(rid)
                
            logger.warning("Provided registry value format unrecognized for RID extraction.")
            return None

        except Exception as e:
            logger.error(f"Failed to extract RID from value: {str(e)}")
            self.corruption_log.append({
                "error": f"RID extraction failure: {str(e)}",
                "stage": "extract_rid_from_value",
                "value_type": type(registry_value).__name__
            })
            return None

    def _is_numeric_rid(self, name:str) -> bool:
        """
        Check if a string is a valid hexadecimal RID.
        
        RIDs are stored as hex strings in SAM hive subkeys:
        - "000001F4" = 500 (Administrator)
        - "000001F5" = 501 (Guest)
        - "000003E8" = 1000 (First local user)
        - "000003E9" = 1001 (Second local user)
        
        Non-RID keys to skip:
        - "Names" (contains username mappings)
        - "Domains" (parent key)
        - "Account" (parent key)
        
        Args:
            name: String name of registry subkey
        
        Returns:
            True if name is a valid hex RID, False otherwise
        
        Example usage:
            FOR subkey IN users_key.subkeys():
                IF self.is_numeric_rid(subkey.name()):
                    // This is a RID subkey - process it
                    rid = int(subkey.name(), 16)
                ELSE:
                    // This is "Names" or other non-RID key - skip
                    CONTINUE
        """
        try:
            # Step 1: Validate input
            if name is None or name == "":
                return False
            
            # Step 2: Check length
            if len(name) > 8:
                logger.debug(f"RID string too long: {name}")
                return False
            
            # Step 3: Try to parse as hexadecimal
            rid_decimal = int(name, 16)

            # Step 4: Validate RID range
            if rid_decimal < 0 or rid_decimal > 2147483647:
                logger.debug(f"RID out of valid range: {rid_decimal}")
                return False
            
            logger.debug(f"Valid RID found: {name} = {rid_decimal}")
            return True
        
        except ValueError:
            logger.debug(f"Not a valid hex string: {name}")
            return False

        except Exception as e:
            logger.error(f"Error in is_numeric_rid('{name}'): {str(e)}")
            return False

    # NTUSER.DAT HELPERS functions
    def _extract_search_history(self, ntuser_hive, username: str) -> List[Event]:
        r"""
        Extract search queries from RunMRU registry key.
        
        Path: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        
        Structure:
        RunMRU/
        ├── a = "calc.exe"           (most recent)
        ├── b = "notepad.exe"
        ├── c = "msiexec /i"
        ├── d = "powershell -NoProfile"
        └── MRUList = "abcd"         (order of recency)
        
        Each value name is a letter (a, b, c, ...)
        MRUList contains the ordering (most recent first)
        """
        
        events = []
        
        try:
            # Step 1: Navigate to RunMRU key
            runmru_key = self._get_registry_key(ntuser_hive, self.RUN_MRU_PATH)
            
            if runmru_key is None:
                logger.debug(f"RunMRU key not found for user {username}")
                return []
            
            # Step 2: Get MRUList to understand order
            mru_list_value = self._get_value(runmru_key, "MRUList")
            
            if mru_list_value is None:
                mru_list = ""
            else:
                mru_list = mru_list_value  # String like "abcd"
            
            # Step 3: Iterate through all values in key
            for value in runmru_key.values():
                value_name = value.name()
                search_query = value.value()  # The actual search/command
                
                # Skip MRUList itself
                if value_name == "MRUList":
                    continue
                
                # Skip empty values
                if not search_query or search_query == "":
                    continue
                
                # Step 4: Determine position in MRU (recency)
                position = mru_list.find(value_name)  # index in MRUList
                if position == -1:
                    position = 999  # Not in list

                metadata = self._get_chain_of_custody_metadata(self.ntuser_dat_path)
                
                # Step 5: Create Event
                event = Event(
                    timestamp = runmru_key.timestamp(),
                    source_device = self.computer_name,
                    source_type = "REGISTRY",
                    event_type = "user_search_query",
                    user = username,  # ← Different from SAM (per-user!)
                    payload = {
                        "search_query": search_query,
                        "mru_position": position,
                        "registry_path": self.RUN_MRU_PATH,
                        "hive_source": self.ntuser_dat_path,
                        "hive_hash_sha256": metadata["sha256"]
                    },
                    timezone_offset = self.system_timezone,
                    local_timestamp = self._calculate_local_timestamp(runmru_key.timestamp(), self.system_timezone),
                    forensic_priority = "HIGH",  # User intent!
                    confidence_score = 0.90,
                    corruption_detected = False
                )
                
                events.append(event)
                self.events_count += 1
            
            return events
            
        except Exception as e:
            logger.warning(f"Error extracting search history for {username}: {e}")
            self.corruption_log.append({
                "error": str(e),
                "stage": "search_history_extraction",
                "username": username
            })
            return []

    def _extract_typed_paths(self, ntuser_hive, username: str) -> List[Event]:
        r"""
        Extract typed URLs and file paths from TypedPaths registry key.
        
        Path: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
        
        Structure:
        TypedPaths/
        ├── url1 = "C:\Users\john\Documents"
        ├── url2 = "\\192.168.1.100\SecretShare"
        ├── url3 = "https://example.com"
        └── url4 = "ftp://files.server.com"
        
        Contains both local paths and network UNC paths
        """

        events = []
        try:
            # Step 1: Navigate to TypedPaths key
            typed_paths_key = self._get_registry_key(ntuser_hive, self.TYPED_PATHS_PATH)

            if typed_paths_key is None:
                logger.debug(f"TypedPaths key not found for user {username}")
                return []
            
            # Step 2: Iterate through all values
            for value in typed_paths_key.values():
                path_or_url = value.value()

                # Skip empty values
                if not path_or_url or path_or_url == "":
                    continue

                # Step 3: Extract IP if this is a UNC path (\\192.168.1.1\share)
                extracted_ip = self._extract_ip_from_unc(path_or_url)
                
                # Step 4: Create Event
                event = Event(
                    timestamp = typed_paths_key.timestamp(),
                    source_device = self.computer_name,
                    source_type = "REGISTRY",
                    event_type = "typed_url_or_path",
                    user = username,
                    payload = {
                        "url_or_path": path_or_url,
                        "registry_path": self.TYPED_PATHS_PATH,
                        "hive_source": self.ntuser_dat_path,
                        "is_unc_path": path_or_url.startswith("\\"),
                        "is_url": path_or_url.startswith("http") or path_or_url.startswith("ftp")
                    },
                    extracted_ips = [extracted_ip] if extracted_ip else [],
                    timezone_offset = self.system_timezone,
                    local_timestamp = self._calculate_local_timestamp(typed_paths_key.timestamp(), self.system_timezone),
                    forensic_priority = "HIGH",  # User explicitly typed this!
                    confidence_score = 0.92,
                    corruption_detected = False
                )
                events.append(event)
                self.events_count += 1

            return events

        except Exception as e:
            logger.warning(f"Error extracting typed paths for {username}: {e}")
            self.corruption_log.append({
                "error": str(e),
                "stage": "typed_paths_extraction",
                "username": username
            })
            return []

    def _extract_recent_documents(self, ntuser_hive, username: str) -> List[Event]:
        r"""
        Extract recently opened files from Recent Documents registry key.
        
        Path: Software\Microsoft\Windows\CurrentVersion\Explorer\Recent Documents
        
        Structure:
        Recent Documents/
        ├── C:\Users\john\Documents\Report.docx = "1A"
        ├── C:\Users\john\Downloads\Image.jpg = "1B"
        └── ...
        
        Contains full file paths that user recently opened
        """

        events = []
        try:
            # Step 1: Navigate to Recent Documents key
            recent_docs_key = self._get_registry_key(ntuser_hive, self.RECENT_DOCS_PATH)
            
            if recent_docs_key is None:
                logger.debug(f"Recent Documents key not found for user {username}")
                return []
            
            for subkey in recent_docs_key.subkeys():
                file_path = subkey.name()

                # Skip Invalid paths
                if not file_path or file_path == "":
                    continue

                # Step 3: Extract file name from full path
                file_name = file_path.split("\\")[-1]

                # Step 4: Create Event
                event = Event(
                    timestamp = subkey.timestamp(),
                    source_device = self.computer_name,
                    source_type = "REGISTRY",
                    event_type = "recent_document_opened",
                    user = username,
                    payload = {
                        "file_path": file_path,
                    "file_name": file_name,
                    "registry_path": self.RECENT_DOCS_PATH,
                    "hive_source": self.ntuser_dat_path
                    },
                    timezone_offset = self.system_timezone,
                    local_timestamp = self._calculate_local_timestamp(subkey.timestamp(), self.system_timezone),
                    forensic_priority = "HIGH",  # User explicitly typed this!
                    confidence_score = 0.92,
                    corruption_detected = False
                )
                events.append(event)
                self.events_count += 1

            return events

        except Exception as e:
            logger.warning(f"Error extracting recent documents for {username}: {e}")
            self.corruption_log.append({
                "error": str(e),
                "stage": "recent_documents_extraction",
                "username": username
            })
            return []

    def _extract_recent_programs(self, ntuser_hive, username: str) -> List[Event]:
        r"""
        Extract recently executed programs from TypedPaths RunMRU.
        
        Note: RunMRU contains BOTH searches AND program executions
        We already extracted searches, but can filter for programs here
        
        Path: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        
        Examples of program execution:
        - "calc.exe"
        - "notepad.exe"
        - "msiexec /i package.msi"
        - "powershell -NoProfile"
        - "cmd /c echo test"
        """
        
        events = []
        try:
            # Step 1: Navigate to RunMRU (same as search history)
            runmru_key = self._get_registry_key(ntuser_hive, self.RUN_MRU_PATH)

            if runmru_key is None:
                return []
            
            # Step 2: Get MRUList for ordering
            mru_list_value = self._get_value(runmru_key, "MRUList")
            mru_list = mru_list_value if mru_list_value else ""

            # Step 3: Iterate through values
            for value in runmru_key.values():
                value_name = value.name()
                command = value.value()

                if value_name == "MRUList" or not command:
                    continue

                # Step 4: Detect if this is a program (heuristic)
                is_program = (
                    ".exe" in command or
                    ".com" in command or
                    ".cmd" in command or
                    ".bat" in command or
                    ".vbs" in command or
                    ".ps1" in command or
                    command.startswith("msiexec") or
                    command.startswith("powershell") or
                    command.startswith("cmd /")
                )
                
                if not is_program:
                    continue        # Skip non-programs

                # Step 5: Extract executable name
                exe_name = command.split(" ")[0]
                exe_name = exe_name.split("\\")[-1]

                # Step 6: Create Event
                position = mru_list.find(value_name)
                event = Event(
                    timestamp= runmru_key.timestamp(),
                    source_device= self.computer_name,
                    source_type= "REGISTRY",
                    event_type= "program_executed",
                    user= username,
                    payload= {
                        "command": command,
                        "executable": exe_name,
                        "mru_position": position,
                        "registry_path": self.RUN_MRU_PATH,
                        "hive_source": self.ntuser_dat_path
                    },
                    timezone_offset= self.system_timezone,
                    local_timestamp= self._calculate_local_timestamp(runmru_key.timestamp(), self.system_timezone),
                    forensic_priority= "MEDIUM-HIGH",  # User ran this program
                    confidence_score= 0.87,
                    corruption_detected= False
                )
                events.append(event)
                self.events_count += 1

            return events

        except Exception as e:
            logger.warning(f"Error extracting recent programs for {username}: {e}")
            return []

    def _extract_network_shares(self, ntuser_hive, username: str) -> List[Event]:
        r"""
        Extract network shares accessed by user.
        
        Path: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        
        Structure:
        MountPoints2/
        ├── ##192.168.1.100#SecretShare (UNC path with # instead of \)
        ├── ##server#Department
        └── ...
        
        The # characters replace \ in UNC paths
        """
        
        events = []

        try:
            # Step 1: Navigate to MountPoints2 key
            mountpoints_key = self._get_registry_key(ntuser_hive, self.MOUNTPOINTS_PATH)

            if mountpoints_key is None:
                logger.debug(f"MountPoints2 key not found for user {username}")
                return []
            
            # Step 2: Iterate through subkeys (each = mounted share)
            for subkey in mountpoints_key.subkeys():
                unc_encoded = subkey.name()

                # Skip if Invalid
                if not unc_encoded.startswith("##"):
                    continue

                # Step 3: Convert encoded UNC to readable format
                unc_path = unc_encoded.replace("#", "\\")

                # Step 4: Extract IP address
                extracted_ip = self._extract_ip_from_unc(unc_path)

                # Step 5: Extract share name
                parts = unc_path.split("\\")
                share_name = parts[-1] if parts else "Unknown"

                # Step 6: Create Event
                event = Event(
                    timestamp = subkey.timestamp(),
                    source_device= self.computer_name,
                    source_type= "REGISTRY",
                    event_type= "network_share_mounted",
                    user= username,
                    payload= {
                        "unc_path": unc_path,
                        "share_name": share_name,
                        "registry_path": self.MOUNTPOINTS_PATH,
                        "hive_source": self.ntuser_dat_path,
                        "encoded_path": unc_encoded
                    },
                    extracted_ips = [extracted_ip] if extracted_ip else [],
                    timezone_offset= self.system_timezone,
                    local_timestamp= self._calculate_local_timestamp(subkey.timestamp()),
                    forensic_priority= "MEDIUM-HIGH",
                    confidence_score= 0.91,
                    corruption_detected= False
                )
                events.append(event)
                self.events_count += 1
            
            return events

        except Exception as e:
            logger.warning(f"Error extracting network shares for {username}: {e}")
            self.corruption_log.append({
                "error": str(e),
                "stage": "network_shares_extraction",
                "username": username
            })
            return []
    
    def _extract_ip_from_unc(self, unc_path: str) -> Optional[str]:
        r"""
        Extract IP address from UNC path.
        
        UNC Path Format: \\{server_or_ip}\{share_name}\{optional_path}
        
        Examples:
        ├─ "\\192.168.1.100\SecretShare" → "192.168.1.100" 
        ├─ "\\SERVER-NAME\Department" → None (hostname, not IP)
        ├─ "\\10.0.0.5\Files\Document.docx" → "10.0.0.5" 
        ├─ "C:\Users\john\Documents" → None (local path, not UNC)
        ├─ "##192.168.1.50#Share" → "192.168.1.50" (encoded UNC)
        └─ "ftp://192.168.1.1/files" → "192.168.1.1" (FTP URL)
        
        Returns:
            IP address string if found, None if not an IP
        """

        try:
            # Step 1: Validate input
            if unc_path is None or unc_path == "":
                return None
            
            unc_path = str(unc_path).strip()

            #Step 3: Define IP regex pattern
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

            # Step 4: Search for IP in the path
            match = re.search(ip_pattern, unc_path)

            if match is None:
                logger.debug(f"No IP found in path: {unc_path}")
                return None
            
            # Step 5: Extract matched IP
            potential_ip = match.group(1)
            octets = potential_ip.split(".")

            for octet in octets:
                octet_int = int(octet)

                if octet_int < 0 or octet_int > 255:
                    logger.debug(f"Invalid octet: {octet}")
                    return None
                
            # Step 7: Additional validation - reject obvious non-IPs
            first_octet = int(octets[0])
            
            if first_octet == 0:
                logger.debug(f"Invalid first octet: {first_octet}")
                return None
            
            # Step 8: Return valid IP
            logger.debug(f"Extracted IP from UNC: {potential_ip}")
            return potential_ip

        except Exception as e:
            logger.error(f"Error extracting IP from UNC: {str(e)}")
            return None

    # SOFTWARE, SYSTEM, SECURITY HELPERS functions
    def _extract_vid_from_device_id(self,device_id: str) -> Optional[str]:
        """Extract VID from "VID_1234&PID_5678" → "1234" """
        try:
            parts = device_id.split("&")
            for part in parts:
                if part.startswith("VID_"):
                    return part.replace("VID_", "")
            return None
        except Exception:
            return None

    def _extract_pid_from_device_id(self, device_id: str) -> Optional[str]:
        """Extract PID from "VID_1234&PID_5678" → "5678" """
        try:
            parts = device_id.split("&")
            for part in parts:
                if part.startswith("PID_"):
                    return part.replace("PID_", "")
            return None
        except Exception:
            return None

    def _categorize_secret(self, secret_name: str) -> str:
        """Categorize LSA secret by name"""
        secret_lower = secret_name.lower()
        
        # Service passwords: specific patterns (ASPNET, MSSQL, service account names)
        if any(x in secret_lower for x in ['aspnet_wp', 'mssql', '_password']):  # <-- underscore prefix
            return "service_password"
        
        # Cached credentials: Default* or explicit cached patterns
        if any(x in secret_lower for x in ['default', 'cached', '$nerlm']):
            return "cached_credential"
        
        # Encryption keys
        if any(x in secret_lower for x in ['dpapi', 'nl$km', 'bkmrx']):
            return "encryption_key"
        
        return "other"

    def _decrypt_lsa_secret(self, secret_subkey) -> Optional[str]:
        """
        Attempt to decrypt LSA secret.
        
        LSA secrets are encrypted with DPAPI using the SYSTEM account's key.
        Only SYSTEM-level code can decrypt them (requires admin + special privileges).
        
        WARNING: This requires:
        1. Admin privileges
        2. SYSTEM token access (not usually available)
        3. Access to SECURITY hive
        
        For forensic use:
        - If you can access the hive, you CAN try decryption
        - If it works, you've found plaintext passwords
        - If it fails, you can still note that the secret exists
        
        Returns: Decrypted secret string if successful, None otherwise
        """
        
        try:
            # Step 1: Try to extract encrypted data
            currval = self._get_value(secret_subkey, "CurrVal")
            
            if currval is None or not isinstance(currval, bytes):
                logger.debug("No encrypted secret data found")
                return None
            
            # Step 2: Try DPAPI decryption
            decrypted = self._dpapi_decrypt(currval)
            
            if decrypted:
                logger.info("Successfully decrypted LSA secret")
                return decrypted
            else:
                logger.debug("DPAPI decryption returned None")
                return None
        
        except Exception as e:
            logger.warning(f"Error attempting LSA secret decryption: {e}")
            return None

    def _dpapi_decrypt(self, encrypted_bytes: bytes) -> Optional[str]:
        """
        Decrypt DPAPI-encrypted data.
        
        This requires SYSTEM privileges and special key material.
        
        In production forensic labs, you would use:
        - impacket library (recommended)
        - mimikatz tool (extracts keys)
        - Windows Vault decryption tools
        
        For now, gracefully fails and logs instructions.
        """
        
        try:
            # Try to use impacket (if installed)
            try:
                from impacket import dpapi
                logger.info("impacket library available - attempting DPAPI decryption")
                # This would require key material from DPAPI_SYSTEM secret
                # Real implementation: decrypted = dpapi.SystemLSASecret(key, encrypted_bytes)
                logger.warning("Full DPAPI decryption requires additional key material")
                return None
            
            except ImportError:
                logger.debug("impacket not installed - DPAPI decryption unavailable")
                logger.info("For forensic DPAPI decryption, install: pip install impacket")
                return None
        
        except Exception as e:
            logger.debug(f"DPAPI decryption not available: {e}")
            return None

    def _extract_executable_path(self, command_line: str) -> str:
        """Extract executable path from command line"""
        if not command_line:
            return ""
        
        command = command_line.strip()
        
        # Remove leading/trailing quotes
        if command.startswith('"') and '"' in command[1:]:
            # Quoted path: "C:\Path\To\App.exe" /params
            end_quote = command.index('"', 1)
            return command[1:end_quote]
        
        # Unquoted path: check if first token is .exe or .com
        tokens = command.split()
        if tokens:
            exe = tokens[0]
            if exe.lower().endswith(('.exe', '.com', '.bat', '.cmd')):
                return exe
            
            # Try first two tokens (C:\Program Files\App.exe)
            if len(tokens) > 1:
                combined = tokens[0] + ' ' + tokens[1]
                if combined.lower().endswith(('.exe', '.com', '.bat', '.cmd')):
                    return combined
        
        return command
   
    def _convert_start_type(self, start_value: int) -> str:
        """
        Convert numeric Start value to readable format.
        
        0 = Boot (loads before kernel)
        1 = System (loads at kernel init)
        2 = Auto (loads during startup)
        3 = Manual (started by user/application)
        4 = Disabled (won't start)
        """
        
        START_TYPES = {
            0: "Boot",
            1: "System",
            2: "Auto",
            3: "Manual",
            4: "Disabled"
        }
        
        if start_value in START_TYPES:
            return START_TYPES[start_value]
        else:
            return f"Unknown ({start_value})"

    def _convert_service_type(self, type_value: int) -> str:
        """
        Convert numeric Type value to readable format.
        
        1 = Kernel Driver
        2 = File System Driver
        4 = Adapter (network, etc)
        8 = Recognizer Driver
        16 = Win32 Service
        32 = Win32 Service (shares process)
        256 = Interactive Service
        """
        
        SERVICE_TYPES = {
            1: "Kernel Driver",
            2: "File System Driver",
            4: "Adapter",
            8: "Recognizer Driver",
            16: "Win32 Service",
            32: "Win32 Service (shared)",
            256: "Interactive Service"
        }
        
        if type_value in SERVICE_TYPES:
            return SERVICE_TYPES[type_value]
        else:
            return f"Unknown ({type_value})"

    def _is_dll_signed(self, dll_path: str) -> bool:
        """
        Check if DLL is digitally signed (Windows-specific).
        
        Unsigned DLLs from AppData/Temp = VERY suspicious
        
        For now, returns False (assume unsigned if can't verify)
        Real implementation would use cryptography or Windows API
        """
        
        try:
            # Check if file exists
            if not Path(dll_path).exists() or not dll_path:
                return False
            
            dll_file = Path(dll_path)

            if not dll_file.exists():
                return False
        
            command = ["powershell", "-Command", (f"(Get-AuthenticodeSignature '{dll_file}').Status")]

            result = subprocess.run(command, capture_output = True, text= True, timeout= 10)
            status = result.stdout.strip()

            return status == "Valid"

        except Exception as e:
            logger.debug(
            f"DLL signature check failed "
            f"for {dll_path}: {e}"
        )
            return False
        