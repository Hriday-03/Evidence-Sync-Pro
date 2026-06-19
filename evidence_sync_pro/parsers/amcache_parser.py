from Registry import Registry
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from .base_parser import BaseParser, Event
import hashlib
from loguru import logger

class AmcacheParser(BaseParser):
    r"""
    Adaptive Windows Amcache Parser with Automatic Structure Detection.
    
    Automatically detects Amcache hive structure (Win7/Win8/Win10/Win11) and
    adapts extraction methods accordingly. Supports multiple data sections
    with priority-based extraction to maximize forensic data recovery.
    
    Supported Amcache Sections:
    - Programs: Installed programs with metadata (Win10+, highest priority)
    - File: File execution history and properties (execution tracking)
    - Orphan: Removed programs (forensic value for deleted software detection)
    - Device: Connected devices (USB, network adapters, storage)
    - HwItem: Hardware inventory (optional, system-dependent)
    - Generic: Generic application compatibility data (optional)
    - Metadata: Amcache metadata (optional)
    
    Structure Detection Strategy:
    1. Probe hive for Root key location (Root vs Root\Root)
    2. Enumerate available sections and entry counts
    3. Identify Windows version signature from sections present
    4. Extract in priority order (Programs first, then File, then Orphan, then optional)
    
    Location: C:\Windows\appcompat\Programs\Amcache.hve
    Forensic Value: Program execution history, installation dates, file hashes, removed software
    """
    
    def __init__(self,
                 amcache_hive_path: str,
                 computer_name: str = "UNKNOWN_HOST",
                 system_timezone: str = "UTC+0"):
        r"""
        Initialize AmcacheParser with hive path and system metadata.
        
        Args:
            amcache_hive_path (str): Full path to Amcache.hve file
            computer_name (str): Computer name for forensic event tracking
            system_timezone (str): System timezone offset (e.g., "UTC+5:30", "UTC-8")
        
        Returns:
            None (initializes parser instance)
        """
        
        self.amcache_hive_path = amcache_hive_path
        self.computer_name = computer_name
        self.system_timezone = system_timezone
        
        # Structure detection results (populated by _detect_amcache_structure)
        self.amcache_type = None  # "Win10+", "Win8/Win9", "Win7", "Unknown"
        self.available_sections = {}  # {"Programs": 16, "File": 4, "Orphan": 78, ...}
        self.root_path = []  # ["Root"] or ["Root", "Root"] depending on Windows version
        
        self.corruption_log: List[Dict[str, Any]] = []
        self.events_count = 0
    
    def parse(self) -> List[Event]:
        r"""
        Main entry point: detect Amcache structure and extract all forensic events.
        
        Orchestrates complete parsing workflow:
        1. Loads Amcache.hve registry hive
        2. Detects hive structure (Windows version, available sections)
        3. Extracts events from populated sections in priority order
        4. Returns consolidated list of all forensic events
        
        Args:
            None (uses self.amcache_hive_path)
        
        Returns:
            List[Event]: All extracted forensic events from Amcache hive
        """
        
        all_events = []
        
        try:
            logger.info("="*80)
            logger.info("AMCACHE PARSER - STARTING EXTRACTION (AUTO-DETECTION)")
            logger.info("="*80)
            
            # Load Amcache hive
            logger.info(f"\nLoading Amcache hive: {self.amcache_hive_path}")
            amcache_hive = self._load_hive(self.amcache_hive_path)
            
            if amcache_hive is None:
                logger.error("Failed to load Amcache hive")
                return []
            
            # === STEP 1: AUTO-DETECT STRUCTURE ===
            logger.info("\n[Step 1] Detecting Amcache structure...")
            self._detect_amcache_structure(amcache_hive)
            
            logger.info(f"  ✓ Detected type: {self.amcache_type}")
            logger.info(f"  ✓ Root path: {chr(92).join(self.root_path)}")
            logger.info(f"  ✓ Available sections:")
            for section, count in sorted(self.available_sections.items()):
                if count > 0:
                    logger.info(f"    - {section}: {count} entries")
            
            # === STEP 2: EXTRACT IN PRIORITY ORDER ===
            logger.info("\n[Step 2] Extracting data from populated sections...")
            
            # Tier 1: Programs (Win10+, most data-rich, highest forensic value)
            if self.available_sections.get("Programs", 0) > 0:
                logger.info(f"\n  [Tier 1] Programs section ({self.available_sections['Programs']} entries)")
                prog_events = self._extract_programs(amcache_hive)
                all_events.extend(prog_events)
                logger.info(f"    ✓ Extracted {len(prog_events)} program events")
            
            # Tier 2: File (execution history, present on exec-tracking systems)
            if self.available_sections.get("File", 0) > 0:
                logger.info(f"\n  [Tier 2] File section ({self.available_sections['File']} entries)")
                file_events = self._extract_file_execution(amcache_hive)
                all_events.extend(file_events)
                logger.info(f"    ✓ Extracted {len(file_events)} file execution events")
            
            # Tier 3: Orphan (removed programs, valuable for deletion forensics)
            if self.available_sections.get("Orphan", 0) > 0:
                logger.info(f"\n  [Tier 3] Orphan section ({self.available_sections['Orphan']} entries)")
                orphan_events = self._extract_orphan_programs(amcache_hive)
                all_events.extend(orphan_events)
                logger.info(f"    ✓ Extracted {len(orphan_events)} orphan program events")
            
            # Tier 4: Optional sections (Device, HwItem, Generic, Metadata)
            for section in ["Device", "HwItem", "Generic", "Metadata"]:
                if self.available_sections.get(section, 0) > 0:
                    logger.info(f"\n  [Tier 4] {section} section ({self.available_sections[section]} entries)")
                    section_events = self._extract_optional_section(amcache_hive, section)
                    all_events.extend(section_events)
                    logger.info(f"    ✓ Extracted {len(section_events)} {section.lower()} events")
            
            # === FINAL SUMMARY ===
            logger.info("\n" + "="*80)
            logger.info("AMCACHE PARSER EXTRACTION COMPLETE")
            logger.info("="*80)
            logger.info(f"Amcache Type: {self.amcache_type}")
            logger.info(f"Total events extracted: {len(all_events)}")
            logger.info(f"Corruption log entries: {len(self.corruption_log)}")
            logger.info("="*80 + "\n")
            
            return all_events
        
        except Exception as e:
            logger.error(f"Fatal error in parse(): {e}")
            self.corruption_log.append({
                "error": str(e),
                "stage": "parse_main_entry_point",
                "events_before_failure": len(all_events)
            })
            return all_events
    
    # ============================================================================
    # === STRUCTURE DETECTION (Auto-Detection of Amcache Type & Layout) ===
    # ============================================================================
    
    def _detect_amcache_structure(self, amcache_hive) -> None:
        r"""
        Auto-detect Amcache hive structure and populate parser metadata.
        
        Probes hive to determine:
        - Root key location (self.root_path)
        - Available sections and entry counts (self.available_sections)
        - Windows version signature (self.amcache_type)
        
        Works by attempting to navigate to Root key, then enumerating all
        recognized section names to determine structure layout.
        
        Args:
            amcache_hive: Registry.RegistryHive object (opened hive)
        
        Returns:
            None (populates self.amcache_type, self.available_sections, self.root_path)
        """
        
        try:
            root = amcache_hive.root()
            
            if root is None:
                logger.error("Cannot get hive root")
                self.amcache_type = "UNKNOWN"
                return
            
            # === PROBE 1: Locate Root key (different structure in different Windows versions) ===
            root_subkey = None
            root_path = None
            
            try:
                first_root = root.subkey("Root")

                if first_root is not None:
                    try:
                        second_root = first_root.subkey("Root")

                        if second_root is not None:
                            root_subkey = second_root
                            root_path = ["Root", "Root"]

                            logger.debug("Detected layout: Root\\Root")

                        else:
                            root_subkey = first_root
                            root_path = ["Root"]
                            logger.debug("Detected layout: Root" )

                    except Exception:
                        root_subkey = first_root
                        root_path = ["Root"]
                        logger.debug("Detected layout: Root")

            except Exception:
                pass
            
            if root_subkey is None:
                try:
                    # Try Root (older Windows: Win7, Win8)
                    test_root = root
                    if list(test_root.subkeys()):  # Has children
                        root_subkey = test_root
                        root_path = ["Root"]
                except:
                    pass
            
            if root_subkey is None:
                logger.error("Cannot find Root key structure in Amcache hive")
                self.amcache_type = "UNKNOWN"
                return
            
            self.root_path = root_path
            
            # === PROBE 2: Scan available sections and count entries ===
            section_names = ["Programs", "File", "Orphan", "Device", "HwItem", 
                           "Generic", "Metadata", "InventoryApplicationFile"]
            
            for section_name in section_names:
                try:
                    section_key = root_subkey.subkey(section_name)
                    
                    if section_key is not None:
                        # Count number of subkeys (entries) in section
                        entry_count = 0
                        try:
                            for _ in section_key.subkeys():
                                entry_count += 1
                        except:
                            pass
                        
                        self.available_sections[section_name] = entry_count
                except:
                    pass
            
            # === PROBE 3: Determine Windows version based on section signatures ===
            self._detect_windows_version()
            
            logger.debug(f"Detected sections: {self.available_sections}")
            logger.debug(f"Amcache type: {self.amcache_type}")
        
        except Exception as e:
            logger.error(f"Error in structure detection: {e}")
            self.amcache_type = "UNKNOWN"
    
    def _detect_windows_version(self) -> None:
        r"""
        Identify Windows version based on Amcache section presence signatures.
        
        Uses section presence to infer Windows version:
        - "Programs" present = Win10 or later
        - "File" but no "Programs" = Win8/Win9
        - Default = Unknown
        
        Sets self.amcache_type to version string.
        
        Args:
            None (reads from self.available_sections)
        
        Returns:
            None (sets self.amcache_type)
        """
        
        try:
            # Win10+ signature: has "Programs" section
            if "Programs" in self.available_sections:
                self.amcache_type = "Win10+"
                return
            
            # Win8-Win9 signature: has "File" but not "Programs"
            if "File" in self.available_sections and "Programs" not in self.available_sections:
                self.amcache_type = "Win8/Win9"
                return
            
            # Fallback
            self.amcache_type = "Unknown"
        
        except Exception as e:
            logger.warning(f"Error detecting Windows version: {e}")
            self.amcache_type = "Unknown"
    
    def _get_root_key(self, hive):
        r"""
        Navigate to root key using detected path (Root or Root\Root).
        
        Uses self.root_path to navigate from hive root to the actual
        root key containing sections. Handles both Win7 (single Root)
        and Win10+ (Root\Root) layouts automatically.
        
        Args:
            hive: Registry.RegistryHive object
        
        Returns:
            Registry.RegistryKey: Root key object, or None if navigation fails
        """
        
        try:
            current = hive.root()
            
            for path_component in self.root_path:
                if path_component == "Root":
                    current = current.subkey("Root")
                
                if current is None:
                    return None
            
            return current
        
        except Exception as e:
            logger.error(f"Error getting root key: {e}")
            return None
    
    # ============================================================================
    # === EXTRACTION METHODS (Tier 1-4 Priority Extraction) ===
    # ============================================================================
    
    def _extract_programs(self, amcache_hive) -> List[Event]:
        r"""
        Extract installed programs from Programs section (Win10+, Tier 1 priority).
        
        Programs section contains rich metadata about installed software:
        - Program name, version, publisher
        - Installation date (Unix timestamp, value "a")
        - Application type (AddRemoveProgram, etc.)
        - File references and uninstall strings
        
        Processes each program entry and creates Event objects with forensic metadata.
        
        Args:
            amcache_hive: Registry.RegistryHive object
        
        Returns:
            List[Event]: All extracted program installation events (empty if section missing)
        """
        
        events = []
        
        try:
            root_key = self._get_root_key(amcache_hive)
            
            if root_key is None:
                logger.warning("Cannot access root key for Programs extraction")
                return []
            
            programs_key = root_key.subkey("Programs")
            
            if programs_key is None:
                logger.warning("Programs section not found")
                return []
            
            logger.debug("Found Programs section")
            
            # Iterate through each program entry in Programs section
            for prog_subkey in programs_key.subkeys():
                prog_id = prog_subkey.name()
                prog_timestamp = prog_subkey.timestamp()
                
                try:
                    # Extract all values from program entry
                    values_dict = {}
                    for value in prog_subkey.values():
                        val_name = value.name()
                        try:
                            values_dict[val_name] = value.value()
                        except:
                            pass
                    
                    if not values_dict:
                        continue
                    
                    # Map registry value names to fields (numeric value names in Programs section)
                    program_name = values_dict.get("0")  # Program name
                    version = values_dict.get("1")  # Version
                    publisher = values_dict.get("2")  # Publisher
                    language = values_dict.get("3")  # Language
                    app_type = values_dict.get("5")  # App type (e.g., "AddRemoveProgram")
                    install_date_raw = values_dict.get("a")  # Install date (Unix timestamp)
                    uninstall_string = values_dict.get("7")  # Uninstall string
                    file_refs = values_dict.get("Files")  # File references
                    
                    # Skip entries without program name
                    if not program_name:
                        continue
                    
                    # Parse install date (Unix timestamp)
                    install_date = None
                    if install_date_raw:
                        try:
                            if isinstance(install_date_raw, int):
                                install_date = datetime.fromtimestamp(install_date_raw, tz=timezone.utc)
                        except:
                            pass
                    
                    event_timestamp = install_date or prog_timestamp
                    
                    # Create forensic event
                    event = Event(
                        timestamp=event_timestamp,
                        source_device=self.computer_name,
                        source_type="AMCACHE",
                        event_type="program_installed",
                        user="SYSTEM",
                        payload={
                            "program_id": prog_id,
                            "program_name": program_name,
                            "version": version or "Unknown",
                            "publisher": publisher or "Unknown",
                            "language": language,
                            "app_type": app_type,
                            "install_date": install_date,
                            "uninstall_string": uninstall_string,
                            "file_references": file_refs,
                            "registry_path": f"{chr(92).join(self.root_path)}{chr(92)}Programs",
                            "hive_source": self.amcache_hive_path,
                        },
                        timezone_offset=self.system_timezone,
                        local_timestamp=self._calculate_local_timestamp(event_timestamp, self.system_timezone),
                        forensic_priority="HIGH",
                        confidence_score=0.95,
                        corruption_detected=False
                    )
                    
                    events.append(event)
                    self.events_count += 1
                
                except Exception as e:
                    logger.warning(f"Error processing program {prog_id}: {e}")
                    self.corruption_log.append({
                        "error": str(e),
                        "stage": "program_extraction",
                        "program_id": prog_id
                    })
                    continue
            
            return events
        
        except Exception as e:
            logger.warning(f"Error extracting Programs section: {e}")
            return []
    
    def _extract_file_execution(self, amcache_hive) -> List[Event]:
        r"""
        Extract file execution history from File section (Tier 2 priority).
        
        File section contains execution records with basic metadata:
        - File name, path, size
        - SHA1 hash, version, publisher
        - Limited to files that actually executed on system
        
        Processes each file entry and creates forensic events.
        
        Args:
            amcache_hive: Registry.RegistryHive object
        
        Returns:
            List[Event]: All extracted file execution events (empty if section missing)
        """
        
        events = []
        
        try:
            root_key = self._get_root_key(amcache_hive)
            
            if root_key is None:
                logger.warning("Cannot access root key for File extraction")
                return []
            
            file_key = root_key.subkey("File")
            
            if file_key is None:
                logger.warning("File section not found")
                return []
            
            logger.debug("Found File section")
            
            # Iterate through each file entry
            for file_subkey in file_key.subkeys():
                file_id = file_subkey.name()
                file_timestamp = file_subkey.timestamp()
                
                try:
                    # Extract all values from file entry
                    values_dict = {}
                    for value in file_subkey.values():
                        val_name = value.name()
                        try:
                            values_dict[val_name] = value.value()
                        except:
                            pass
                    
                    if not values_dict:
                        continue
                    
                    # Extract file metadata
                    program_name = values_dict.get("Name")
                    file_path = values_dict.get("Path")
                    sha1 = values_dict.get("SHA1")
                    file_size = values_dict.get("Size")
                    version = values_dict.get("Version")
                    publisher = values_dict.get("Publisher")
                    
                    # If no name, try to extract filename from path
                    if not program_name and file_path:
                        program_name = file_path.split("\\")[-1]
                    
                    if not program_name:
                        continue
                    
                    # Create forensic event
                    event = Event(
                        timestamp=file_timestamp,
                        source_device=self.computer_name,
                        source_type="AMCACHE",
                        event_type="file_execution",
                        user="SYSTEM",
                        payload={
                            "file_id": file_id,
                            "program_name": program_name,
                            "file_path": file_path,
                            "sha1_hash": sha1,
                            "file_size": file_size,
                            "version": version,
                            "publisher": publisher,
                            "registry_path": f"{chr(92).join(self.root_path)}{chr(92)}File",
                            "hive_source": self.amcache_hive_path,
                        },
                        timezone_offset=self.system_timezone,
                        local_timestamp=self._calculate_local_timestamp(file_timestamp, self.system_timezone),
                        forensic_priority="HIGH",
                        confidence_score=0.85,
                        corruption_detected=False
                    )
                    
                    events.append(event)
                    self.events_count += 1
                
                except Exception as e:
                    logger.warning(f"Error processing file {file_id}: {e}")
                    self.corruption_log.append({
                        "error": str(e),
                        "stage": "file_execution_extraction",
                        "file_id": file_id
                    })
                    continue
            
            return events
        
        except Exception as e:
            logger.warning(f"Error extracting File section: {e}")
            return []
    
    def _extract_orphan_programs(self, amcache_hive) -> List[Event]:
        r"""
        Extract removed programs from Orphan section (Tier 3 priority).
        
        Orphan section contains entries for programs that were uninstalled
        but still referenced in Amcache registry. Forensically valuable for
        detecting removed software and reconstruction of deletion timeline.
        
        Processes each orphan entry and creates forensic events.
        
        Args:
            amcache_hive: Registry.RegistryHive object
        
        Returns:
            List[Event]: All extracted orphan program events (empty if section missing)
        """
        
        events = []
        
        try:
            root_key = self._get_root_key(amcache_hive)
            
            if root_key is None:
                logger.warning("Cannot access root key for Orphan extraction")
                return []
            
            orphan_key = root_key.subkey("Orphan")
            
            if orphan_key is None:
                logger.warning("Orphan section not found")
                return []
            
            logger.debug("Found Orphan section")
            
            # Iterate through each orphan entry
            for orphan_subkey in orphan_key.subkeys():
                orphan_id = orphan_subkey.name()
                orphan_timestamp = orphan_subkey.timestamp()
                
                try:
                    # Extract all values from orphan entry
                    values_dict = {}
                    for value in orphan_subkey.values():
                        val_name = value.name()
                        try:
                            values_dict[val_name] = value.value()
                        except:
                            pass
                    
                    if not values_dict:
                        continue
                    
                    # Create forensic event
                    event = Event(
                        timestamp=orphan_timestamp,
                        source_device=self.computer_name,
                        source_type="AMCACHE",
                        event_type="program_removed",
                        user="SYSTEM",
                        payload={
                            "orphan_id": orphan_id,
                            "orphan_data": values_dict,
                            "registry_path": f"{chr(92).join(self.root_path)}{chr(92)}Orphan",
                            "hive_source": self.amcache_hive_path,
                        },
                        timezone_offset=self.system_timezone,
                        local_timestamp=self._calculate_local_timestamp(orphan_timestamp, self.system_timezone),
                        forensic_priority="MEDIUM",
                        confidence_score=0.70,
                        corruption_detected=False
                    )
                    
                    events.append(event)
                    self.events_count += 1
                
                except Exception as e:
                    logger.warning(f"Error processing orphan {orphan_id}: {e}")
                    self.corruption_log.append({
                        "error": str(e),
                        "stage": "orphan_program_extraction",
                        "orphan_id": orphan_id
                    })
                    continue
            
            return events
        
        except Exception as e:
            logger.warning(f"Error extracting Orphan section: {e}")
            return []
    
    def _extract_optional_section(self, amcache_hive, section_name: str) -> List[Event]:
        r"""
        Extract from optional sections (Device, HwItem, Generic, Metadata) using generic handler.
        
        Tier 4 priority extraction for optional sections that vary in content.
        Uses generic extraction since section structures may differ. Collects
        all available values from each entry without schema assumptions.
        
        Args:
            amcache_hive: Registry.RegistryHive object
            section_name (str): Name of section to extract ("Device", "HwItem", etc.)
        
        Returns:
            List[Event]: All extracted events from specified section (empty if section missing)
        """
        
        events = []
        
        try:
            root_key = self._get_root_key(amcache_hive)
            
            if root_key is None:
                logger.warning(f"Cannot access root key for {section_name} extraction")
                return []
            
            section_key = root_key.subkey(section_name)
            
            if section_key is None:
                logger.debug(f"{section_name} section not found")
                return []
            
            logger.debug(f"Found {section_name} section")
            
            # Iterate through entries in optional section
            for entry_subkey in section_key.subkeys():
                entry_id = entry_subkey.name()
                entry_timestamp = entry_subkey.timestamp()
                
                try:
                    # Extract all values from entry (generic collection)
                    values_dict = {}
                    for value in entry_subkey.values():
                        val_name = value.name()
                        try:
                            val_data = value.value()
                            values_dict[val_name] = val_data
                        except:
                            pass
                    
                    if not values_dict:
                        continue
                    
                    # Create forensic event
                    event = Event(
                        timestamp=entry_timestamp,
                        source_device=self.computer_name,
                        source_type="AMCACHE",
                        event_type=f"amcache_{section_name.lower()}",
                        user="SYSTEM",
                        payload={
                            "entry_id": entry_id,
                            "section": section_name,
                            "data": values_dict,
                            "registry_path": f"{chr(92).join(self.root_path)}{chr(92)}{section_name}",
                            "hive_source": self.amcache_hive_path,
                        },
                        timezone_offset=self.system_timezone,
                        local_timestamp=self._calculate_local_timestamp(entry_timestamp, self.system_timezone),
                        forensic_priority="MEDIUM",
                        confidence_score=0.80,
                        corruption_detected=False
                    )
                    
                    events.append(event)
                    self.events_count += 1
                
                except Exception as e:
                    logger.warning(f"Error processing {section_name} entry {entry_id}: {e}")
                    self.corruption_log.append({
                        "error": str(e),
                        "stage": f"{section_name.lower()}_extraction",
                        "entry_id": entry_id
                    })
                    continue
            
            return events
        
        except Exception as e:
            logger.warning(f"Error extracting {section_name} section: {e}")
            return []
    
    # ============================================================================
    # === HELPER FUNCTIONS (File I/O, Timestamp Conversion, Chain of Custody) ===
    # ============================================================================
    
    def _load_hive(self, hive_path: str):
        r"""
        Load and validate Amcache.hve registry hive file.
        
        Opens hive file, validates registry signature ("regf"), and returns
        Registry object for parsing. Handles permission errors and I/O errors gracefully.
        
        Args:
            hive_path (str): Full filesystem path to Amcache.hve file
        
        Returns:
            Registry.RegistryHive: Opened hive object, or None if load fails
        """
        
        try:
            hive_file_path = Path(hive_path)
            
            # Check file exists
            if not hive_file_path.is_file():
                logger.error(f"Amcache hive file not found: {hive_path}")
                self.corruption_log.append({
                    "error": "File not found",
                    "stage": "hive_load",
                    "hive_path": hive_path
                })
                return None
            
            # Try to open file
            try:
                hive_file_handle = open(hive_path, 'rb')
            except PermissionError:
                logger.error(f"Permission denied reading hive: {hive_path}")
                logger.info("Tip: Run as Administrator or check file permissions")
                return None
            except IOError as e:
                logger.error(f"I/O error reading hive: {e}")
                return None
            
            # Validate registry file signature (must start with "regf")
            first_bytes = hive_file_handle.read(4)
            hive_file_handle.seek(0)
            
            if first_bytes != b'regf':
                logger.error(f"Invalid hive signature: {hive_path}")
                logger.debug(f"Got {first_bytes} instead of b'regf'")
                hive_file_handle.close()
                return None
            
            # Load hive using python-registry
            try:
                hive = Registry.Registry(hive_file_handle)
                logger.info(f"Successfully loaded Amcache hive: {hive_path}")
                hive_file_handle.close()
                return hive
            
            except Exception as e:
                logger.error(f"Error loading Amcache hive {hive_path}: {e}")
                hive_file_handle.close()
                return None
        
        except Exception as e:
            logger.error(f"Fatal error in _load_hive: {e}")
            return None
    
    def _calculate_local_timestamp(self, utc_dt: datetime, offset_str: str) -> datetime:
        r"""
        Convert UTC datetime to local time using timezone offset string.
        
        Parses timezone offset (e.g., "UTC+5:30", "UTC-8") and applies to UTC
        timestamp to get local system time. Returns unchanged UTC if parsing fails.
        
        Args:
            utc_dt (datetime): UTC datetime object
            offset_str (str): Timezone offset string (e.g., "UTC+5:30", "UTC-8")
        
        Returns:
            datetime: Local datetime (adjusted for timezone), or original UTC if conversion fails
        """
        
        if not utc_dt:
            return utc_dt
        
        try:
            # Clean offset string
            clean_offset = offset_str.upper().replace("UTC", "").strip()
            if not clean_offset or clean_offset == "+0" or clean_offset == "-0":
                return utc_dt
            
            # Parse sign
            sign = -1 if clean_offset.startswith("-") else 1
            clean_offset = clean_offset.lstrip("+-")
            
            # Parse hours and minutes
            if ":" in clean_offset:
                hours_part, minutes_part = clean_offset.split(":", 1)
                hours = int(hours_part)
                minutes = int(minutes_part)
            else:
                hours = int(clean_offset)
                minutes = 0
            
            # Create timedelta and apply
            delta = timedelta(hours=hours, minutes=minutes)
            if sign == -1:
                return utc_dt - delta
            else:
                return utc_dt + delta
        
        except Exception as e:
            logger.debug(f"Error parsing timezone offset '{offset_str}': {e}")
            return utc_dt
    
    def _get_chain_of_custody_metadata(self, hive_path: str) -> Dict:
        r"""
        Calculate cryptographic hashes and metadata for chain of custody documentation.
        
        Computes SHA256 and MD5 hashes of hive file for forensic integrity validation.
        Useful for case documentation and legal proceedings.
        
        Args:
            hive_path (str): Full filesystem path to Amcache.hve file
        
        Returns:
            Dict: Chain of custody metadata including hashes:
                  {
                    "hive_path": str,
                    "hive_name": "Amcache",
                    "file_size": int (bytes),
                    "sha256": str (hex digest),
                    "md5": str (hex digest),
                    "parse_timestamp": datetime,
                    "parser_version": str,
                    "parser_name": str,
                    "error": str (if hashing failed)
                  }
        """
        
        try:
            file_path = Path(hive_path)
            
            if not file_path.is_file():
                return {
                    "hive_path": hive_path,
                    "error": "File not found",
                    "sha256": None,
                    "md5": None
                }
            
            file_size = file_path.stat().st_size
            logger.info(f"Calculating hashes of {hive_path} ({file_size} bytes)")
            
            # Initialize hash objects
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            CHUNK_SIZE = 8192
            
            # Read file in chunks and update hashes
            with open(hive_path, 'rb') as hive_file:
                while True:
                    chunk = hive_file.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            # Get hex digests
            sha256_digest = sha256_hash.hexdigest()
            md5_digest = md5_hash.hexdigest()
            
            # Create metadata dict
            metadata = {
                "hive_path": str(hive_path),
                "hive_name": "Amcache",
                "file_size": file_size,
                "sha256": sha256_digest,
                "md5": md5_digest,
                "parse_timestamp": datetime.now(timezone.utc),
                "parser_version": "2.0.0",
                "parser_name": "EvidenceSync Pro Amcache Parser (Auto-Detect)"
            }
            
            logger.info(f"SHA256: {sha256_digest}")
            logger.info(f"MD5: {md5_digest}")
            
            return metadata
        
        except Exception as e:
            logger.error(f"Error calculating chain of custody: {e}")
            return {
                "hive_path": hive_path,
                "error": f"Error: {str(e)}",
                "sha256": None,
                "md5": None
            }
