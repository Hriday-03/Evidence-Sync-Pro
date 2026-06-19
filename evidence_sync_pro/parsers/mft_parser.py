from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from .base_parser import BaseParser, Event
import hashlib
from loguru import logger
import struct

class MFTParser(BaseParser):
    r"""
    Windows NTFS Master File Table (MFT) Parser.
    
    The MFT is the NTFS file system journal that tracks all files and directories
    on a Windows partition. Each entry ($FILE_RECORD) contains metadata about
    one file or directory including:
    - Filename and full path
    - File size
    - Creation, modification, access timestamps (MAC times)
    - File attributes (hidden, system, archive, etc.)
    - Data runs and allocation information
    - $FILE_NAME and $STANDARD_INFORMATION attributes
    
    Forensic Significance:
    - Timeline of all file system activity
    - Detects deleted files (marked as "not in use")
    - Recoverable timestamps even after file deletion
    - Links files to execution sequences (via timestamps)
    - Identifies hidden/system files and anomalies
    
    MFT Structure:
    - Each record is 1024 bytes (default)
    - Record 0: MFT itself
    - Record 1: MFTMirr (backup)
    - Record 2: LogFile (transaction log)
    - Record 3: Volume (volume label)
    - Record 4: AttrDef (attribute definitions)
    - Record 5: Root directory
    - Record 6+: User files and directories
    
    Location: $MFT (at root of NTFS partition)
    Size: Typically 10-200 MB depending on drive size and file count
    """
    
    # MFT Constants
    MFT_RECORD_SIZE = 1024
    FIXUP_SIZE = 2
    MFT_SIGNATURE = b'FILE'
    
    # File flags
    FILE_RECORD_IN_USE = 0x01
    FILE_IS_DIRECTORY = 0x02
    
    # Attribute types
    ATTR_TYPE_STANDARD_INFO = 0x10
    ATTR_TYPE_ATTR_LIST = 0x20
    ATTR_TYPE_FILENAME = 0x30
    ATTR_TYPE_DATA = 0x80
    
    # Attribute names for readability
    ATTR_NAMES = {
        0x10: "$STANDARD_INFORMATION",
        0x20: "$ATTRIBUTE_LIST",
        0x30: "$FILE_NAME",
        0x40: "$VOLUME_VERSION",
        0x50: "$SECURITY_DESCRIPTOR",
        0x60: "$VOLUME_NAME",
        0x70: "$VOLUME_INFORMATION",
        0x80: "$DATA",
        0x90: "$INDEX_ROOT",
        0xA0: "$INDEX_ALLOCATION",
        0xB0: "$BITMAP",
        0xC0: "$REPARSE_POINT",
        0xD0: "$EA_INFORMATION",
        0xE0: "$EA",
        0xF0: "$LOGGED_UTILITY_STREAM",
    }
    
    def __init__(self,
                 mft_file_path: str,
                 computer_name: str = "UNKNOWN_HOST",
                 system_timezone: str = "UTC+0",
                 partition_letter: str = "C"):
        r"""
        Initialize MFTParser with MFT file path and system metadata.
        
        Args:
            mft_file_path (str): Full path to $MFT file
            computer_name (str): Computer name for forensic event tracking
            system_timezone (str): System timezone offset (e.g., "UTC+5:30", "UTC-8")
            partition_letter (str): Partition letter (C, D, E, etc.)
        
        Returns:
            None (initializes parser instance)
        """
        
        self.mft_file_path = mft_file_path
        self.computer_name = computer_name
        self.system_timezone = system_timezone
        self.partition_letter = partition_letter
        
        # Parser state
        self.total_records = 0
        self.in_use_records = 0
        self.deleted_records = 0
        self.directories = 0
        self.files = 0
        
        self.corruption_log: List[Dict[str, Any]] = []
        self.events_count = 0
    
    def parse(self) -> List[Event]:
        r"""
        Main entry point: parse MFT file and extract all file system activity events.
        
        Orchestrates complete parsing workflow:
        1. Load and validate MFT file
        2. Parse MFT header
        3. Iterate through all MFT records
        4. Extract $STANDARD_INFORMATION (timestamps) and $FILE_NAME attributes
        5. Create forensic Event for each file/directory
        6. Return consolidated list of all file system events
        
        Args:
            None (uses self.mft_file_path)
        
        Returns:
            List[Event]: All extracted file system activity events
        """
        
        all_events = []
        
        try:
            logger.info("="*80)
            logger.info("MFT PARSER - STARTING EXTRACTION")
            logger.info("="*80)
            
            # Load MFT file
            logger.info(f"\nLoading MFT file: {self.mft_file_path}")
            mft_data = self._load_mft_file(self.mft_file_path)
            
            if mft_data is None:
                logger.error("Failed to load MFT file")
                return []
            
            logger.info(f"  ✓ Loaded {len(mft_data)} bytes")
            
            # Calculate total records
            self.total_records = len(mft_data) // self.MFT_RECORD_SIZE
            logger.info(f"  ✓ Total MFT records: {self.total_records}")
            
            # === STEP 1: PARSE MFT RECORDS ===
            logger.info(f"\n[Step 1] Parsing {self.total_records} MFT records...")
            
            for record_num in range(self.total_records):
                record_offset = record_num * self.MFT_RECORD_SIZE
                
                if record_offset + self.MFT_RECORD_SIZE > len(mft_data):
                    break
                
                record_data = mft_data[record_offset:record_offset + self.MFT_RECORD_SIZE]
                
                try:
                    # Parse single MFT record
                    record_events = self._parse_mft_record(record_num, record_data)
                    all_events.extend(record_events)
                    
                except Exception as e:
                    logger.warning(f"Error parsing MFT record {record_num}: {e}")
                    self.corruption_log.append({
                        "error": str(e),
                        "stage": "mft_record_parsing",
                        "record_number": record_num
                    })
                    continue
            
            # === FINAL SUMMARY ===
            logger.info("\n" + "="*80)
            logger.info("MFT PARSER EXTRACTION COMPLETE")
            logger.info("="*80)
            logger.info(f"Total MFT records processed: {self.total_records}")
            logger.info(f"In-use records: {self.in_use_records}")
            logger.info(f"Deleted records (unallocated): {self.deleted_records}")
            logger.info(f"Directories: {self.directories}")
            logger.info(f"Files: {self.files}")
            logger.info(f"Total forensic events extracted: {len(all_events)}")
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
    # === MFT RECORD PARSING ===
    # ============================================================================
    
    def _parse_mft_record(self, record_num: int, record_data: bytes) -> List[Event]:
        r"""
        Parse single MFT record and extract file system activity events.
        
        Each MFT record contains:
        - MFT header (42 bytes)
        - Update sequence array (for NTFS protection)
        - Attributes ($STANDARD_INFORMATION, $FILE_NAME, $DATA, etc.)
        
        Extracts timestamps and file metadata from attributes.
        
        Args:
            record_num (int): MFT record number (0-based index)
            record_data (bytes): 1024-byte MFT record
        
        Returns:
            List[Event]: All events extracted from this record (0 if record unused)
        """
        
        events = []
        
        try:
            # Check signature
            if len(record_data) < 4 or record_data[0:4] != self.MFT_SIGNATURE:
                logger.debug(f"MFT record {record_num}: Invalid signature")
                return []
            
            # Parse record flags
            flags = struct.unpack('<H', record_data[22:24])[0]
            in_use = bool(flags & self.FILE_RECORD_IN_USE)
            is_directory = bool(flags & self.FILE_IS_DIRECTORY)
            
            if in_use:
                self.in_use_records += 1
                if is_directory:
                    self.directories += 1
                else:
                    self.files += 1
            else:
                self.deleted_records += 1
            
            # Get bytes used in record
            bytes_used = struct.unpack('<I', record_data[28:32])[0]
            
            # Extract attributes
            attr_offset = struct.unpack('<H', record_data[20:22])[0]
            
            # Variables to store extracted data
            std_info = None
            file_name = None
            
            # Parse attributes
            while attr_offset < bytes_used and attr_offset < len(record_data):
                attr_type = struct.unpack('<I', record_data[attr_offset:attr_offset+4])[0]
                
                if attr_type == 0xFFFFFFFF:  # End marker
                    break
                
                attr_length = struct.unpack('<I', record_data[attr_offset+4:attr_offset+8])[0]
                
                if attr_length == 0 or attr_offset + attr_length > len(record_data):
                    break
                
                attr_data = record_data[attr_offset:attr_offset+attr_length]
                
                # Parse specific attributes
                if attr_type == self.ATTR_TYPE_STANDARD_INFO:
                    std_info = self._parse_standard_information(attr_data)
                
                elif attr_type == self.ATTR_TYPE_FILENAME:
                    file_name = self._parse_filename_attribute(attr_data)
                
                attr_offset += attr_length
            
            # Create event if we have meaningful data
            if std_info or file_name:
                event = self._create_mft_event(
                    record_num, in_use, is_directory,
                    std_info, file_name
                )
                if event:
                    events.append(event)
                    self.events_count += 1
        
        except Exception as e:
            logger.debug(f"Error parsing MFT record {record_num}: {e}")
        
        return events
    
    def _parse_standard_information(self, attr_data: bytes) -> Optional[Dict]:
        r"""
        Parse $STANDARD_INFORMATION attribute (MAC times).
        
        Contains:
        - C time: File creation time
        - M time: File modification time
        - A time: File access time
        - W time: MFT write time
        - File attributes
        - Max versions, version
        - Class ID
        
        Args:
            attr_data (bytes): Attribute data buffer
        
        Returns:
            Dict with parsed timestamps, or None if parsing fails
        """
        
        try:
            # Skip attribute header (22 bytes for resident attribute)
            if len(attr_data) < 48:
                return None
            
            # Read timestamps (FILETIME format = 100-nanosecond intervals since 1601)
            c_time_raw = struct.unpack('<Q', attr_data[24:32])[0]
            a_time_raw = struct.unpack('<Q', attr_data[32:40])[0]
            m_time_raw = struct.unpack('<Q', attr_data[40:48])[0]
            w_time_raw = struct.unpack('<Q', attr_data[16:24])[0]
            
            # File attributes (4 bytes at offset 32 in standard info)
            file_attrs = struct.unpack('<I', attr_data[8:12])[0] if len(attr_data) >= 12 else 0
            
            return {
                "c_time": self._filetime_to_datetime(c_time_raw),
                "a_time": self._filetime_to_datetime(a_time_raw),
                "m_time": self._filetime_to_datetime(m_time_raw),
                "w_time": self._filetime_to_datetime(w_time_raw),
                "file_attributes": file_attrs
            }
        
        except Exception as e:
            logger.debug(f"Error parsing STANDARD_INFORMATION: {e}")
            return None
    
    def _parse_filename_attribute(self, attr_data: bytes) -> Optional[Dict]:
        r"""
        Parse $FILE_NAME attribute (filename and path info).
        
        Contains:
        - Parent directory reference (MFT record number)
        - Filename
        - File creation time
        - File size (allocated and actual)
        - File attributes
        
        Args:
            attr_data (bytes): Attribute data buffer
        
        Returns:
            Dict with filename and metadata, or None if parsing fails
        """
        
        try:
            # Skip attribute header (22 bytes)
            if len(attr_data) < 66:
                return None
            
            # Parent directory reference (8 bytes at offset 22)
            parent_ref = struct.unpack('<Q', attr_data[22:30])[0] & 0xFFFFFFFFFFFF
            
            # File creation time (at offset 30)
            c_time_raw = struct.unpack('<Q', attr_data[30:38])[0]
            
            # Filename length and namespace (at offset 64)
            filename_len = attr_data[64]
            
            # Filename (Unicode, 2 bytes per character)
            filename_start = 66
            filename_end = filename_start + (filename_len * 2)
            
            if filename_end > len(attr_data):
                return None
            
            filename_bytes = attr_data[filename_start:filename_end]
            filename = filename_bytes.decode('utf-16-le', errors='ignore')
            
            # File size (8 bytes at offset 48 and 56)
            allocated_size = struct.unpack('<Q', attr_data[48:56])[0]
            actual_size = struct.unpack('<Q', attr_data[56:64])[0]
            
            return {
                "filename": filename,
                "parent_ref": parent_ref,
                "c_time": self._filetime_to_datetime(c_time_raw),
                "allocated_size": allocated_size,
                "actual_size": actual_size
            }
        
        except Exception as e:
            logger.debug(f"Error parsing FILE_NAME: {e}")
            return None
    
    def _create_mft_event(self,
                         record_num: int,
                         in_use: bool,
                         is_directory: bool,
                         std_info: Optional[Dict],
                         file_name: Optional[Dict]) -> Optional[Event]:
        r"""
        Create forensic Event from MFT record data.
        
        Combines $STANDARD_INFORMATION and $FILE_NAME attributes into
        a single forensic event with all file system metadata.
        
        Args:
            record_num (int): MFT record number
            in_use (bool): Whether record is in-use or deleted
            is_directory (bool): Whether entry is directory or file
            std_info (Dict): Parsed STANDARD_INFORMATION
            file_name (Dict): Parsed FILE_NAME
        
        Returns:
            Event: Forensic event object, or None if no meaningful data
        """
        
        try:
            if not std_info or not file_name:
                return None
            
            # Use most recent timestamp
            timestamps = [
                std_info.get("c_time"),
                std_info.get("m_time"),
                std_info.get("a_time"),
                std_info.get("w_time")
            ]
            event_timestamp = max([t for t in timestamps if t is not None])
            
            # Determine event type
            if not in_use:
                event_type = "file_deleted"
                priority = "HIGH"
                confidence = 0.85
            elif is_directory:
                event_type = "directory_created"
                priority = "MEDIUM"
                confidence = 0.90
            else:
                event_type = "file_created"
                priority = "MEDIUM"
                confidence = 0.90
            
            # Create event
            event = Event(
                timestamp=event_timestamp,
                source_device=self.computer_name,
                source_type="MFT",
                event_type=event_type,
                user="SYSTEM",
                payload={
                    "mft_record_number": record_num,
                    "filename": file_name.get("filename"),
                    "parent_record": file_name.get("parent_ref"),
                    "is_directory": is_directory,
                    "in_use": in_use,
                    "creation_time": std_info.get("c_time"),
                    "modification_time": std_info.get("m_time"),
                    "access_time": std_info.get("a_time"),
                    "mft_write_time": std_info.get("w_time"),
                    "allocated_size": file_name.get("allocated_size", 0),
                    "actual_size": file_name.get("actual_size", 0),
                    "file_attributes": std_info.get("file_attributes", 0),
                    "partition": self.partition_letter,
                    "mft_source": self.mft_file_path
                },
                timezone_offset=self.system_timezone,
                local_timestamp=self._calculate_local_timestamp(event_timestamp, self.system_timezone),
                forensic_priority=priority,
                confidence_score=confidence,
                corruption_detected=False
            )
            
            return event
        
        except Exception as e:
            logger.debug(f"Error creating MFT event: {e}")
            return None
    
    # ============================================================================
    # === HELPER FUNCTIONS ===
    # ============================================================================
    
    def _load_mft_file(self, mft_path: str) -> Optional[bytes]:
        r"""
        Load $MFT file from disk.
        
        Args:
            mft_path (str): Full path to $MFT file
        
        Returns:
            bytes: MFT file contents, or None if load fails
        """
        
        try:
            file_path = Path(mft_path)
            
            if not file_path.is_file():
                logger.error(f"MFT file not found: {mft_path}")
                return None
            
            file_size = file_path.stat().st_size
            logger.info(f"MFT file size: {file_size:,} bytes ({file_size // 1024 // 1024} MB)")
            
            with open(mft_path, 'rb') as f:
                mft_data = f.read()
            
            if len(mft_data) < self.MFT_RECORD_SIZE:
                logger.error(f"MFT file too small: {len(mft_data)} bytes")
                return None
            
            logger.info(f"Successfully loaded MFT file: {len(mft_data):,} bytes")
            return mft_data
        
        except Exception as e:
            logger.error(f"Error loading MFT file: {e}")
            return None
    
    def _filetime_to_datetime(self, filetime_int: int) -> Optional[datetime]:
        r"""
        Convert Windows FILETIME to Python datetime.
        
        FILETIME = 100-nanosecond intervals since 1601-01-01 00:00:00 UTC
        
        Args:
            filetime_int (int): FILETIME value
        
        Returns:
            datetime: UTC datetime object, or None if conversion fails
        """
        
        if filetime_int <= 0:
            return None
        
        try:
            WINDOWS_EPOCH_DIFF = 116444736000000000
            unix_timestamp = (filetime_int - WINDOWS_EPOCH_DIFF) / 10_000_000
            dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
            return dt
        
        except Exception as e:
            logger.debug(f"FILETIME conversion failed: {e}")
            return None
    
    def _calculate_local_timestamp(self, utc_dt: datetime, offset_str: str) -> datetime:
        r"""
        Convert UTC datetime to local time using timezone offset string.
        
        Args:
            utc_dt (datetime): UTC datetime object
            offset_str (str): Timezone offset string (e.g., "UTC+5:30", "UTC-8")
        
        Returns:
            datetime: Local datetime (adjusted for timezone)
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
    
    def _get_chain_of_custody_metadata(self, mft_path: str) -> Dict:
        r"""
        Calculate cryptographic hashes and metadata for chain of custody.
        
        Args:
            mft_path (str): Full path to $MFT file
        
        Returns:
            Dict: Chain of custody metadata with SHA256 and MD5 hashes
        """
        
        try:
            file_path = Path(mft_path)
            
            if not file_path.is_file():
                return {
                    "mft_path": mft_path,
                    "error": "File not found",
                    "sha256": None,
                    "md5": None
                }
            
            file_size = file_path.stat().st_size
            logger.info(f"Calculating hashes of {mft_path} ({file_size:,} bytes)")
            
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            CHUNK_SIZE = 8192
            
            with open(mft_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            sha256_digest = sha256_hash.hexdigest()
            md5_digest = md5_hash.hexdigest()
            
            metadata = {
                "mft_path": str(mft_path),
                "mft_name": "$MFT",
                "file_size": file_size,
                "sha256": sha256_digest,
                "md5": md5_digest,
                "parse_timestamp": datetime.now(timezone.utc),
                "parser_version": "1.0.0",
                "parser_name": "EvidenceSync Pro MFT Parser"
            }
            
            logger.info(f"SHA256: {sha256_digest}")
            logger.info(f"MD5: {md5_digest}")
            
            return metadata
        
        except Exception as e:
            logger.error(f"Error calculating chain of custody: {e}")
            return {
                "mft_path": mft_path,
                "error": str(e),
                "sha256": None,
                "md5": None
            }