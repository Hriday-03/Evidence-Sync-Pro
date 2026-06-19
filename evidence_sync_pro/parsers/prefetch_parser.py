from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from .base_parser import BaseParser, Event
import hashlib
from loguru import logger
import struct

class PrefetchParser(BaseParser):
    r"""
    Windows Prefetch Parser - Program Execution History.
    
    Prefetch files (.pf) are created by Windows to optimize application startup
    performance. Each .pf file contains a record of:
    - Program execution timestamps
    - DLL dependencies
    - Pages accessed during execution
    - File system paths accessed
    - Execution counts and frequency
    
    Forensic Significance:
    - Definitive proof of program execution
    - Last execution time (FILETIME format)
    - Execution run count
    - Network connections (UAC, network service info)
    - File/registry access patterns
    - Timestamps remain even after file deletion
    
    Prefetch Structure:
    - Header (84 bytes in Vista+)
    - Metrics array (variable)
    - Strings array (filenames and DLLs)
    - Execution times (8-byte FILETIME values)
    - Footer with run count and timestamps
    
    Location: C:\Windows\Prefetch\*.pf
    Size: Typically 4-32 KB per file
    Retention: Up to 128 most recent programs (configurable)
    Format Versions: XP/2003, Vista/2008, Win7, Win8+, Win10+
    
    Key Forensic Points:
    - Each execution adds a timestamp
    - Last modification = last execution time
    - Run count = total executions
    - Defragmentation tool names persist in prefetch records
    - Even disabled prefetch keeps historical data in memory
    """
    
    # Prefetch Constants
    PREFETCH_SIGNATURE = b'SCCA'
    PREFETCH_VERSION_XP = 17
    PREFETCH_VERSION_VISTA = 23
    PREFETCH_VERSION_WIN7 = 23
    PREFETCH_VERSION_WIN8 = 26
    PREFETCH_VERSION_WIN10 = 30
    PREFETCH_COMPRESSED_SIGNATURE = b'MAM\x04'
    
    def __init__(self,
                 prefetch_dir_path: str,
                 computer_name: str = "UNKNOWN_HOST",
                 system_timezone: str = "UTC+0"):
        r"""
        Initialize PrefetchParser with Prefetch directory path.
        
        Args:
            prefetch_dir_path (str): Path to C:\Windows\Prefetch directory
            computer_name (str): Computer name for forensic event tracking
            system_timezone (str): System timezone offset (e.g., "UTC+5:30", "UTC-8")
        
        Returns:
            None (initializes parser instance)
        """
        
        self.prefetch_dir_path = prefetch_dir_path
        self.computer_name = computer_name
        self.system_timezone = system_timezone
        
        # Parser state
        self.prefetch_files_found = 0
        self.prefetch_files_parsed = 0
        self.execution_records = 0
        
        self.corruption_log: List[Dict[str, Any]] = []
        self.events_count = 0
    
    def parse(self) -> List[Event]:
        r"""
        Main entry point: discover and parse all Prefetch files.
        
        Orchestrates complete parsing workflow:
        1. Discover all .pf files in Prefetch directory
        2. Load and validate each Prefetch file
        3. Parse Prefetch structure and extract execution history
        4. Create forensic Event for each program execution
        5. Return consolidated list of all execution events
        
        Args:
            None (uses self.prefetch_dir_path)
        
        Returns:
            List[Event]: All extracted program execution events
        """
        
        all_events = []
        
        try:
            logger.info("="*80)
            logger.info("PREFETCH PARSER - STARTING EXTRACTION")
            logger.info("="*80)
            
            # Discover Prefetch files
            logger.info(f"\nDiscovering Prefetch files in: {self.prefetch_dir_path}")
            prefetch_files = self._discover_prefetch_files(self.prefetch_dir_path)
            
            self.prefetch_files_found = len(prefetch_files)
            logger.info(f"  ✓ Found {self.prefetch_files_found} Prefetch files")
            
            if self.prefetch_files_found == 0:
                logger.warning("No Prefetch files found")
                return []
            
            # === STEP 1: PARSE EACH PREFETCH FILE ===
            logger.info(f"\n[Step 1] Parsing {self.prefetch_files_found} Prefetch files...")
            
            for pf_file in prefetch_files:
                try:
                    # Parse single Prefetch file
                    file_events = self._parse_prefetch_file(pf_file)
                    all_events.extend(file_events)
                    self.prefetch_files_parsed += 1
                
                except Exception as e:
                    logger.warning(f"Error parsing {pf_file.name}: {e}")
                    self.corruption_log.append({
                        "error": str(e),
                        "stage": "prefetch_file_parsing",
                        "filename": pf_file.name
                    })
                    continue
            
            # === FINAL SUMMARY ===
            logger.info("\n" + "="*80)
            logger.info("PREFETCH PARSER EXTRACTION COMPLETE")
            logger.info("="*80)
            logger.info(f"Total Prefetch files found: {self.prefetch_files_found}")
            logger.info(f"Prefetch files parsed successfully: {self.prefetch_files_parsed}")
            logger.info(f"Total program execution events: {len(all_events)}")
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
    # === PREFETCH FILE DISCOVERY ===
    # ============================================================================
    
    def _discover_prefetch_files(self, prefetch_dir: str) -> List[Path]:
        try:
            prefetch_path = Path(prefetch_dir)
            if not prefetch_path.is_dir():
                logger.error(f"Prefetch directory not found: {prefetch_dir}")
                return []
            
            # Use a set comprehension to completely prevent duplicate counts across filesystems
            pf_files = {p.resolve() for p in prefetch_path.iterdir() if p.suffix.lower() == '.pf'}
            return sorted(list(pf_files))
        except Exception as e:
            logger.error(f"Error discovering Prefetch files: {e}")
            return []

    # ============================================================================
    # === PREFETCH FILE PARSING ===
    # ============================================================================
    
    def _parse_prefetch_file(self, pf_file_path: Path) -> List[Event]:
        r"""
        Parse single Prefetch file and extract execution history.
        
        Prefetch structure (Win7+):
        - Bytes 0-3: Signature 'SCCA'
        - Bytes 4-7: Version (23 for Win7, 26 for Win8, 30 for Win10+)
        - Bytes 8-83: File size and offsets
        - Bytes 84+: Metrics and strings sections
        - EOF: Execution times and run count
        
        Args:
            pf_file_path (Path): Path to .pf file
        
        Returns:
            List[Event]: All execution events from this Prefetch file
        """
        
        events = []
        
        try:
            # Load file
            pf_data = self._load_prefetch_file(pf_file_path)
            
            if pf_data is None:
                return []
            
            # Check for MAM compression and decompress using native ntdll API
            if pf_data[0:4] == self.PREFETCH_COMPRESSED_SIGNATURE:
                try:
                    import ctypes
                    from ctypes import wintypes

                    ntdll = ctypes.windll.ntdll
                    RtlDecompressBuffer = ntdll.RtlDecompressBuffer
                    RtlDecompressBuffer.argtypes = [
                        wintypes.USHORT, # CompressionFormat
                        ctypes.c_void_p, # UncompressedBuffer
                        wintypes.ULONG,  # UncompressedBufferSize
                        ctypes.c_void_p, # CompressedBuffer
                        wintypes.ULONG,  # CompressedBufferSize
                        ctypes.POINTER(wintypes.ULONG) # FinalUncompressedSize
                    ]

                    uncompressed_size = struct.unpack('<I', pf_data[4:8])[0]
                    compressed_data = pf_data[8:]
                    
                    uncompressed_buf = ctypes.create_string_buffer(uncompressed_size)
                    final_size = wintypes.ULONG(0)
                    
                    status = RtlDecompressBuffer(
                        0x0004,  # COMPRESSION_FORMAT_XPRESS_HUFFMAN
                        uncompressed_buf,
                        uncompressed_size,
                        compressed_data,
                        len(compressed_data),
                        ctypes.byref(final_size)
                    )
                    
                    if status == 0:
                        pf_data = uncompressed_buf.raw[:final_size.value]
                    else:
                        logger.warning(f"ntdll decompression failed with NTSTATUS: {hex(status & 0xffffffff)} for {pf_file_path.name}")
                        return []
                        
                except Exception as decompress_err:
                    logger.warning(f"Decompression exception for {pf_file_path.name}: {decompress_err}")
                    return []

            # === DYNAMIC HEADER ROUTING ===
            magic_0_4 = pf_data[0:4]
            magic_4_8 = pf_data[4:8]

            if magic_0_4 == self.PREFETCH_SIGNATURE:
                # Layout for Windows Vista, 7, 8, 10, 11 (Signature at 0, Version at 4)
                version = struct.unpack('<I', magic_4_8)[0]
            elif magic_4_8 == self.PREFETCH_SIGNATURE:
                # Layout for Windows XP / Server 2003 (Version at 0, Signature at 4)
                version = struct.unpack('<I', magic_0_4)[0]
            else:
                logger.warning(f"Invalid or unrecognized Prefetch signature for {pf_file_path.name}")
                return []

            logger.debug(f"Prefetch file {pf_file_path.name}: version {version}")
            
            # Parse based on version
            if version == self.PREFETCH_VERSION_XP:
                events = self._parse_prefetch_xp(pf_file_path, pf_data)
            elif version == self.PREFETCH_VERSION_VISTA or version == self.PREFETCH_VERSION_WIN7:
                events = self._parse_prefetch_vista_win7(pf_file_path, pf_data)
            elif version == self.PREFETCH_VERSION_WIN8:
                events = self._parse_prefetch_win8(pf_file_path, pf_data)
            elif version == self.PREFETCH_VERSION_WIN10:
                events = self._parse_prefetch_win10(pf_file_path, pf_data)
            else:
                logger.warning(f"Unknown Prefetch version: {version}")
                return []
            
            return events
        
        except Exception as e:
            logger.warning(f"Error parsing {pf_file_path.name}: {e}")
            return []

    def _parse_prefetch_xp(self, pf_file_path: Path, pf_data: bytes) -> List[Event]:
        r"""
        Parse Prefetch file format for Windows XP / Server 2003 (version 17).
        
        Args:
            pf_file_path (Path): Path to .pf file
            pf_data (bytes): Full Prefetch file data
        
        Returns:
            List[Event]: Execution events extracted from legacy Prefetch file
        """
        events = []
        
        try:
            program_name = self._extract_program_name(pf_file_path)
            
            # Windows XP Specification:
            # Run count is stored inside the File Info structure at absolute offset 120 (0x78)
            run_count = struct.unpack('<I', pf_data[120:124])[0]
            
            # Last execution FILETIME timestamp is located at absolute offset 124 (0x7C)
            exec_time = self._filetime_to_datetime(pf_data[124:132])
            
            if exec_time:
                events.append(self._create_forensic_event(pf_file_path, program_name, exec_time, run_count, 17))
                self.events_count += 1
        
        except Exception as e:
            logger.warning(f"Error parsing Windows XP Prefetch: {e}")
            
        return events
    
    def _parse_prefetch_vista_win7(self, pf_file_path: Path, pf_data: bytes) -> List[Event]:
        r"""
        Parse Prefetch file format for Vista/Win7 (version 23).
        
        Args:
            pf_file_path (Path): Path to .pf file
            pf_data (bytes): Full Prefetch file data
        
        Returns:
            List[Event]: Execution events extracted from Prefetch
        """
        
        events = []
        
        try:
            program_name = self._extract_program_name(pf_file_path)
            
            # Windows Vista/7 Specification:
            # Run count is stored inside the File Info structure at absolute offset 0xD4 (212)
            run_count = struct.unpack('<I', pf_data[212:216])[0]
            
            # The last execution FILETIME timestamp is located at absolute offset 0x5C (92)
            exec_time = self._filetime_to_datetime(pf_data[92:100])
            
            if exec_time:
                events.append(self._create_forensic_event(pf_file_path, program_name, exec_time, run_count, 23))
                self.events_count += 1
        
        except Exception as e:
            logger.warning(f"Error parsing Vista/Win7 Prefetch: {e}")
        
        return events
    
    def _parse_prefetch_win8(self, pf_file_path: Path, pf_data: bytes) -> List[Event]:
        r"""
        Parse Prefetch file format for Win8 (version 26).
        
        Similar to Vista/Win7 but with improved structure.
        
        Args:
            pf_file_path (Path): Path to .pf file
            pf_data (bytes): Full Prefetch file data
        
        Returns:
            List[Event]: Execution events extracted from Prefetch
        """
        
        events = []
        
        try:
            program_name = self._extract_program_name(pf_file_path)
            
            # Run count is stored inside the File Info block at absolute offset 0xCC (204)
            run_count = struct.unpack('<I', pf_data[204:208])[0]
            
            # Read the absolute structural pointer for the Last Execution Time Array
            # It is located at absolute byte offset 80 (4 bytes)
            exec_array_offset = struct.unpack('<I', pf_data[80:84])[0]
            
            # Win8 tracks up to 8 executions consecutively
            for i in range(8):
                start = exec_array_offset + (i * 8)
                if start + 8 <= len(pf_data):
                    exec_time = self._filetime_to_datetime(pf_data[start:start+8])
                    if exec_time:
                        events.append(self._create_forensic_event(pf_file_path, program_name, exec_time, run_count, 26))
                    self.events_count += 1
        
        except Exception as e:
            logger.warning(f"Error parsing Win8 Prefetch: {e}")
        
        return events
    
    def _parse_prefetch_win10(self, pf_file_path: Path, pf_data: bytes) -> List[Event]:
        r"""
        Parse Prefetch file format for Win10+ (version 30).
        
        Win10 format includes detailed execution timeline.
        
        Args:
            pf_file_path (Path): Path to .pf file
            pf_data (bytes): Full Prefetch file data
        
        Returns:
            List[Event]: Execution events extracted from Prefetch
        """
        
        events = []
        
        try:
            program_name = self._extract_program_name(pf_file_path)
            
            # Run count is stored inside the File Info block at absolute offset 0xD0 (208)
            run_count = struct.unpack('<I', pf_data[208:212])[0]
            
            # Read the absolute structural pointer for the Last Execution Time Array
            # For Windows 10/11, this pointer is located at absolute byte offset 128 (4 bytes)
            exec_array_offset = struct.unpack('<I', pf_data[128:132])[0]
            
            # Win10 tracks up to 8 individual execution history events
            for i in range(8):
                start = exec_array_offset + (i * 8)
                if start + 8 <= len(pf_data):
                    exec_time = self._filetime_to_datetime(pf_data[start:start+8])
                    if exec_time:
                        events.append(self._create_forensic_event(pf_file_path, program_name, exec_time, run_count, 30))
                    self.events_count += 1
        
        except Exception as e:
            logger.warning(f"Error parsing Win10 Prefetch: {e}")
        
        return events
    
    # ============================================================================
    # === HELPER FUNCTIONS ===
    # ============================================================================
    
    def _extract_program_name(self, pf_file_path: Path) -> str:
        pf_name = pf_file_path.stem
        parts = pf_name.split('-')
        return parts[0] if parts else "UNKNOWN"

    def _create_forensic_event(self, pf_file_path: Path, program_name: str, 
                               exec_time: datetime, run_count: int, version: int) -> Event:
        self.events_count += 1
        return Event(
            timestamp=exec_time,
            source_device=self.computer_name,
            source_type="PREFETCH",
            event_type="program_executed",
            user="SYSTEM",
            payload={
                "program_name": program_name,
                "executable": program_name,
                "last_execution": exec_time,
                "run_count": run_count,
                "prefetch_version": version,
                "prefetch_file": pf_file_path.name,
                "prefetch_source": str(pf_file_path)
            },
            timezone_offset=self.system_timezone,
            local_timestamp=self._calculate_local_timestamp(exec_time, self.system_timezone),
            forensic_priority="HIGH",
            confidence_score=0.95,
            corruption_detected=False
        )

    def _load_prefetch_file(self, pf_file_path: Path) -> Optional[bytes]:
        r"""
        Load Prefetch file from disk.
        
        Args:
            pf_file_path (Path): Full path to .pf file
        
        Returns:
            bytes: Prefetch file contents, or None if load fails
        """
        
        try:
            if not pf_file_path.is_file():
                logger.debug(f"Prefetch file not found: {pf_file_path}")
                return None
            
            with open(pf_file_path, 'rb') as f:
                pf_data = f.read()
            
            if len(pf_data) < 84:
                logger.debug(f"Prefetch file too small: {len(pf_data)} bytes")
                return None
            
            logger.debug(f"Loaded Prefetch file: {pf_file_path.name} ({len(pf_data)} bytes)")
            return pf_data
        
        except Exception as e:
            logger.debug(f"Error loading Prefetch file {pf_file_path.name}: {e}")
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
    
    def _filetime_to_datetime(self, filetime_bytes: bytes) -> Optional[datetime]:
        """Convert standard 8-byte Windows FILETIME structure to UTC datetime."""
        try:
            val = struct.unpack('<Q', filetime_bytes)[0]
            if val == 0:
                return None
            # FILETIME: 100-nanosecond intervals since January 1, 1601
            us = (val - 116444736000000000) // 10
            return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
        except Exception:
            return None

    def _get_chain_of_custody_metadata(self, pf_file_path: Path) -> Dict:
        r"""
        Calculate cryptographic hashes for chain of custody documentation.
        
        Args:
            pf_file_path (Path): Full path to .pf file
        
        Returns:
            Dict: Chain of custody metadata with SHA256 and MD5 hashes
        """
        
        try:
            if not pf_file_path.is_file():
                return {
                    "prefetch_path": str(pf_file_path),
                    "error": "File not found",
                    "sha256": None,
                    "md5": None
                }
            
            file_size = pf_file_path.stat().st_size
            logger.debug(f"Calculating hashes of {pf_file_path.name}")
            
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            with open(pf_file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return {
                "prefetch_file": pf_file_path.name,
                "file_size": file_size,
                "sha256": sha256_hash.hexdigest(),
                "md5": md5_hash.hexdigest(),
                "parse_timestamp": datetime.now(timezone.utc),
                "parser_version": "1.0.0"
            }
        
        except Exception as e:
            logger.error(f"Error calculating hashes: {e}")
            return {
                "prefetch_path": str(pf_file_path),
                "error": str(e)
            }
