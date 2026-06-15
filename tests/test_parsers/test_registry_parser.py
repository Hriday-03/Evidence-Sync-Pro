r"""
Comprehensive pytest suite for EvidenceSync Pro Registry Parser
Tests Bit 1 (SAM), Bit 2 (NTUSER.DAT), and Bit 3 (SYSTEM/SOFTWARE/SECURITY)

Uses real forensic registry hives from NIST CFReDS dataset (Volume Shadow Copies):
https://cfreds-archive.nist.gov/winreg/cfreds-2017-winreg/

Windows 10 sample hives location (extracted from VSS):
C:\Users\Hriday\Project\Refrences\sample_registry\Win10_10586_IE11+Edge_(CFReDS)

Registry hive paths (extracted from /p1 VSS):
- SYSTEM: /p1/Windows/System32/config/SYSTEM
- SOFTWARE: /p1/Windows/System32/config/SOFTWARE
- SAM: /p1/Windows/System32/config/SAM
- SECURITY: /p1/Windows/System32/config/SECURITY
- NTUSER.DAT: /p1/Users/[USERNAME]/NTUSER.DAT
- USRCLASS.DAT: /p1/Users/[USERNAME]/AppData/Local/Microsoft/Windows/UsrClass.dat

Note: Bits 4 (USRCLASS.DAT/Shell Extensions) and 5 (COMPONENTS/DEFAULT)
are commented out and will be tested once those implementations are complete.
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from evidence_sync_pro.parsers.registry_parser import RegistryParser
from evidence_sync_pro.parsers.base_parser import Event


# ==============================================================================
# FIXTURES FOR NIST REGISTRY HIVES
# ==============================================================================

@pytest.fixture
def nist_registry_hive_paths():
    """
    Points to NIST Windows 10 registry hives from CFReDS dataset.
    
    Location: 0x04_reference_hive folder containing VSS snapshots
    """
    
    base_path = Path(r"C:\Users\Hriday\Project\Refrences\sample_registry\Win10_10586_IE11+Edge_(CFReDS)\0x04_reference_hive")
    
    if not base_path.exists():
        pytest.skip(f"NIST reference hive path not found: {base_path}")
    
    # Use p1 (latest/main partition snapshot)
    snapshot_path = base_path / "p1"
    system_config_path = snapshot_path / "Windows" / "System32" / "config"
    
    # Available users from the file_info.log: CFReDS, CFTT, cfttu, Default, Forensics, IEUser, sshd_server
    # IEUser has the most activity
    ieuser_path = snapshot_path / "Users" / "IEUser"
    
    hive_paths = {
        "system": str(system_config_path / "SYSTEM"),
        "software": str(system_config_path / "SOFTWARE"),
        "sam": str(system_config_path / "SAM"),
        "security": str(system_config_path / "SECURITY"),
        "ntuser_dat": str(ieuser_path / "NTUSER.DAT"),
        "usrclass_dat": str(ieuser_path / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"),
    }
    
    # Check which hives exist and report
    missing = []
    for hive_name, hive_path in hive_paths.items():
        if not Path(hive_path).exists():
            missing.append(f"{hive_name}: {hive_path}")
    
    if missing:
        print(f"\n⚠️  WARNING: Missing hives:\n" + "\n".join(missing))
        print(f"\nBase path checked: {snapshot_path}")
        print(f"Available dirs: {[d.name for d in snapshot_path.iterdir() if d.is_dir()]}")
    
    return hive_paths


@pytest.fixture
def registry_parser(nist_registry_hive_paths):
    """Initialize RegistryParser with NIST hive paths"""
    
    parser = RegistryParser(
        system_hive_path=nist_registry_hive_paths["system"],
        software_hive_path=nist_registry_hive_paths["software"],
        sam_hive_path=nist_registry_hive_paths["sam"],
        security_hive_path=nist_registry_hive_paths["security"],
        ntuser_dat_paths=[nist_registry_hive_paths["ntuser_dat"]],
        usrclass_dat_paths=[nist_registry_hive_paths["usrclass_dat"]],
        computer_name="WIN10-NIST-CFReDS",
        system_timezone="UTC+0"
    )
    
    return parser


# ==============================================================================
# BIT 1: SAM HIVE TESTS
# ==============================================================================

class TestBit1SAMExtraction:
    """Test Bit 1: SAM user account extraction"""
    
    def test_load_sam_hive(self, registry_parser, nist_registry_hive_paths):
        """Test loading SAM hive file"""
        sam_hive = registry_parser._load_hive(nist_registry_hive_paths["sam"])
        
        assert sam_hive is not None, "Should successfully load SAM hive"
        assert sam_hive.root() is not None, "SAM hive should have root key"
    
    def test_extract_user_accounts_from_sam(self, registry_parser, nist_registry_hive_paths):
        """Extract user accounts from real SAM hive"""
        sam_hive = registry_parser._load_hive(nist_registry_hive_paths["sam"])
        
        assert sam_hive is not None, "SAM hive load failed"
        
        events = registry_parser._extract_user_accounts(sam_hive)
        
        assert isinstance(events, list), "Should return list of events"
        assert len(events) > 0, "Should extract at least one user account"
        
        # Verify event structure
        for event in events:
            assert isinstance(event, Event), "Should be Event object"
            assert event.event_type == "user_account_info", "Event type should be user_account_info"
            assert event.source_type == "REGISTRY", "Source type should be REGISTRY"
            assert event.forensic_priority == "HIGH", "SAM events should be HIGH priority"
            assert event.payload.get("username") is not None, "Should have username"
            assert event.payload.get("rid") is not None, "Should have RID"
    
    def test_sam_events_have_timestamps(self, registry_parser, nist_registry_hive_paths):
        """SAM events should have valid timestamps"""
        sam_hive = registry_parser._load_hive(nist_registry_hive_paths["sam"])
        events = registry_parser._extract_user_accounts(sam_hive)
        
        assert len(events) > 0, "Should have events"
        
        for event in events:
            assert event.timestamp is not None, "Event should have timestamp"
            assert isinstance(event.timestamp, datetime), "Timestamp should be datetime"
            assert event.timezone_offset is not None, "Event should have timezone_offset"
    
    def test_sam_events_have_chain_of_custody(self, registry_parser, nist_registry_hive_paths):
        """SAM events should have chain of custody metadata"""
        sam_hive = registry_parser._load_hive(nist_registry_hive_paths["sam"])
        events = registry_parser._extract_user_accounts(sam_hive)
        
        assert len(events) > 0, "Should have events"
        
        for event in events:
            assert event.payload.get("hive_source") is not None, "Should have hive_source"
            assert event.payload.get("hive_hash_sha256") is not None, "Should have SHA256 hash"
    
    def test_sam_user_has_correct_fields(self, registry_parser, nist_registry_hive_paths):
        """Verify SAM user events have all required fields"""
        sam_hive = registry_parser._load_hive(nist_registry_hive_paths["sam"])
        events = registry_parser._extract_user_accounts(sam_hive)
        
        assert len(events) > 0, "Should have events"
        
        for event in events:
            payload = event.payload
            
            assert payload.get("username") is not None, "Should have username"
            assert payload.get("rid") is not None, "Should have RID"
            assert "last_login" in payload, "Should have last_login field"
            assert "last_password_set" in payload, "Should have last_password_set field"
            assert "failed_login_count" in payload, "Should have failed_login_count"
            assert "login_count" in payload, "Should have login_count"
            assert "account_disabled" in payload, "Should have account_disabled flag"
            assert "account_locked" in payload, "Should have account_locked flag"
    
    def test_sam_extraction_summary(self, registry_parser, nist_registry_hive_paths):
        """Print summary of SAM extraction"""
        sam_hive = registry_parser._load_hive(nist_registry_hive_paths["sam"])
        events = registry_parser._extract_user_accounts(sam_hive)
        
        print("\n" + "="*80)
        print("BIT 1: SAM USER ACCOUNT EXTRACTION SUMMARY")
        print("="*80)
        print(f"Total users extracted: {len(events)}")
        
        for event in events:
            username = event.payload.get("username", "Unknown")
            rid = event.payload.get("rid", "Unknown")
            last_login = event.payload.get("last_login", "Never")
            disabled = event.payload.get("account_disabled", False)
            
            status = "[DISABLED]" if disabled else "[ACTIVE]"
            print(f"  {status} {username:20} (RID: {rid:5}) - Last Login: {last_login}")
        
        print("="*80 + "\n")


# ==============================================================================
# BIT 2: NTUSER.DAT TESTS
# ==============================================================================

class TestBit2NTUSERDATExtraction:
    """Test Bit 2: NTUSER.DAT user activity extraction"""
    
    def test_load_ntuser_hive(self, registry_parser, nist_registry_hive_paths):
        """Test loading NTUSER.DAT hive file"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        assert ntuser_hive is not None, "Should successfully load NTUSER.DAT hive"
        assert ntuser_hive.root() is not None, "NTUSER.DAT hive should have root key"
    
    def test_extract_search_history(self, registry_parser, nist_registry_hive_paths):
        """Extract search history from RunMRU"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        assert ntuser_hive is not None, "NTUSER.DAT hive load failed"
        
        events = registry_parser._extract_search_history(ntuser_hive, "DefaultUser")
        
        assert isinstance(events, list), "Should return list of events"
        
        # May or may not have search history depending on hive
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "user_search_query", "Event type should be user_search_query"
                assert event.user == "DefaultUser", "User should match"
                assert event.forensic_priority == "HIGH", "Search history should be HIGH priority"
    
    def test_extract_typed_paths(self, registry_parser, nist_registry_hive_paths):
        """Extract typed URLs and paths"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        assert ntuser_hive is not None, "NTUSER.DAT hive load failed"
        
        events = registry_parser._extract_typed_paths(ntuser_hive, "DefaultUser")
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "typed_url_or_path", "Event type should be typed_url_or_path"
                assert event.forensic_priority == "HIGH", "Typed paths should be HIGH priority"
    
    def test_extract_recent_documents(self, registry_parser, nist_registry_hive_paths):
        """Extract recently opened files"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        assert ntuser_hive is not None, "NTUSER.DAT hive load failed"
        
        events = registry_parser._extract_recent_documents(ntuser_hive, "DefaultUser")
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "recent_document_opened", "Event type should be recent_document_opened"
                assert event.payload.get("file_path") is not None, "Should have file_path"
                assert event.payload.get("file_name") is not None, "Should have file_name"
    
    def test_extract_recent_programs(self, registry_parser, nist_registry_hive_paths):
        """Extract recently executed programs"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        assert ntuser_hive is not None, "NTUSER.DAT hive load failed"
        
        events = registry_parser._extract_recent_programs(ntuser_hive, "DefaultUser")
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "program_executed", "Event type should be program_executed"
                assert event.payload.get("command") is not None, "Should have command"
                assert event.payload.get("executable") is not None, "Should have executable"
    
    def test_extract_network_shares(self, registry_parser, nist_registry_hive_paths):
        """Extract network shares mounted"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        assert ntuser_hive is not None, "NTUSER.DAT hive load failed"
        
        events = registry_parser._extract_network_shares(ntuser_hive, "DefaultUser")
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "network_share_mounted", "Event type should be network_share_mounted"
                assert event.payload.get("unc_path") is not None, "Should have UNC path"
    
    def test_extract_user_activity_comprehensive(self, registry_parser, nist_registry_hive_paths):
        """Extract all user activity from NTUSER.DAT"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        assert ntuser_hive is not None, "NTUSER.DAT hive load failed"
        
        events = registry_parser._extract_user_activity(ntuser_hive, "DefaultUser")
        
        assert isinstance(events, list), "Should return list of events"
        # May be empty depending on hive content, but should be valid list
    
    def test_ip_extraction_from_unc_paths(self, registry_parser):
        """Test IP extraction from UNC paths"""
        
        test_cases = [
            (r"\\192.168.1.100\SecretShare", "192.168.1.100"),
            (r"\\10.0.0.5\Files\Document.docx", "10.0.0.5"),
            ("##172.16.5.50#Backup", "172.16.5.50"),
            (r"\\SERVER-NAME\Department", None),  # Hostname, not IP
            (r"C:\Users\john\Documents", None),  # Local path
            ("", None),  # Empty
            (None, None),  # None
        ]
        
        for path, expected_ip in test_cases:
            result = registry_parser._extract_ip_from_unc(path)
            assert result == expected_ip, f"Failed for {path}: expected {expected_ip}, got {result}"
    
    def test_bit2_extraction_summary(self, registry_parser, nist_registry_hive_paths):
        """Print summary of NTUSER.DAT extraction"""
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        
        print("\n" + "="*80)
        print("BIT 2: NTUSER.DAT USER ACTIVITY EXTRACTION SUMMARY")
        print("="*80)
        
        search_events = registry_parser._extract_search_history(ntuser_hive, "DefaultUser")
        typed_events = registry_parser._extract_typed_paths(ntuser_hive, "DefaultUser")
        docs_events = registry_parser._extract_recent_documents(ntuser_hive, "DefaultUser")
        prog_events = registry_parser._extract_recent_programs(ntuser_hive, "DefaultUser")
        share_events = registry_parser._extract_network_shares(ntuser_hive, "DefaultUser")
        
        print(f"Search history entries: {len(search_events)}")
        print(f"Typed paths/URLs: {len(typed_events)}")
        print(f"Recent documents: {len(docs_events)}")
        print(f"Recent programs: {len(prog_events)}")
        print(f"Network shares: {len(share_events)}")
        
        total = len(search_events) + len(typed_events) + len(docs_events) + len(prog_events) + len(share_events)
        print(f"Total user activity events: {total}")
        
        print("="*80 + "\n")


# ==============================================================================
# BIT 3: SYSTEM/SOFTWARE/SECURITY TESTS
# ==============================================================================

class TestBit3SystemExtraction:
    """Test Bit 3: System-wide registry extraction"""
    
    def test_load_system_hive(self, registry_parser, nist_registry_hive_paths):
        """Test loading SYSTEM hive file"""
        system_hive = registry_parser._load_hive(nist_registry_hive_paths["system"])
        
        assert system_hive is not None, "Should successfully load SYSTEM hive"
        assert system_hive.root() is not None, "SYSTEM hive should have root key"
    
    def test_extract_usb_timeline(self, registry_parser, nist_registry_hive_paths):
        """Extract USB device enumeration timeline"""
        system_hive = registry_parser._load_hive(nist_registry_hive_paths["system"])
        
        assert system_hive is not None, "SYSTEM hive load failed"
        
        events = registry_parser._extract_usb_timeline(system_hive)
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "usb_device_enumerated", "Event type should be usb_device_enumerated"
                assert event.forensic_priority == "HIGH", "USB timeline should be HIGH priority"
                assert event.payload.get("device_id") is not None, "Should have device_id"
                assert event.payload.get("friendly_name") is not None, "Should have friendly_name"
    
    def test_extract_network_adapters(self, registry_parser, nist_registry_hive_paths):
        """Extract network adapter configurations"""
        system_hive = registry_parser._load_hive(nist_registry_hive_paths["system"])
        
        assert system_hive is not None, "SYSTEM hive load failed"
        
        events = registry_parser._extract_network_adapters(system_hive)
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "network_adapter_config", "Event type should be network_adapter_config"
                assert event.payload.get("adapter_guid") is not None, "Should have adapter_guid"
    
    def test_extract_services(self, registry_parser, nist_registry_hive_paths):
        """Extract Windows services configuration"""
        system_hive = registry_parser._load_hive(nist_registry_hive_paths["system"])
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        
        assert system_hive is not None, "SYSTEM hive load failed"
        assert software_hive is not None, "SOFTWARE hive load failed"
        
        events = registry_parser._extract_services(software_hive, system_hive)
        
        assert isinstance(events, list), "Should return list of events"
        assert len(events) > 0, "Should extract at least some services"
        
        for event in events:
            assert isinstance(event, Event), "Should be Event object"
            assert event.event_type == "service_configured", "Event type should be service_configured"
            assert event.payload.get("service_name") is not None, "Should have service_name"
            assert "suspicious_score" in event.payload, "Should have suspicious_score"
    
    def test_load_software_hive(self, registry_parser, nist_registry_hive_paths):
        """Test loading SOFTWARE hive file"""
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        
        assert software_hive is not None, "Should successfully load SOFTWARE hive"
        assert software_hive.root() is not None, "SOFTWARE hive should have root key"
    
    def test_extract_installed_programs(self, registry_parser, nist_registry_hive_paths):
        """Extract installed programs list"""
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        
        assert software_hive is not None, "SOFTWARE hive load failed"
        
        events = registry_parser._extract_installed_programs(software_hive)
        
        assert isinstance(events, list), "Should return list of events"
        assert len(events) > 0, "Should extract at least some programs"
        
        for event in events:
            assert isinstance(event, Event), "Should be Event object"
            assert event.event_type == "program_installed", "Event type should be program_installed"
            assert event.payload.get("program_name") is not None, "Should have program_name"
            assert event.payload.get("version") is not None, "Should have version"
    
    def test_extract_startup_programs(self, registry_parser, nist_registry_hive_paths):
        """Extract startup programs (persistence mechanisms)"""
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        
        assert software_hive is not None, "SOFTWARE hive load failed"
        
        events = registry_parser._extract_startup_programs(software_hive)
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "startup_program_configured", "Event type should be startup_program_configured"
                assert event.payload.get("command") is not None, "Should have command"
                assert "suspicious_score" in event.payload, "Should have suspicious_score"
    
    def test_extract_browser_helper_objects(self, registry_parser, nist_registry_hive_paths):
        """Extract Browser Helper Objects (BHO)"""
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        
        assert software_hive is not None, "SOFTWARE hive load failed"
        
        events = registry_parser._extract_browser_helper_objects(software_hive)
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "browser_helper_object_installed", "Event type should be browser_helper_object_installed"
                assert event.payload.get("bho_clsid") is not None, "Should have BHO CLSID"
                assert "suspicious_score" in event.payload, "Should have suspicious_score"
    
    def test_load_security_hive(self, registry_parser, nist_registry_hive_paths):
        """Test loading SECURITY hive file"""
        security_hive = registry_parser._load_hive(nist_registry_hive_paths["security"])
        
        assert security_hive is not None, "Should successfully load SECURITY hive"
        assert security_hive.root() is not None, "SECURITY hive should have root key"
    
    def test_extract_lsa_secrets(self, registry_parser, nist_registry_hive_paths):
        """Extract LSA secrets (credential storage)"""
        security_hive = registry_parser._load_hive(nist_registry_hive_paths["security"])
        
        assert security_hive is not None, "SECURITY hive load failed"
        
        events = registry_parser._extract_lsa_secrets(security_hive)
        
        assert isinstance(events, list), "Should return list of events"
        
        if events:
            for event in events:
                assert isinstance(event, Event), "Should be Event object"
                assert event.event_type == "lsa_secret_found", "Event type should be lsa_secret_found"
                assert event.forensic_priority == "HIGH", "LSA secrets should be HIGH priority"
                assert event.payload.get("secret_name") is not None, "Should have secret_name"
                assert "secret_type" in event.payload, "Should have secret_type"
    
    def test_extract_system_info_comprehensive(self, registry_parser, nist_registry_hive_paths):
        """Extract all system information (Bit 3 comprehensive)"""
        system_hive = registry_parser._load_hive(nist_registry_hive_paths["system"])
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        security_hive = registry_parser._load_hive(nist_registry_hive_paths["security"])
        
        assert system_hive is not None, "SYSTEM hive load failed"
        assert software_hive is not None, "SOFTWARE hive load failed"
        assert security_hive is not None, "SECURITY hive load failed"
        
        events = registry_parser._extract_system_info(system_hive, software_hive, security_hive)
        
        assert isinstance(events, list), "Should return list of events"
        assert len(events) > 10, "Should extract at least 10+ events from all sources"
    
    def test_chain_of_custody_metadata(self, registry_parser, nist_registry_hive_paths):
        """Verify chain of custody metadata for all hives"""
        
        hives_to_check = [
            ("SYSTEM", nist_registry_hive_paths["system"]),
            ("SOFTWARE", nist_registry_hive_paths["software"]),
            ("SAM", nist_registry_hive_paths["sam"]),
            ("SECURITY", nist_registry_hive_paths["security"]),
        ]
        
        for hive_name, hive_path in hives_to_check:
            metadata = registry_parser._get_chain_of_custody_metadata(hive_path)
            
            assert metadata is not None, f"Should get metadata for {hive_name}"
            assert metadata.get("sha256") is not None, f"{hive_name} should have SHA256 hash"
            assert metadata.get("md5") is not None, f"{hive_name} should have MD5 hash"
            assert metadata.get("file_size") is not None, f"{hive_name} should have file size"
            
            print(f"\n{hive_name} Chain of Custody:")
            print(f"  SHA256: {metadata['sha256']}")
            print(f"  MD5:    {metadata['md5']}")
            print(f"  Size:   {metadata['file_size']} bytes")
    
    def test_bit3_extraction_summary(self, registry_parser, nist_registry_hive_paths):
        """Print comprehensive summary of Bit 3 extraction"""
        
        system_hive = registry_parser._load_hive(nist_registry_hive_paths["system"])
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        security_hive = registry_parser._load_hive(nist_registry_hive_paths["security"])
        
        print("\n" + "="*80)
        print("BIT 3: SYSTEM-WIDE REGISTRY EXTRACTION SUMMARY")
        print("="*80)
        
        # SYSTEM hive
        usb_events = registry_parser._extract_usb_timeline(system_hive)
        net_events = registry_parser._extract_network_adapters(system_hive)
        
        print("\nSYSTEM Hive:")
        print(f"  USB devices: {len(usb_events)}")
        print(f"  Network adapters: {len(net_events)}")
        
        # SOFTWARE hive
        prog_events = registry_parser._extract_installed_programs(software_hive)
        startup_events = registry_parser._extract_startup_programs(software_hive)
        bho_events = registry_parser._extract_browser_helper_objects(software_hive)
        service_events = registry_parser._extract_services(software_hive, system_hive)
        
        print("\nSOFTWARE Hive:")
        print(f"  Installed programs: {len(prog_events)}")
        print(f"  Startup programs: {len(startup_events)}")
        print(f"  Browser Helper Objects: {len(bho_events)}")
        print(f"  Services: {len(service_events)}")
        
        # SECURITY hive
        lsa_events = registry_parser._extract_lsa_secrets(security_hive)
        
        print("\nSECURITY Hive:")
        print(f"  LSA secrets: {len(lsa_events)}")
        
        total_bit3 = (len(usb_events) + len(net_events) + len(prog_events) + 
                      len(startup_events) + len(bho_events) + len(service_events) + 
                      len(lsa_events))
        
        print(f"\nTotal Bit 3 events: {total_bit3}")
        print("="*80 + "\n")


# ==============================================================================
# BIT 4: USRCLASS.DAT TESTS
# ==============================================================================

class TestBit4USRCLASSExtraction:
    """
    Test Bit 4:
    - Shell Extensions
    - File Associations
    """

    def test_load_usrclass_hive(
        self,
        registry_parser,
        nist_registry_hive_paths
    ):
        """Test loading USRCLASS.DAT"""

        usrclass_hive = registry_parser._load_hive(
            nist_registry_hive_paths["usrclass_dat"]
        )

        assert usrclass_hive is not None
        assert usrclass_hive.root() is not None

    def test_extract_shell_extensions(
        self,
        registry_parser,
        nist_registry_hive_paths
    ):
        """Extract shell extensions"""

        usrclass_hive = registry_parser._load_hive(
            nist_registry_hive_paths["usrclass_dat"]
        )

        events = registry_parser._extract_shell_extensions(
            usrclass_hive,
            "IEUser"
        )

        assert isinstance(events, list)

        if events:
            for event in events:

                assert isinstance(event, Event)

                assert (
                    event.event_type
                    == "shell_extension_registered"
                )

                assert (
                    event.payload.get(
                        "extension_guid"
                    ) is not None
                )

                assert (
                    "suspicious_score"
                    in event.payload
                )

                assert (
                    event.forensic_priority
                    == "MEDIUM"
                )

    def test_extract_file_associations(
        self,
        registry_parser,
        nist_registry_hive_paths
    ):
        """Extract file associations"""

        usrclass_hive = registry_parser._load_hive(
            nist_registry_hive_paths["usrclass_dat"]
        )

        events = registry_parser._extract_file_associations(
            usrclass_hive,
            "IEUser"
        )

        assert isinstance(events, list)

        if events:

            for event in events:

                assert isinstance(event, Event)

                assert (
                    event.event_type
                    == "file_association_modified"
                )

                assert (
                    event.payload.get(
                        "extension"
                    ) is not None
                )

                assert (
                    "associated_program"
                    in event.payload
                )

                assert (
                    event.forensic_priority
                    == "MEDIUM"
                )

    def test_extract_usrclass_comprehensive(
        self,
        registry_parser,
        nist_registry_hive_paths
    ):
        """Run all USRCLASS extraction"""

        usrclass_hive = registry_parser._load_hive(
            nist_registry_hive_paths["usrclass_dat"]
        )

        shell_events = (
            registry_parser._extract_shell_extensions(
                usrclass_hive,
                "IEUser"
            )
        )

        assoc_events = (
            registry_parser._extract_file_associations(
                usrclass_hive,
                "IEUser"
            )
        )

        all_events = shell_events + assoc_events

        assert isinstance(all_events, list)

    def test_bit4_extraction_summary(
        self,
        registry_parser,
        nist_registry_hive_paths
    ):
        """Print Bit 4 summary"""

        usrclass_hive = registry_parser._load_hive(
            nist_registry_hive_paths["usrclass_dat"]
        )

        shell_events = (
            registry_parser._extract_shell_extensions(
                usrclass_hive,
                "IEUser"
            )
        )

        assoc_events = (
            registry_parser._extract_file_associations(
                usrclass_hive,
                "IEUser"
            )
        )

        print("\n" + "=" * 80)
        print("BIT 4: USRCLASS.DAT EXTRACTION SUMMARY")
        print("=" * 80)

        print(
            f"Shell Extensions: {len(shell_events)}"
        )

        print(
            f"File Associations: {len(assoc_events)}"
        )

        print(
            f"Total Bit 4 Events: "
            f"{len(shell_events)+len(assoc_events)}"
        )

        print("=" * 80 + "\n")

# ==============================================================================
# INTEGRATION TESTS: ALL BITS TOGETHER
# ==============================================================================

class TestIntegrationAllBits:
    """Integration tests combining Bits 1, 2, and 3"""
    
    def test_all_hives_load_successfully(self, registry_parser, nist_registry_hive_paths):
        """Verify all hives can be loaded"""
        
        hives = {
            "SYSTEM": nist_registry_hive_paths["system"],
            "SOFTWARE": nist_registry_hive_paths["software"],
            "SAM": nist_registry_hive_paths["sam"],
            "SECURITY": nist_registry_hive_paths["security"],
            "NTUSER.DAT": nist_registry_hive_paths["ntuser_dat"],
            "USRCLASS.DAT": nist_registry_hive_paths["usrclass_dat"]
        }
        
        for hive_name, hive_path in hives.items():
            hive = registry_parser._load_hive(hive_path)
            assert hive is not None, f"Should load {hive_name} hive"
            print(f"✓ {hive_name} loaded successfully")
    
    def test_comprehensive_extraction(self, registry_parser, nist_registry_hive_paths):
        """Run full extraction across all bits"""
        
        print("\n" + "="*80)
        print("COMPREHENSIVE EXTRACTION TEST: BITS 1-3")
        print("="*80)
        
        # Load all hives
        system_hive = registry_parser._load_hive(nist_registry_hive_paths["system"])
        software_hive = registry_parser._load_hive(nist_registry_hive_paths["software"])
        sam_hive = registry_parser._load_hive(nist_registry_hive_paths["sam"])
        security_hive = registry_parser._load_hive(nist_registry_hive_paths["security"])
        ntuser_hive = registry_parser._load_hive(nist_registry_hive_paths["ntuser_dat"])
        usrclass_hive = registry_parser._load_hive(nist_registry_hive_paths["usrclass_dat"])
        
        all_events = []
        
        # Bit 1: SAM
        print("\n[Bit 1] Extracting user accounts from SAM...")
        sam_events = registry_parser._extract_user_accounts(sam_hive)
        all_events.extend(sam_events)
        print(f"  ✓ Extracted {len(sam_events)} user account events")
        
        # Bit 2: NTUSER.DAT
        print("\n[Bit 2] Extracting user activity from NTUSER.DAT...")
        ntuser_events = registry_parser._extract_user_activity(ntuser_hive, "DefaultUser")
        all_events.extend(ntuser_events)
        print(f"  ✓ Extracted {len(ntuser_events)} user activity events")
        
        # Bit 3: SYSTEM/SOFTWARE/SECURITY
        print("\n[Bit 3] Extracting system-wide artifacts...")
        system_events = registry_parser._extract_system_info(system_hive, software_hive, security_hive)
        all_events.extend(system_events)
        print(f"  ✓ Extracted {len(system_events)} system-wide events")

        print("\n[Bit 4] Extracting USRCLASS artifacts...")

        shell_events = registry_parser._extract_shell_extensions(usrclass_hive,"IEUser")
        assoc_events = registry_parser._extract_file_associations(usrclass_hive,"IEUser")
        bit4_events = shell_events + assoc_events
        all_events.extend(bit4_events)
        print(f"  ✓ Extracted {len(bit4_events)} USRCLASS events")
        
        # Final summary
        print("\n" + "-"*80)
        print(f"TOTAL EVENTS EXTRACTED: {len(all_events)}")
        print("-"*80)
        print(f"  Bit 1 (SAM):                    {len(sam_events):4} events")
        print(f"  Bit 2 (NTUSER.DAT):             {len(ntuser_events):4} events")
        print(f"  Bit 3 (SYSTEM/SOFTWARE/SEC):    {len(system_events):4} events")
        print("="*80 + "\n")
        
        # Verify all events are valid
        assert len(all_events) > 0, "Should extract at least some events"
        
        for event in all_events:
            assert isinstance(event, Event), f"Invalid event: {event}"
            assert event.timestamp is not None, "Event should have timestamp"
            assert event.source_device is not None, "Event should have source_device"
            assert event.event_type is not None, "Event should have event_type"


# ==============================================================================
# HELPER TESTS
# ==============================================================================

class TestHelperFunctions:
    """Test helper functions"""
    
    def test_convert_start_type(self, registry_parser):
        """Test service start type conversion"""
        
        test_cases = [
            (0, "Boot"),
            (1, "System"),
            (2, "Auto"),
            (3, "Manual"),
            (4, "Disabled"),
            (999, "Unknown (999)"),
        ]
        
        for start_value, expected in test_cases:
            result = registry_parser._convert_start_type(start_value)
            assert result == expected, f"Start type {start_value}: expected {expected}, got {result}"
    
    def test_convert_service_type(self, registry_parser):
        """Test service type conversion"""
        
        test_cases = [
            (1, "Kernel Driver"),
            (16, "Win32 Service"),
            (32, "Win32 Service (shared)"),
            (999, "Unknown (999)"),
        ]
        
        for type_value, expected in test_cases:
            result = registry_parser._convert_service_type(type_value)
            assert result == expected, f"Service type {type_value}: expected {expected}, got {result}"
    
    def test_categorize_secret(self, registry_parser):
        """Test LSA secret categorization"""
        
        test_cases = [
            ("ASPNET_WP_PASSWORD", "service_password"),
            ("DefaultPassword", "cached_credential"),
            ("DPAPI_SYSTEM", "encryption_key"),
            ("NL$KM", "encryption_key"),
            ("UnknownSecret", "other"),
        ]
        
        for secret_name, expected in test_cases:
            result = registry_parser._categorize_secret(secret_name)
            assert result == expected, f"Secret {secret_name}: expected {expected}, got {result}"
    
    def test_extract_executable_path(self, registry_parser):
        """Test executable path extraction from command line"""
        
        test_cases = [
            ("C:\\Program Files\\App\\app.exe", "C:\\Program Files\\App\\app.exe"),
            ("C:\\Program Files\\App\\app.exe /param1 /param2", "C:\\Program Files\\App\\app.exe"),
            ('"C:\\Program Files\\App\\app.exe" /param', "C:\\Program Files\\App\\app.exe"),
            ("notepad.exe", "notepad.exe"),
            ('notepad.exe "C:\\file.txt"', "notepad.exe"),
        ]
        
        for command, expected in test_cases:
            result = registry_parser._extract_executable_path(command)
            assert result == expected, f"Command {command}: expected {expected}, got {result}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])