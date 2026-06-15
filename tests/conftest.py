"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path
from datetime import datetime
from evidence_sync_pro.parsers.base_parser import Event
from unittest.mock import Mock
import struct



@pytest.fixture
def sample_event():
    """Fixture: a sample normalized event."""
    return Event(
        timestamp=datetime(2024, 1, 15, 14, 23, 45),
        source_device="DESKTOP-ABC123",
        source_type="EVTX",
        event_type="login",
        user="john.doe",
        payload={"ip_address": "192.168.1.100", "logon_type": 3},
        timezone_offset="UTC-5"
    )


@pytest.fixture
def test_data_dir():
    """Fixture: path to test data directory."""
    return Path(__file__).parent / "test_data"


# ==============================================================================
# MOCK REGISTRY FIXTURES (for RegistryParser tests)
# ==============================================================================

@pytest.fixture
def mock_registry_value():
    """Create a mock registry value object."""
    mock_value = Mock()
    mock_value.name.return_value = "TestValue"
    mock_value.value.return_value = "TestData"
    mock_value.value_type.return_value = 1000  # RID
    return mock_value


@pytest.fixture
def mock_registry_key_with_users():
    """
    Create a mock registry key with SAM user data.
    
    Structure:
    Users/
    ├── Names/
    │   ├── Administrator (value_type=500)
    │   └── testuser (value_type=1000)
    ├── 000001F4 (RID 500 = Administrator)
    │   └── V (binary data)
    └── 000003E8 (RID 1000 = testuser)
        └── V (binary data)
    """
    
    # Create the "Names" subkey with username mappings
    mock_names_key = Mock()
    mock_names_key.name.return_value = "Names"
    
    # Administrator value
    admin_value = Mock()
    admin_value.name.return_value = "Administrator"
    admin_value.value_type.return_value = 500  # RID 500
    admin_value.value.return_value = b"some_binary_data"
    
    # testuser value
    testuser_value = Mock()
    testuser_value.name.return_value = "testuser"
    testuser_value.value_type.return_value = 1000  # RID 1000
    testuser_value.value.return_value = b"some_binary_data"
    
    # Names key returns both values
    mock_names_key.values.return_value = [admin_value, testuser_value]
    
    # =========================================================================
    # Create V field data (binary blob with account info)
    # =========================================================================
    v_data = bytearray(120)
    
    # Last login time (offset 0x30)
    struct.pack_into("<Q", v_data, 0x30, 134249820000000000)
    
    # Last password set time (offset 0x40)
    struct.pack_into("<Q", v_data, 0x40, 134249810000000000)
    
    # Account control flags (offset 0x38) - enabled, not locked
    struct.pack_into("<H", v_data, 0x38, 0x0000)
    
    # Failed login count (offset 0x58)
    struct.pack_into("<I", v_data, 0x58, 2)
    
    # Total login count (offset 0x5C)
    struct.pack_into("<I", v_data, 0x5C, 10)
    
    v_bytes = bytes(v_data)
    
    # =========================================================================
    # Create RID 500 (Administrator) subkey
    # =========================================================================
    mock_rid_500 = Mock()
    mock_rid_500.name.return_value = "000001F4"  # Hex for 500
    
    v_value_500 = Mock()
    v_value_500.name.return_value = "V"
    v_value_500.value.return_value = v_bytes
    
    mock_rid_500.values.return_value = [v_value_500]
    
    # =========================================================================
    # Create RID 1000 (testuser) subkey
    # =========================================================================
    mock_rid_1000 = Mock()
    mock_rid_1000.name.return_value = "000003E8"  # Hex for 1000
    
    v_value_1000 = Mock()
    v_value_1000.name.return_value = "V"
    v_value_1000.value.return_value = v_bytes
    
    mock_rid_1000.values.return_value = [v_value_1000]
    
    # =========================================================================
    # Create parent Users key with all subkeys
    # =========================================================================
    mock_users_key = Mock()
    mock_users_key.name.return_value = "Users"
    
    # Return all three subkeys: Names, RID 500, RID 1000
    mock_users_key.subkeys.return_value = [mock_names_key, mock_rid_500, mock_rid_1000]
    
    # subkey() method returns specific subkey by name
    def subkey_side_effect(name):
        if name == "Names":
            return mock_names_key
        elif name == "000001F4":
            return mock_rid_500
        elif name == "000003E8":
            return mock_rid_1000
        return None
    
    mock_users_key.subkey.side_effect = subkey_side_effect
    
    return mock_users_key


@pytest.fixture
def mock_hive():
    """
    Create a mock registry hive object.
    
    This represents the entire SAM hive file.
    """
    mock_hive = Mock()
    
    # Root key (represents SAM root)
    mock_root = Mock()
    mock_root.name.return_value = "SAM"
    mock_root.subkey.return_value = Mock()  # For navigation
    
    mock_hive.root.return_value = mock_root
    
    return mock_hive