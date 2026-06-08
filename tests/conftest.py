"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path
from datetime import datetime
from evidence_sync_pro.parsers.base_parser import Event


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