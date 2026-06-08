"""Abstract base class for all artifact parsers."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Event:
    """Normalized event representation across all artifact types."""
    
    timestamp: datetime          # When event occurred (UTC)
    source_device: str           # Device name (e.g., "DESKTOP-ABC123")
    source_type: str             # Artifact type (e.g., "EVTX", "OneDrive")
    event_type: str              # Specific event (e.g., "login", "file_access")
    user: str                    # Username or email
    payload: Dict[str, Any]      # Event-specific data
    timezone_offset: str         # Original timezone (e.g., "UTC+5:30")
    
    def __post_init__(self):
        """Validate critical fields."""
        if self.timestamp is None:
            raise ValueError("Timestamp cannot be None")
        if not self.source_device:
            raise ValueError("Source device required")
        if not self.source_type:
            raise ValueError("Source type required")


class BaseParser(ABC):
    """Base class for all artifact parsers."""
    
    def __init__(self, artifact_path: str):
        """
        Initialize parser.
        
        Args:
            artifact_path: Path to artifact file/directory
        """
        self.artifact_path = artifact_path
        self.events: List[Event] = []
    
    @abstractmethod
    def parse(self) -> List[Event]:
        """
        Parse artifact and return normalized events.
        
        Returns:
            List of Event objects
            
        Raises:
            FileNotFoundError: If artifact not found
            ValueError: If artifact format invalid
        """
        pass
    
    def _validate_event(self, event: Event) -> bool:
        """
        Validate event has required fields.
        
        Args:
            event: Event to validate
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['timestamp', 'source_device', 'source_type', 'user']
        return all(getattr(event, field, None) is not None 
                   for field in required_fields)