"""
EvidenceSync Pro - Windows-native forensic cross-device correlation engine.
"""

__version__ = "0.1.0"
__author__ = "Hriday"

from loguru import logger

logger.add(
    "logs/evidencesync.log",
    rotation="500 MB",
    retention="10 days",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}"
)