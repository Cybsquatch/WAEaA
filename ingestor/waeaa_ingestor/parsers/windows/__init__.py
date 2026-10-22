"""Windows forensic artefact parsers."""

from waeaa_ingestor.parsers.windows.browser import BrowserHistoryParser
from waeaa_ingestor.parsers.windows.evtx import EvtxParser
from waeaa_ingestor.parsers.windows.lnk import LnkParser
from waeaa_ingestor.parsers.windows.prefetch import PrefetchParser
from waeaa_ingestor.parsers.windows.registry import RegistryHiveParser

__all__ = [
    "EvtxParser",
    "PrefetchParser",
    "RegistryHiveParser",
    "LnkParser",
    "BrowserHistoryParser",
]
