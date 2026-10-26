"""Windows forensic artefact parsers."""

from waeaa_ingestor.parsers.windows.appdata import AppDataStagingParser
from waeaa_ingestor.parsers.windows.browser import BrowserHistoryParser
from waeaa_ingestor.parsers.windows.evtx import EvtxParser
from waeaa_ingestor.parsers.windows.hosts import HostsFileParser
from waeaa_ingestor.parsers.windows.lnk import LnkParser
from waeaa_ingestor.parsers.windows.mft import MftParser
from waeaa_ingestor.parsers.windows.prefetch import PrefetchParser
from waeaa_ingestor.parsers.windows.pshistory import PowerShellHistoryParser
from waeaa_ingestor.parsers.windows.rdp_cache import RdpCacheParser, ScreenReconstructor
from waeaa_ingestor.parsers.windows.registry import RegistryHiveParser
from waeaa_ingestor.parsers.windows.remote_access import RemoteAccessParser
from waeaa_ingestor.parsers.windows.setupapi import SetupApiParser
from waeaa_ingestor.parsers.windows.tasks import TaskSchedulerParser
from waeaa_ingestor.parsers.windows.wer import WerParser

__all__ = [
    "AppDataStagingParser",
    "EvtxParser",
    "PrefetchParser",
    "RegistryHiveParser",
    "LnkParser",
    "BrowserHistoryParser",
    "RdpCacheParser",
    "RemoteAccessParser",
    "ScreenReconstructor",
    "TaskSchedulerParser",
    "MftParser",
    "SetupApiParser",
    "HostsFileParser",
    "PowerShellHistoryParser",
    "WerParser",
]
