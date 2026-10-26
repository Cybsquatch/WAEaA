"""Registry and discovery of available artefact parsers."""

from __future__ import annotations

from waeaa_ingestor.parsers.base import BaseParser
from waeaa_ingestor.parsers.linux import CronParser, ShellHistoryParser, SyslogParser, WtmpParser
from waeaa_ingestor.parsers.windows import (
    AppDataStagingParser,
    BrowserHistoryParser,
    EvtxParser,
    HostsFileParser,
    LnkParser,
    MftParser,
    PowerShellHistoryParser,
    PrefetchParser,
    RdpCacheParser,
    RegistryHiveParser,
    RemoteAccessParser,
    SetupApiParser,
    TaskSchedulerParser,
    WerParser,
)


def get_default_parsers() -> list[BaseParser]:
    """Return an instantiated list of all proprietary artefact parsers."""
    return [
        EvtxParser(),
        PrefetchParser(),
        RegistryHiveParser(),
        LnkParser(),
        BrowserHistoryParser(),
        RdpCacheParser(),
        RemoteAccessParser(),
        AppDataStagingParser(),
        TaskSchedulerParser(),
        MftParser(),
        SetupApiParser(),
        HostsFileParser(),
        PowerShellHistoryParser(),
        WerParser(),
        SyslogParser(),
        WtmpParser(),
        ShellHistoryParser(),
        CronParser(),
    ]


def find_parser(file_path: str, parsers: list[BaseParser] | None = None) -> BaseParser | None:
    """Find the first matching parser for the given file path."""
    for p in parsers or get_default_parsers():
        if p.can_parse(file_path):
            return p
    return None
