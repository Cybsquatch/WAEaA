"""Unit tests for proprietary Windows and Linux artefact parsers."""

from __future__ import annotations

import io
import struct

from waeaa_ingestor.parsers.linux.cron import CronParser
from waeaa_ingestor.parsers.linux.history import ShellHistoryParser
from waeaa_ingestor.parsers.linux.syslog import SyslogParser
from waeaa_ingestor.parsers.linux.wtmp import UTMP_RECORD_SIZE, WtmpParser
from waeaa_ingestor.parsers.windows.lnk import LNK_CLSID, LnkParser
from waeaa_ingestor.parsers.windows.prefetch import PREFETCH_SCCA, PrefetchParser


def test_syslog_parser() -> None:
    parser = SyslogParser()
    assert parser.can_parse("/var/log/auth.log") is True
    assert parser.can_parse("/var/log/syslog") is True

    log_data = (
        b"Oct 22 10:15:20 host1 sshd[1234]: Failed password for invalid user admin"
        b" from 192.168.1.50 port 44322 ssh2\n"
        b"Oct 22 10:16:00 host1 sudo:   analyst : TTY=pts/0 ; COMMAND=/usr/bin/cat /etc/shadow\n"
    )
    records = list(parser.parse(io.BytesIO(log_data), "/var/log/auth.log"))
    assert len(records) == 2
    assert records[0].action == "SSHFailedLogon"
    assert records[0].user == "admin"
    assert records[0].process_id == 1234
    assert records[1].action == "SudoExecution"
    assert records[1].user == "analyst"


def test_wtmp_parser() -> None:
    parser = WtmpParser()
    assert parser.can_parse("/var/log/wtmp") is True
    assert parser.can_parse("/var/log/btmp") is True

    # Craft a synthetic 384-byte utmp record
    chunk = bytearray(UTMP_RECORD_SIZE)
    struct.pack_into("<h", chunk, 0, 7)  # USER_PROCESS
    struct.pack_into("<i", chunk, 4, 4321)  # PID
    chunk[8 : 8 + 4] = b"pts1"
    chunk[44 : 44 + 8] = b"root\x00\x00\x00\x00"
    chunk[76 : 76 + 11] = b"10.0.0.99\x00\x00"
    struct.pack_into("<i", chunk, 340, 1729600000)  # Timestamp

    records = list(parser.parse(io.BytesIO(bytes(chunk)), "/var/log/wtmp"))
    assert len(records) == 1
    assert records[0].user == "root"
    assert records[0].action == "UserLogon"
    assert "10.0.0.99" in records[0].summary


def test_shell_history_parser() -> None:
    parser = ShellHistoryParser()
    assert parser.can_parse("/root/.bash_history") is True

    bash_data = (
        b"#1729600000\n"
        b"whoami\n"
        b"#1729600010\n"
        b"cat /etc/shadow\n"
    )
    records = list(parser.parse(io.BytesIO(bash_data), "/root/.bash_history"))
    assert len(records) == 2
    assert records[0].details["command"] == "whoami"
    assert records[1].details["command"] == "cat /etc/shadow"


def test_cron_parser() -> None:
    parser = CronParser()
    assert parser.can_parse("/etc/crontab") is True

    cron_data = b"*/5 * * * * root /usr/local/bin/backup.sh\n"
    records = list(parser.parse(io.BytesIO(cron_data), "/etc/crontab"))
    assert len(records) == 1
    assert records[0].user == "root"
    assert records[0].details["command"] == "/usr/local/bin/backup.sh"


def test_prefetch_parser_synthetic() -> None:
    parser = PrefetchParser()
    assert parser.can_parse("CMD.EXE-12345678.pf") is True

    # Craft synthetic SCCA prefetch header (version 30 = Win10)
    buf = bytearray(512)
    struct.pack_into("<I", buf, 0, 30)  # Version 30
    buf[4:8] = PREFETCH_SCCA
    # Executable name CMD.EXE in UTF-16LE
    name_utf16 = "CMD.EXE".encode("utf-16le")
    buf[0x10 : 0x10 + len(name_utf16)] = name_utf16
    struct.pack_into("<I", buf, 0xD0, 42)  # Run count 42
    struct.pack_into("<Q", buf, 0x80, 133500000000000000)  # FILETIME

    records = list(parser.parse(io.BytesIO(bytes(buf)), "CMD.EXE-12345678.pf"))
    assert len(records) == 1
    assert records[0].process_name == "CMD.EXE"
    assert records[0].details["total_run_count"] == 42


def test_lnk_parser_synthetic() -> None:
    parser = LnkParser()
    assert parser.can_parse("C:/Users/test/Recent/cmd.lnk") is True

    buf = bytearray(256)
    struct.pack_into("<I", buf, 0, 76)  # Header size 76
    buf[4:20] = LNK_CLSID
    struct.pack_into("<Q", buf, 28, 133500000000000000)  # Creation
    struct.pack_into("<Q", buf, 44, 133500000000000000)  # Write
    buf[76 : 76 + 18] = b"C:\\Windows\\cmd.exe\x00"

    records = list(parser.parse(io.BytesIO(bytes(buf)), "cmd.lnk"))
    assert len(records) == 1
    assert records[0].artefact_type == "LNK"
    assert "C:\\Windows\\cmd.exe" in records[0].details["target_path"]
