"""Unit tests for forensic EVTX enrichment and network/connection detection rules."""

from __future__ import annotations

import io
import struct

from waeaa_ingestor.detection.models import Severity
from waeaa_ingestor.detection.rules import (
    FailedLogonRule,
    NetworkShareAccessRule,
    PrivilegedGroupModificationRule,
    RdpIntrusionRule,
    RemoteLogonRule,
    UserAccountCreatedRule,
)
from waeaa_ingestor.parsers.base import ParsedRecord
from waeaa_ingestor.parsers.windows.evtx import EvtxParser, filetime_to_iso


def test_filetime_to_iso() -> None:
    """Validate Windows FILETIME conversion to ISO 8601 UTC."""
    assert filetime_to_iso(0) == ""
    # 2024-01-01T00:00:00Z in FileTime is 133485408000000000
    ft = 133485408000000000
    iso = filetime_to_iso(ft)
    assert iso.startswith("2024-01-01T00:00:00")


def test_evtx_parser_enrichment_rdp_1149() -> None:
    """Validate Event 1149 RDP authentication enrichment with IP and User."""
    parser = EvtxParser()
    record = parser._enrich_event(
        record_id=101,
        timestamp_utc="2024-02-10T12:00:00+00:00",
        file_path="C/Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
        event_id=1149,
        provider="Microsoft-Windows-TerminalServices-RemoteConnectionManager",
        channel="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        computer="DESKTOP-VICTIM",
        user_sid="",
        event_data={
            "Param1": "admin",
            "Param2": "",
            "Param3": "31.220.85.162",
            "param_4": "admin",
            "param_5": "31.220.85.162",
        },
        all_strings=["admin", "31.220.85.162"],
    )

    assert record.action == "RdpAuth_1149"
    assert record.user == "admin"
    assert record.details.get("ip_address") == "31.220.85.162"
    assert "31.220.85.162" in record.summary
    assert "admin" in record.summary

    # Ensure RdpIntrusionRule triggers
    rule = RdpIntrusionRule()
    finding = rule.evaluate(record)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert "31.220.85.162" in finding.summary


def test_evtx_parser_enrichment_security_4624() -> None:
    """Validate Event 4624 successful network logon enrichment."""
    parser = EvtxParser()
    record = parser._enrich_event(
        record_id=202,
        timestamp_utc="2024-02-10T12:05:00+00:00",
        file_path="C/Windows/System32/winevt/Logs/Security.evtx",
        event_id=4624,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="WIN-NI9FBK23SLO.branchoffice.example.com",
        user_sid="S-1-5-21-1057484085-1795310446-2370380301-500",
        event_data={
            "TargetUserName": "Administrator",
            "TargetDomainName": "BRANCHOFFICE",
            "LogonType": 3,
            "WorkstationName": "ADMIN-WFH",
            "IpAddress": "195.21.1.97",
            "IpPort": 0,
        },
        all_strings=["Administrator", "BRANCHOFFICE", "ADMIN-WFH", "195.21.1.97"],
    )

    assert record.action == "Logon_4624"
    assert record.user == "Administrator"
    assert record.details.get("domain") == "BRANCHOFFICE"
    assert record.details.get("ip_address") == "195.21.1.97"
    assert record.details.get("workstation") == "ADMIN-WFH"
    assert record.details.get("logon_type") == "3 (Network)"
    assert "195.21.1.97" in record.summary

    # Ensure RemoteLogonRule triggers on external IP + Administrator
    rule = RemoteLogonRule()
    finding = rule.evaluate(record)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert "195.21.1.97" in finding.title


def test_evtx_parser_enrichment_security_4625() -> None:
    """Validate Event 4625 failed logon enrichment and FailedLogonRule."""
    parser = EvtxParser()
    record = parser._enrich_event(
        record_id=303,
        timestamp_utc="2024-02-10T12:10:00+00:00",
        file_path="C/Windows/System32/winevt/Logs/Security.evtx",
        event_id=4625,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="SERVER-01",
        user_sid="",
        event_data={
            "TargetUserName": "finance_admin",
            "TargetDomainName": "CORP",
            "Status": "0xc000006a",
            "IpAddress": "198.51.100.44",
        },
        all_strings=["finance_admin", "CORP", "198.51.100.44"],
    )

    assert record.action == "FailedLogon_4625"
    assert "Bad password" in record.summary
    assert record.details.get("ip_address") == "198.51.100.44"

    rule = FailedLogonRule()
    finding = rule.evaluate(record)
    assert finding is not None
    assert finding.severity == Severity.HIGH  # external IP
    assert "finance_admin" in finding.title


def test_user_creation_and_group_add_rules() -> None:
    """Validate detection of user account creation and group manipulation."""
    parser = EvtxParser()

    # Event 4720: User account created
    rec_4720 = parser._enrich_event(
        record_id=401,
        timestamp_utc="2024-02-10T12:15:00+00:00",
        file_path="Security.evtx",
        event_id=4720,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="DC-01",
        user_sid="",
        event_data={
            "TargetUserName": "backdoor_user",
            "SubjectUserName": "Administrator",
        },
        all_strings=["backdoor_user", "Administrator"],
    )
    rule_4720 = UserAccountCreatedRule()
    finding_4720 = rule_4720.evaluate(rec_4720)
    assert finding_4720 is not None
    assert "backdoor_user" in finding_4720.title

    # Event 4728: Member added to group
    rec_4728 = parser._enrich_event(
        record_id=402,
        timestamp_utc="2024-02-10T12:16:00+00:00",
        file_path="Security.evtx",
        event_id=4728,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="DC-01",
        user_sid="",
        event_data={
            "TargetUserName": "Domain Admins",
            "MemberName": "CN=backdoor_user,CN=Users,DC=corp",
            "SubjectUserName": "Administrator",
        },
        all_strings=["Domain Admins", "backdoor_user", "Administrator"],
    )
    rule_4728 = PrivilegedGroupModificationRule()
    finding_4728 = rule_4728.evaluate(rec_4728)
    assert finding_4728 is not None
    assert "Domain Admins" in finding_4728.title


def test_network_share_access_rule() -> None:
    """Validate detection of Event 5140/5145 administrative share access."""
    parser = EvtxParser()
    record = parser._enrich_event(
        record_id=501,
        timestamp_utc="2024-02-10T12:20:00+00:00",
        file_path="Security.evtx",
        event_id=5145,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="FILESERVER",
        user_sid="",
        event_data={
            "SubjectUserName": "Administrator",
            "ShareName": r"\\*\ADMIN$",
            "RelativeTargetName": "psexesvc.exe",
            "IpAddress": "195.21.1.97",
        },
        all_strings=["Administrator", r"\\*\ADMIN$", "psexesvc.exe", "195.21.1.97"],
    )

    rule = NetworkShareAccessRule()
    finding = rule.evaluate(record)
    assert finding is not None
    assert "ADMIN$" in finding.title
    assert "195.21.1.97" in finding.title
