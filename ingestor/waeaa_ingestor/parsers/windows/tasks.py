"""Windows Scheduled Tasks XML definitions proprietary parser.

Parses tasks from %SystemRoot%\\System32\\Tasks, extracts action commands, arguments,
authors, triggers, principals, and execution privileges for persistence investigation.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

XML_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


class TaskSchedulerParser(BaseParser):
    """Parser for Windows Scheduled Tasks XML job definition files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path is located in the Windows System32 Tasks directory."""
        lower = file_path.lower().replace("\\", "/")
        return "system32/tasks" in lower or "syswow64/tasks" in lower

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse XML task definition and yield ParsedRecord."""
        raw_data = stream.read()
        if not raw_data:
            return
        if b"<Task" not in raw_data and b"<\x00T\x00a\x00s\x00k" not in raw_data:
            return

        # Handle UTF-16 and UTF-8 task XML definitions
        text = ""
        for encoding in ("utf-16", "utf-16-le", "utf-8", "latin1"):
            try:
                text = raw_data.decode(encoding).lstrip("\ufeff")
                if "<Task" in text:
                    break
            except UnicodeDecodeError:
                continue

        if not text:
            return

        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return

        # Strip namespace prefix if present
        def find_elem(parent: ET.Element, tag: str) -> ET.Element | None:
            elem = parent.find(f"{XML_TASK_NS}{tag}")
            if elem is None:
                elem = parent.find(tag)
            return elem

        def find_all(parent: ET.Element, tag: str) -> list[ET.Element]:
            res = parent.findall(f"{XML_TASK_NS}{tag}")
            if not res:
                res = parent.findall(tag)
            return res

        # Registration metadata
        reg_info = find_elem(root, "RegistrationInfo")
        author = ""
        created_utc = ""
        uri = ""
        if reg_info is not None:
            author_el = find_elem(reg_info, "Author")
            if author_el is not None and author_el.text:
                author = author_el.text.strip()
            date_el = find_elem(reg_info, "Date")
            if date_el is not None and date_el.text:
                created_utc = date_el.text.strip()
            uri_el = find_elem(reg_info, "URI")
            if uri_el is not None and uri_el.text:
                uri = uri_el.text.strip()

        task_name = uri.lstrip("\\/") if uri else Path(file_path).name

        # Principals & Privileges
        principals = find_elem(root, "Principals")
        run_level = ""
        user_id = ""
        if principals is not None:
            for p in find_all(principals, "Principal"):
                rl = find_elem(p, "RunLevel")
                if rl is not None and rl.text:
                    run_level = rl.text.strip()
                uid = find_elem(p, "UserId")
                if uid is not None and uid.text:
                    user_id = uid.text.strip()

        # Triggers
        triggers_list: list[str] = []
        triggers = find_elem(root, "Triggers")
        if triggers is not None:
            for child in triggers:
                tag = child.tag.split("}")[-1]
                sb = find_elem(child, "StartBoundary")
                start_time = sb.text.strip() if sb is not None and sb.text else ""
                triggers_list.append(f"{tag}:{start_time}" if start_time else tag)

        # Actions
        actions = find_elem(root, "Actions")
        if actions is None:
            return

        exec_elements = find_all(actions, "Exec")
        for idx, exec_el in enumerate(exec_elements):
            cmd_el = find_elem(exec_el, "Command")
            args_el = find_elem(exec_el, "Arguments")
            cmd = cmd_el.text.strip() if cmd_el is not None and cmd_el.text else ""
            args = args_el.text.strip() if args_el is not None and args_el.text else ""

            full_command = f"{cmd} {args}".strip()
            summary = f"Scheduled Task '{task_name}': {full_command}"

            yield ParsedRecord(
                artefact_type="ScheduledTask",
                source_file=file_path,
                timestamp_utc=created_utc,
                action="TaskCreated",
                summary=summary,
                user=user_id or author,
                details={
                    "task_name": task_name,
                    "command": full_command,
                    "executable": cmd,
                    "arguments": args,
                    "author": author,
                    "run_level": run_level,
                    "triggers": ", ".join(triggers_list),
                    "action_index": idx,
                },
            )
