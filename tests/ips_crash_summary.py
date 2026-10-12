"""Extract observations from an existing Apple JSON crash report, without device access.

Usage: python3 tests/ips_crash_summary.py report.ips
Missing evidence stays unknown; this report cannot establish a compatibility fix.
Format: https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys


def parse_report(data: bytes) -> dict:
    text = data.decode("utf-8-sig")
    decoder = json.JSONDecoder()
    documents = []
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        document, offset = decoder.raw_decode(text, offset)
        if not isinstance(document, dict):
            raise ValueError("Crash report JSON records must be objects")
        documents.append(document)
    if len(documents) not in (1, 2):
        raise ValueError("Expected a crash report, optionally preceded by one metadata record")
    if len(documents) == 2 and "procName" in documents[0]:
        raise ValueError("Multiple crash reports are not one incident")
    if len(documents) == 2 and str(documents[0].get("bug_type")) != "309":
        raise ValueError("IPS metadata must identify an application crash (bug_type 309)")
    if any(str(record.get("bug_type", "309")) != "309" for record in documents):
        raise ValueError("Only application crash reports (bug_type 309) are supported")
    report = documents[-1]
    if "procName" not in report or not any(key in report for key in ("exception", "termination")):
        raise ValueError("Missing application crash report body")
    return report


def integer(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError:
            return None
    return value if isinstance(value, int) and value >= 0 else None


def object_field(value) -> dict:
    return value if isinstance(value, dict) else {}


def register_value(state: dict, name: str):
    return integer(object_field(state.get(name)).get("value"))


def fault_mapping(report: dict):
    info = report.get("vmRegionInfo") or report.get("vmregioninfo")
    if not isinstance(info, str):
        return None
    match = re.search(
        r"^\s*--->\s+(\S+)\s+(?:0x)?([\da-fA-F]+)-(?:0x)?([\da-fA-F]+)"
        r"\s+\[[^\]]+\]\s+([rwx-]{3})/([rwx-]{3})(?=\s|$)",
        info, re.MULTILINE,
    )
    if not match:
        return None
    kind, start, end, protection, maximum = match.groups()
    start, end = int(start, 16), int(end, 16)
    if end <= start:
        return None
    return {
        "type": kind, "start": start, "end": end, "size_bytes": end - start,
        "protection": protection, "maximum_protection": maximum,
    }


def summarize_report(data: bytes, report_name: str = "") -> dict:
    report = parse_report(data)
    threads = report.get("threads")
    threads = threads if isinstance(threads, list) else []
    index = integer(report.get("faultingThread"))
    thread_source = "faultingThread" if index is not None else None
    if "faultingThread" not in report:
        triggered = [i for i, thread in enumerate(threads)
                     if object_field(thread).get("triggered") is True]
        if len(triggered) == 1:
            index, thread_source = triggered[0], "triggered"
    thread = object_field(threads[index]) if index is not None and index < len(threads) else {}
    if not thread:
        index, thread_source = None, None
    state = object_field(thread.get("threadState"))
    pc, far, lr = (register_value(state, name) for name in ("pc", "far", "lr"))
    esr = object_field(state.get("esr")).get("description")
    esr = esr if isinstance(esr, str) else None
    mapping = fault_mapping(report)
    if mapping:
        for name, address in (("pc", pc), ("far", far)):
            mapping[f"contains_{name}"] = (
                mapping["start"] <= address < mapping["end"] if address is not None else None
            )
    raw_images = report.get("usedImages")
    images = raw_images if isinstance(raw_images, list) else []
    valid_images = [image for image in images if isinstance(image, dict)]
    names = "\n".join(str(image.get(key, "")) for image in valid_images for key in ("name", "path"))
    image_observations_available = bool(valid_images)
    # Absolute-symbol records have no loaded mapping; Apple may use a zero-size
    # record with source A. Do not mistake that record for a missing image range.
    mapped_images = [image for image in valid_images if image.get("source") != "A"]
    ranges = [(integer(image.get("base")), integer(image.get("size"))) for image in mapped_images]
    matching_image = any(base is not None and size is not None and base <= pc < base + size
                         for base, size in ranges) if pc is not None else False
    complete_ranges = bool(mapped_images) and len(valid_images) == len(images) and all(
        base is not None and size is not None and size > 0 for base, size in ranges
    )
    pc_in_image = True if matching_image else False if pc is not None and complete_ranges else None
    termination = object_field(report.get("termination"))
    namespace = termination.get("namespace")
    code, indicator = termination.get("code"), termination.get("indicator")
    if namespace is None:
        invalid_page = None
    elif namespace != "CODESIGNING":
        invalid_page = False
    elif indicator == "Invalid Page" or integer(code) == 2:
        invalid_page = True
    else:
        invalid_page = False if code is not None or indicator is not None else None
    return {
        "schema_version": 1,
        "report_name": report_name,
        "report_sha256": hashlib.sha256(data).hexdigest(),
        "process": {"name": report.get("procName"), "pid": report.get("pid"),
                    "capture_time": report.get("captureTime")},
        "os_version": report.get("osVersion"),
        "exception": object_field(report.get("exception")),
        "termination": termination,
        "faulting_thread": {"index": index, "selected_by": thread_source,
                            "frame_count": len(thread["frames"]) if isinstance(thread.get("frames"), list) else None},
        "registers": {"pc": pc, "far": far, "lr": lr, "esr_description": esr},
        "fault_mapping": mapping,
        "observations": {
            "codesigning_invalid_page": invalid_page,
            "instruction_permission_fault": (
                "instruction abort" in esr.lower() and "permission fault" in esr.lower()
                if esr is not None else None
            ),
            "pc_equals_far": pc == far if pc is not None and far is not None else None,
            "pc_in_reported_image": pc_in_image,
            "reported_image_count": len(images) if isinstance(raw_images, list) else None,
            "image_name_presence": {
                name: name in names.lower() if image_observations_available else None
                for name in ("frida-agent", "systemhook")
            },
        },
        "underlying_compatibility_defect": "not_established_by_crash_report",
        "fix_verification": "not_assessed",
        "limitations": [
            "Registers and mapping permissions describe the fault, not the earlier protection operations.",
            "Image-name absence does not prove initialization order or exclude a renamed image.",
            "This historical report does not establish current device or server state.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=pathlib.Path)
    args = parser.parse_args()
    try:
        summary = summarize_report(args.report.read_bytes(), args.report.name)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Cannot summarize crash report: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
