#!/usr/bin/env python3
"""Probe IPTV sources from an M3U file and generate an invalid-source report."""

from __future__ import annotations

import argparse
import concurrent.futures
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Iterable
from urllib import error, request


@dataclass(frozen=True)
class StreamEntry:
    channel_name: str
    url: str
    extinf_line: int
    url_line: int


@dataclass(frozen=True)
class ProbeResult:
    entry: StreamEntry
    ok: bool
    status_code: int | None
    method: str | None
    elapsed_ms: int | None
    error_message: str | None


@dataclass(frozen=True)
class AlternativeInfo:
    has_alternative: bool
    alternative_count: int
    valid_alternative_count: int
    alternative_url_lines: str


def parse_m3u(m3u_path: Path) -> list[StreamEntry]:
    lines = m3u_path.read_text(encoding="utf-8", errors="replace").splitlines()
    entries: list[StreamEntry] = []
    pending_name: str | None = None
    pending_line: int | None = None

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("#EXTINF"):
            name = line.split(",", 1)[1].strip() if "," in line else "UNKNOWN"
            pending_name = name
            pending_line = line_no
            continue

        if line.startswith("#"):
            continue

        if pending_name is None or pending_line is None:
            entries.append(
                StreamEntry(
                    channel_name="UNKNOWN",
                    url=line,
                    extinf_line=line_no,
                    url_line=line_no,
                )
            )
            continue

        entries.append(
            StreamEntry(
                channel_name=pending_name,
                url=line,
                extinf_line=pending_line,
                url_line=line_no,
            )
        )
        pending_name = None
        pending_line = None

    return entries


def _single_request(
    url: str, method: str, timeout: float, user_agent: str
) -> tuple[int, int]:
    headers = {"User-Agent": user_agent}
    if method == "GET":
        headers["Range"] = "bytes=0-0"

    req = request.Request(url=url, method=method, headers=headers)
    start = perf_counter()
    with request.urlopen(req, timeout=timeout) as resp:
        status_code = getattr(resp, "status", None) or resp.getcode()
    elapsed_ms = int((perf_counter() - start) * 1000)
    return int(status_code), elapsed_ms


def probe_stream(
    entry: StreamEntry,
    timeout: float,
    retries: int,
    user_agent: str,
    strict_2xx: bool,
) -> ProbeResult:
    last_error = "Unknown error"
    methods = ("HEAD", "GET")
    total_attempts = retries + 1

    for _ in range(total_attempts):
        for method in methods:
            try:
                status_code, elapsed_ms = _single_request(
                    url=entry.url, method=method, timeout=timeout, user_agent=user_agent
                )
                ok = 200 <= status_code < 300 if strict_2xx else 200 <= status_code < 400
                if ok:
                    return ProbeResult(
                        entry=entry,
                        ok=True,
                        status_code=status_code,
                        method=method,
                        elapsed_ms=elapsed_ms,
                        error_message=None,
                    )
                last_error = f"HTTP {status_code}"
            except error.HTTPError as exc:
                last_error = f"HTTP {exc.code}"
            except error.URLError as exc:
                last_error = f"URLError: {exc.reason}"
            except TimeoutError:
                last_error = "Timeout"
            except Exception as exc:  # pragma: no cover
                last_error = f"{exc.__class__.__name__}: {exc}"

    return ProbeResult(
        entry=entry,
        ok=False,
        status_code=None,
        method=None,
        elapsed_ms=None,
        error_message=last_error,
    )


def markdown_escape(text: str) -> str:
    return text.replace("|", r"\|")


def build_channel_result_index(
    results: Iterable[ProbeResult],
) -> dict[str, list[ProbeResult]]:
    index: dict[str, list[ProbeResult]] = {}
    for result in results:
        index.setdefault(result.entry.channel_name, []).append(result)
    return index


def get_alternative_info(
    result: ProbeResult, channel_index: dict[str, list[ProbeResult]]
) -> AlternativeInfo:
    same_channel_results = channel_index.get(result.entry.channel_name, [])
    alternatives = [
        item
        for item in same_channel_results
        if item.entry.url_line != result.entry.url_line
    ]
    valid_alternatives = [item for item in alternatives if item.ok]
    lines = ",".join(
        str(item.entry.url_line) for item in sorted(alternatives, key=lambda x: x.entry.url_line)
    )
    return AlternativeInfo(
        has_alternative=bool(alternatives),
        alternative_count=len(alternatives),
        valid_alternative_count=len(valid_alternatives),
        alternative_url_lines=lines or "-",
    )


def build_report(
    *,
    source_file: Path,
    total: int,
    valid: int,
    invalid_results: Iterable[ProbeResult],
    channel_index: dict[str, list[ProbeResult]],
    timeout: float,
    retries: int,
    concurrency: int,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    invalid_list = list(invalid_results)
    lines = [
        "# IPTV Source Health Report",
        "",
        f"- Generated at: `{now}`",
        f"- Source file: `{source_file}`",
        f"- Total sources: `{total}`",
        f"- Valid sources: `{valid}`",
        f"- Invalid sources: `{len(invalid_list)}`",
        f"- Probe config: `timeout={timeout}s`, `retries={retries}`, `concurrency={concurrency}`",
        "",
    ]

    if not invalid_list:
        lines.append("All sources are reachable.")
        lines.append("")
        return "\n".join(lines)

    lines.extend(
        [
            "## Invalid Sources",
            "",
            "| # | Channel Name | Source URL | URL Line | EXTINF Line | Has Alternative | Alt Count | Valid Alt Count | Alt URL Lines | Error |",
            "|---|---|---|---:|---:|---|---:|---:|---|---|",
        ]
    )

    for idx, result in enumerate(
        sorted(invalid_list, key=lambda item: item.entry.url_line), start=1
    ):
        entry = result.entry
        alt_info = get_alternative_info(result=result, channel_index=channel_index)
        lines.append(
            "| "
            + f"{idx} | "
            + f"{markdown_escape(entry.channel_name)} | "
            + f"{markdown_escape(entry.url)} | "
            + f"{entry.url_line} | "
            + f"{entry.extinf_line} | "
            + f"{'Yes' if alt_info.has_alternative else 'No'} | "
            + f"{alt_info.alternative_count} | "
            + f"{alt_info.valid_alternative_count} | "
            + f"{alt_info.alternative_url_lines} | "
            + f"{markdown_escape(result.error_message or 'Unknown')} |"
        )

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check which IPTV source URLs in an M3U playlist are invalid."
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path("IPTV.m3u"),
        help="Path to the source M3U file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Path to the markdown report file. Defaults to reports/invalid_sources_report_<timestamp>.md",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=8.0,
        help="Per-request timeout in seconds.",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=20,
        help="Number of concurrent workers.",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=1,
        help="Number of retries after the first attempt.",
    )
    parser.add_argument(
        "--strict-2xx",
        action="store_true",
        help="Treat only 2xx as valid (default accepts 2xx-3xx).",
    )
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (X11; Linux x86_64) IPTVSourceChecker/1.0",
        help="User-Agent used for HTTP requests.",
    )
    parser.add_argument(
        "--fail-on-invalid",
        action="store_true",
        help="Exit with code 1 when any invalid source is found.",
    )
    args = parser.parse_args()

    if args.concurrency < 1:
        raise ValueError("--concurrency must be >= 1")
    if args.retries < 0:
        raise ValueError("--retries must be >= 0")
    if args.timeout <= 0:
        raise ValueError("--timeout must be > 0")

    source_file = args.input.resolve()
    if not source_file.exists():
        raise FileNotFoundError(f"Source file not found: {source_file}")

    entries = parse_m3u(source_file)
    if not entries:
        raise RuntimeError(f"No stream entries found in: {source_file}")

    results: list[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_to_entry = {
            executor.submit(
                probe_stream,
                entry,
                args.timeout,
                args.retries,
                args.user_agent,
                args.strict_2xx,
            ): entry
            for entry in entries
        }
        for future in concurrent.futures.as_completed(future_to_entry):
            results.append(future.result())

    invalid_results = [result for result in results if not result.ok]
    valid_count = len(results) - len(invalid_results)
    channel_index = build_channel_result_index(results)

    default_report_path = (
        Path("reports")
        / f"invalid_sources_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    report_path = (args.output or default_report_path).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report_content = build_report(
        source_file=source_file,
        total=len(results),
        valid=valid_count,
        invalid_results=invalid_results,
        channel_index=channel_index,
        timeout=args.timeout,
        retries=args.retries,
        concurrency=args.concurrency,
    )
    report_path.write_text(report_content, encoding="utf-8")

    print(f"Checked sources: {len(results)}")
    print(f"Valid: {valid_count}")
    print(f"Invalid: {len(invalid_results)}")
    print(f"Report: {report_path}")

    if invalid_results:
        print("\nInvalid sources:")
        print(
            "channel_name\turl_line\textinf_line\tsource_url\t"
            "has_alternative\talternative_count\tvalid_alternative_count\talternative_url_lines\terror"
        )
        for item in sorted(invalid_results, key=lambda value: value.entry.url_line):
            alt_info = get_alternative_info(result=item, channel_index=channel_index)
            print(
                f"{item.entry.channel_name}\t"
                f"{item.entry.url_line}\t"
                f"{item.entry.extinf_line}\t"
                f"{item.entry.url}\t"
                f"{'Yes' if alt_info.has_alternative else 'No'}\t"
                f"{alt_info.alternative_count}\t"
                f"{alt_info.valid_alternative_count}\t"
                f"{alt_info.alternative_url_lines}\t"
                f"{item.error_message or 'Unknown'}"
            )

    if args.fail_on_invalid and invalid_results:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
