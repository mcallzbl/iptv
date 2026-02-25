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
from urllib import error, parse, request


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


@dataclass(frozen=True)
class UrlValidationResult:
    ok: bool
    status_code: int | None
    check_stage: str
    detail: str
    elapsed_ms: int


@dataclass(frozen=True)
class SegmentProbeStat:
    status_code: int
    elapsed_ms: int
    bytes_read: int
    truncated: bool
    duration_s: float | None
    kbps: float
    realtime_ratio: float | None


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


def status_ok(status_code: int, strict_2xx: bool) -> bool:
    if strict_2xx:
        return 200 <= status_code < 300
    return 200 <= status_code < 400


def decode_text(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


def looks_like_html(payload: bytes) -> bool:
    snippet = payload[:512].strip().lower()
    return snippet.startswith(b"<!doctype html") or snippet.startswith(b"<html")


def http_get(
    *,
    url: str,
    timeout: float,
    user_agent: str,
    max_bytes: int,
    range_header: str | None = None,
) -> tuple[int, str, dict[str, str], bytes, int, bool]:
    headers = {"User-Agent": user_agent}
    if range_header:
        headers["Range"] = range_header

    req = request.Request(url=url, method="GET", headers=headers)
    start = perf_counter()
    with request.urlopen(req, timeout=timeout) as resp:
        status_code = int(getattr(resp, "status", None) or resp.getcode())
        final_url = resp.geturl()
        response_headers = {key.lower(): value for key, value in resp.headers.items()}
        raw_body = resp.read(max_bytes + 1)
    elapsed_ms = int((perf_counter() - start) * 1000)
    truncated = len(raw_body) > max_bytes
    body = raw_body[:max_bytes] if truncated else raw_body
    return status_code, final_url, response_headers, body, elapsed_ms, truncated


def extract_variant_uris(lines: list[str]) -> list[str]:
    variants: list[str] = []
    for idx, line in enumerate(lines):
        if not line.startswith("#EXT-X-STREAM-INF"):
            continue
        cursor = idx + 1
        while cursor < len(lines):
            candidate = lines[cursor].strip()
            if candidate and not candidate.startswith("#"):
                variants.append(candidate)
                break
            cursor += 1
    return variants


def extract_media_segments(lines: list[str]) -> list[tuple[str, float | None]]:
    segments: list[tuple[str, float | None]] = []
    current_duration: float | None = None
    for line in lines:
        if line.startswith("#EXTINF:"):
            raw = line[len("#EXTINF:") :].split(",", 1)[0].strip()
            try:
                parsed_duration = float(raw)
                current_duration = parsed_duration if parsed_duration > 0 else None
            except ValueError:
                current_duration = None
            continue
        if line.startswith("#"):
            continue
        if not line:
            continue
        segments.append((line, current_duration))
        current_duration = None
    return segments


def validate_hls_playlist(
    *,
    url: str,
    timeout: float,
    user_agent: str,
    strict_2xx: bool,
    max_playlist_bytes: int,
    max_probe_bytes: int,
    max_playlist_depth: int,
    probe_segments: int,
    max_segment_bytes: int,
    enable_speed_check: bool,
    min_realtime_ratio: float,
    min_single_realtime_ratio: float,
    min_segment_kbps: float,
    depth: int = 0,
    prefetched: tuple[int, str, dict[str, str], bytes, int, bool] | None = None,
) -> UrlValidationResult:
    try:
        if prefetched is None:
            status_code, final_url, headers, body, elapsed_ms, _ = http_get(
                url=url,
                timeout=timeout,
                user_agent=user_agent,
                max_bytes=max_playlist_bytes,
            )
        else:
            status_code, final_url, headers, body, elapsed_ms, _ = prefetched
    except error.HTTPError as exc:
        return UrlValidationResult(
            ok=False,
            status_code=exc.code,
            check_stage="HLS",
            detail=f"HLS playlist HTTP {exc.code}",
            elapsed_ms=0,
        )
    except error.URLError as exc:
        return UrlValidationResult(
            ok=False,
            status_code=None,
            check_stage="HLS",
            detail=f"HLS playlist unreachable: {exc.reason}",
            elapsed_ms=0,
        )
    except TimeoutError:
        return UrlValidationResult(
            ok=False,
            status_code=None,
            check_stage="HLS",
            detail="HLS playlist timeout",
            elapsed_ms=0,
        )
    except Exception as exc:  # pragma: no cover
        return UrlValidationResult(
            ok=False,
            status_code=None,
            check_stage="HLS",
            detail=f"HLS playlist exception: {exc.__class__.__name__}: {exc}",
            elapsed_ms=0,
        )

    if not status_ok(status_code, strict_2xx):
        return UrlValidationResult(
            ok=False,
            status_code=status_code,
            check_stage="HLS",
            detail=f"HLS playlist returned HTTP {status_code}",
            elapsed_ms=elapsed_ms,
        )

    text = decode_text(body).lstrip("\ufeff")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("#EXTM3U"):
        return UrlValidationResult(
            ok=False,
            status_code=status_code,
            check_stage="HLS",
            detail="Not a valid M3U8 playlist (missing #EXTM3U)",
            elapsed_ms=elapsed_ms,
        )

    variants = extract_variant_uris(lines)
    if variants:
        if depth >= max_playlist_depth:
            return UrlValidationResult(
                ok=False,
                status_code=status_code,
                check_stage="HLS",
                detail=f"Playlist nesting too deep (>{max_playlist_depth})",
                elapsed_ms=elapsed_ms,
            )
        nested_url = parse.urljoin(final_url, variants[0])
        nested = validate_hls_playlist(
            url=nested_url,
            timeout=timeout,
            user_agent=user_agent,
            strict_2xx=strict_2xx,
            max_playlist_bytes=max_playlist_bytes,
            max_probe_bytes=max_probe_bytes,
            max_playlist_depth=max_playlist_depth,
            probe_segments=probe_segments,
            max_segment_bytes=max_segment_bytes,
            enable_speed_check=enable_speed_check,
            min_realtime_ratio=min_realtime_ratio,
            min_single_realtime_ratio=min_single_realtime_ratio,
            min_segment_kbps=min_segment_kbps,
            depth=depth + 1,
            prefetched=None,
        )
        if not nested.ok:
            return UrlValidationResult(
                ok=False,
                status_code=nested.status_code,
                check_stage="HLS",
                detail=f"Master playlist has unusable variant: {nested.detail}",
                elapsed_ms=elapsed_ms + nested.elapsed_ms,
            )
        return UrlValidationResult(
            ok=True,
            status_code=nested.status_code,
            check_stage="HLS",
            detail=f"Master playlist OK; variant playable ({nested.detail})",
            elapsed_ms=elapsed_ms + nested.elapsed_ms,
        )

    segments = extract_media_segments(lines)
    if not segments:
        return UrlValidationResult(
            ok=False,
            status_code=status_code,
            check_stage="HLS",
            detail="Media playlist has no segment URLs",
            elapsed_ms=elapsed_ms,
        )

    probe_count = max(1, min(probe_segments, len(segments)))
    segment_stats: list[SegmentProbeStat] = []
    total_elapsed_ms = elapsed_ms
    for idx in range(probe_count):
        seg_uri, seg_duration = segments[idx]
        segment_url = parse.urljoin(final_url, seg_uri)
        try:
            seg_status, _, _, seg_body, seg_elapsed, seg_truncated = http_get(
                url=segment_url,
                timeout=timeout,
                user_agent=user_agent,
                max_bytes=max_segment_bytes,
                range_header=None,
            )
        except error.HTTPError as exc:
            return UrlValidationResult(
                ok=False,
                status_code=exc.code,
                check_stage="HLS_SPEED",
                detail=f"Segment {idx + 1} HTTP {exc.code}",
                elapsed_ms=total_elapsed_ms,
            )
        except error.URLError as exc:
            return UrlValidationResult(
                ok=False,
                status_code=None,
                check_stage="HLS_SPEED",
                detail=f"Segment {idx + 1} unreachable: {exc.reason}",
                elapsed_ms=total_elapsed_ms,
            )
        except TimeoutError:
            return UrlValidationResult(
                ok=False,
                status_code=None,
                check_stage="HLS_SPEED",
                detail=f"Segment {idx + 1} timeout",
                elapsed_ms=total_elapsed_ms,
            )
        except Exception as exc:  # pragma: no cover
            return UrlValidationResult(
                ok=False,
                status_code=None,
                check_stage="HLS_SPEED",
                detail=f"Segment {idx + 1} exception: {exc.__class__.__name__}: {exc}",
                elapsed_ms=total_elapsed_ms,
            )

        total_elapsed_ms += seg_elapsed
        if not status_ok(seg_status, strict_2xx):
            return UrlValidationResult(
                ok=False,
                status_code=seg_status,
                check_stage="HLS_SPEED",
                detail=f"Segment {idx + 1} returned HTTP {seg_status}",
                elapsed_ms=total_elapsed_ms,
            )
        if not seg_body:
            return UrlValidationResult(
                ok=False,
                status_code=seg_status,
                check_stage="HLS_SPEED",
                detail=f"Segment {idx + 1} returned empty payload",
                elapsed_ms=total_elapsed_ms,
            )
        if looks_like_html(seg_body):
            return UrlValidationResult(
                ok=False,
                status_code=seg_status,
                check_stage="HLS_SPEED",
                detail=f"Segment {idx + 1} looks like HTML response",
                elapsed_ms=total_elapsed_ms,
            )

        elapsed_s = max(seg_elapsed / 1000.0, 0.001)
        kbps = (len(seg_body) * 8.0) / elapsed_s / 1000.0
        realtime_ratio = None
        if seg_duration and seg_duration > 0 and not seg_truncated:
            realtime_ratio = seg_duration / elapsed_s

        segment_stats.append(
            SegmentProbeStat(
                status_code=seg_status,
                elapsed_ms=seg_elapsed,
                bytes_read=len(seg_body),
                truncated=seg_truncated,
                duration_s=seg_duration,
                kbps=kbps,
                realtime_ratio=realtime_ratio,
            )
        )

    avg_kbps = sum(item.kbps for item in segment_stats) / len(segment_stats)
    if min_segment_kbps > 0 and avg_kbps < min_segment_kbps:
        return UrlValidationResult(
            ok=False,
            status_code=segment_stats[-1].status_code,
            check_stage="HLS_SPEED",
            detail=(
                f"Average segment speed too low: {avg_kbps:.1f} kbps < "
                f"{min_segment_kbps:.1f} kbps"
            ),
            elapsed_ms=total_elapsed_ms,
        )

    realtime_ratios = [
        item.realtime_ratio for item in segment_stats if item.realtime_ratio is not None
    ]
    if enable_speed_check and realtime_ratios:
        worst_ratio = min(realtime_ratios)
        avg_ratio = sum(realtime_ratios) / len(realtime_ratios)
        if worst_ratio < min_single_realtime_ratio:
            return UrlValidationResult(
                ok=False,
                status_code=segment_stats[-1].status_code,
                check_stage="HLS_SPEED",
                detail=(
                    f"Segment speed instability: worst realtime ratio {worst_ratio:.2f} < "
                    f"{min_single_realtime_ratio:.2f}"
                ),
                elapsed_ms=total_elapsed_ms,
            )
        if avg_ratio < min_realtime_ratio:
            return UrlValidationResult(
                ok=False,
                status_code=segment_stats[-1].status_code,
                check_stage="HLS_SPEED",
                detail=(
                    f"Average realtime ratio too low: {avg_ratio:.2f} < "
                    f"{min_realtime_ratio:.2f}"
                ),
                elapsed_ms=total_elapsed_ms,
            )

    fastest = max(item.kbps for item in segment_stats)
    slowest = min(item.kbps for item in segment_stats)
    ratio_text = "-"
    if realtime_ratios:
        ratio_text = (
            f"avg={sum(realtime_ratios) / len(realtime_ratios):.2f}, "
            f"min={min(realtime_ratios):.2f}"
        )
    return UrlValidationResult(
        ok=True,
        status_code=segment_stats[-1].status_code,
        check_stage="HLS_SPEED",
        detail=(
            f"Sampled {len(segment_stats)} segments; "
            f"speed kbps avg={avg_kbps:.1f}, min={slowest:.1f}, max={fastest:.1f}; "
            f"realtime_ratio {ratio_text}"
        ),
        elapsed_ms=total_elapsed_ms,
    )


def validate_generic_stream(
    *,
    url: str,
    timeout: float,
    user_agent: str,
    strict_2xx: bool,
    max_playlist_bytes: int,
    max_probe_bytes: int,
    max_playlist_depth: int,
    probe_segments: int,
    max_segment_bytes: int,
    enable_speed_check: bool,
    min_realtime_ratio: float,
    min_single_realtime_ratio: float,
    min_segment_kbps: float,
) -> UrlValidationResult:
    try:
        status_code, final_url, headers, body, elapsed_ms, _ = http_get(
            url=url,
            timeout=timeout,
            user_agent=user_agent,
            max_bytes=max_probe_bytes,
            range_header=f"bytes=0-{max_probe_bytes - 1}",
        )
    except error.HTTPError as exc:
        return UrlValidationResult(
            ok=False,
            status_code=exc.code,
            check_stage="GENERIC",
            detail=f"HTTP {exc.code}",
            elapsed_ms=0,
        )
    except error.URLError as exc:
        return UrlValidationResult(
            ok=False,
            status_code=None,
            check_stage="GENERIC",
            detail=f"Unreachable: {exc.reason}",
            elapsed_ms=0,
        )
    except TimeoutError:
        return UrlValidationResult(
            ok=False,
            status_code=None,
            check_stage="GENERIC",
            detail="Timeout",
            elapsed_ms=0,
        )
    except Exception as exc:  # pragma: no cover
        return UrlValidationResult(
            ok=False,
            status_code=None,
            check_stage="GENERIC",
            detail=f"Exception: {exc.__class__.__name__}: {exc}",
            elapsed_ms=0,
        )

    if not status_ok(status_code, strict_2xx):
        return UrlValidationResult(
            ok=False,
            status_code=status_code,
            check_stage="GENERIC",
            detail=f"HTTP {status_code}",
            elapsed_ms=elapsed_ms,
        )
    if not body:
        return UrlValidationResult(
            ok=False,
            status_code=status_code,
            check_stage="GENERIC",
            detail="Empty response body",
            elapsed_ms=elapsed_ms,
        )

    text = decode_text(body).lstrip("\ufeff")
    content_type = headers.get("content-type", "").lower()
    looks_hls = (
        final_url.lower().endswith(".m3u8")
        or "mpegurl" in content_type
        or text.startswith("#EXTM3U")
    )
    if looks_hls:
        return validate_hls_playlist(
            url=final_url,
            timeout=timeout,
            user_agent=user_agent,
            strict_2xx=strict_2xx,
            max_playlist_bytes=max_playlist_bytes,
            max_probe_bytes=max_probe_bytes,
            max_playlist_depth=max_playlist_depth,
            probe_segments=probe_segments,
            max_segment_bytes=max_segment_bytes,
            enable_speed_check=enable_speed_check,
            min_realtime_ratio=min_realtime_ratio,
            min_single_realtime_ratio=min_single_realtime_ratio,
            min_segment_kbps=min_segment_kbps,
            depth=0,
            prefetched=(status_code, final_url, headers, body, elapsed_ms, False),
        )

    if looks_like_html(body):
        return UrlValidationResult(
            ok=False,
            status_code=status_code,
            check_stage="GENERIC",
            detail="Response looks like HTML page, not media stream",
            elapsed_ms=elapsed_ms,
        )

    return UrlValidationResult(
        ok=True,
        status_code=status_code,
        check_stage="GENERIC",
        detail=f"Binary payload is readable ({len(body)} bytes sampled)",
        elapsed_ms=elapsed_ms,
    )


def validate_stream_url(
    *,
    url: str,
    timeout: float,
    user_agent: str,
    strict_2xx: bool,
    max_playlist_bytes: int,
    max_probe_bytes: int,
    max_playlist_depth: int,
    probe_segments: int,
    max_segment_bytes: int,
    enable_speed_check: bool,
    min_realtime_ratio: float,
    min_single_realtime_ratio: float,
    min_segment_kbps: float,
) -> UrlValidationResult:
    parsed = parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return UrlValidationResult(
            ok=False,
            status_code=None,
            check_stage="VALIDATION",
            detail=f"Unsupported URL scheme: {parsed.scheme or 'EMPTY'}",
            elapsed_ms=0,
        )

    if parsed.path.lower().endswith(".m3u8"):
        return validate_hls_playlist(
            url=url,
            timeout=timeout,
            user_agent=user_agent,
            strict_2xx=strict_2xx,
            max_playlist_bytes=max_playlist_bytes,
            max_probe_bytes=max_probe_bytes,
            max_playlist_depth=max_playlist_depth,
            probe_segments=probe_segments,
            max_segment_bytes=max_segment_bytes,
            enable_speed_check=enable_speed_check,
            min_realtime_ratio=min_realtime_ratio,
            min_single_realtime_ratio=min_single_realtime_ratio,
            min_segment_kbps=min_segment_kbps,
            depth=0,
            prefetched=None,
        )

    return validate_generic_stream(
        url=url,
        timeout=timeout,
        user_agent=user_agent,
        strict_2xx=strict_2xx,
        max_playlist_bytes=max_playlist_bytes,
        max_probe_bytes=max_probe_bytes,
        max_playlist_depth=max_playlist_depth,
        probe_segments=probe_segments,
        max_segment_bytes=max_segment_bytes,
        enable_speed_check=enable_speed_check,
        min_realtime_ratio=min_realtime_ratio,
        min_single_realtime_ratio=min_single_realtime_ratio,
        min_segment_kbps=min_segment_kbps,
    )


def probe_stream(
    entry: StreamEntry,
    timeout: float,
    retries: int,
    user_agent: str,
    strict_2xx: bool,
    max_playlist_bytes: int,
    max_probe_bytes: int,
    max_playlist_depth: int,
    probe_segments: int,
    max_segment_bytes: int,
    enable_speed_check: bool,
    min_realtime_ratio: float,
    min_single_realtime_ratio: float,
    min_segment_kbps: float,
) -> ProbeResult:
    last_result = UrlValidationResult(
        ok=False,
        status_code=None,
        check_stage="VALIDATION",
        detail="Unknown error",
        elapsed_ms=0,
    )

    for _ in range(retries + 1):
        last_result = validate_stream_url(
            url=entry.url,
            timeout=timeout,
            user_agent=user_agent,
            strict_2xx=strict_2xx,
            max_playlist_bytes=max_playlist_bytes,
            max_probe_bytes=max_probe_bytes,
            max_playlist_depth=max_playlist_depth,
            probe_segments=probe_segments,
            max_segment_bytes=max_segment_bytes,
            enable_speed_check=enable_speed_check,
            min_realtime_ratio=min_realtime_ratio,
            min_single_realtime_ratio=min_single_realtime_ratio,
            min_segment_kbps=min_segment_kbps,
        )
        if last_result.ok:
            return ProbeResult(
                entry=entry,
                ok=True,
                status_code=last_result.status_code,
                method=last_result.check_stage,
                elapsed_ms=last_result.elapsed_ms,
                error_message=last_result.detail,
            )

    return ProbeResult(
        entry=entry,
        ok=False,
        status_code=last_result.status_code,
        method=last_result.check_stage,
        elapsed_ms=last_result.elapsed_ms,
        error_message=last_result.detail,
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
        str(item.entry.url_line)
        for item in sorted(alternatives, key=lambda item: item.entry.url_line)
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
    probe_segments: int,
    max_segment_bytes: int,
    enable_speed_check: bool,
    min_realtime_ratio: float,
    min_single_realtime_ratio: float,
    min_segment_kbps: float,
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
        (
            f"- Probe config: `timeout={timeout}s`, `retries={retries}`, "
            f"`concurrency={concurrency}`, `probe_segments={probe_segments}`, "
            f"`max_segment_bytes={max_segment_bytes}`, "
            f"`speed_check={'on' if enable_speed_check else 'off'}`, "
            f"`min_realtime_ratio={min_realtime_ratio}`, "
            f"`min_single_realtime_ratio={min_single_realtime_ratio}`, "
            f"`min_segment_kbps={min_segment_kbps}`"
        ),
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
            "| # | Channel Name | Source URL | URL Line | EXTINF Line | Has Alternative | Alt Count | Valid Alt Count | Alt URL Lines | Check Stage | Reason |",
            "|---|---|---|---:|---:|---|---:|---:|---|---|---|",
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
            + f"{result.method or '-'} | "
            + f"{markdown_escape(result.error_message or 'Unknown')} |"
        )

    lines.append("")
    return "\n".join(lines)


def build_single_check_report(
    *,
    entry: StreamEntry,
    result: ProbeResult,
    timeout: float,
    retries: int,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status_text = "Valid" if result.ok else "Invalid"
    lines = [
        "# IPTV Single Source Check",
        "",
        f"- Generated at: `{now}`",
        f"- Timeout: `{timeout}s`",
        f"- Retries: `{retries}`",
        "",
        "| Channel Name | Source URL | URL Line | EXTINF Line | Status | HTTP Status | Check Stage | Reason |",
        "|---|---|---:|---:|---|---|---|---|",
        "| "
        + f"{markdown_escape(entry.channel_name)} | "
        + f"{markdown_escape(entry.url)} | "
        + f"{entry.url_line} | "
        + f"{entry.extinf_line} | "
        + f"{status_text} | "
        + f"{result.status_code if result.status_code is not None else '-'} | "
        + f"{result.method or '-'} | "
        + f"{markdown_escape(result.error_message or '-')} |",
        "",
    ]
    return "\n".join(lines)


def default_report_path() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("reports") / f"invalid_sources_report_{timestamp}.md"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check whether IPTV source URLs are actually playable (not just HTTP 200)."
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
        help="Path to the markdown report file.",
    )
    parser.add_argument(
        "--check-url",
        default=None,
        help="Check a single source URL directly (skip full M3U parsing).",
    )
    parser.add_argument(
        "--check-channel-name",
        default="SINGLE_URL",
        help="Channel name label used in --check-url mode.",
    )
    parser.add_argument(
        "--check-url-line",
        type=int,
        default=0,
        help="URL line number used in --check-url mode.",
    )
    parser.add_argument(
        "--check-extinf-line",
        type=int,
        default=0,
        help="EXTINF line number used in --check-url mode.",
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
        default="Mozilla/5.0 (X11; Linux x86_64) IPTVSourceChecker/2.0",
        help="User-Agent used for HTTP requests.",
    )
    parser.add_argument(
        "--max-playlist-bytes",
        type=int,
        default=524288,
        help="Max bytes to read from playlist responses.",
    )
    parser.add_argument(
        "--max-probe-bytes",
        type=int,
        default=4096,
        help="Max bytes to read from stream/segment probes.",
    )
    parser.add_argument(
        "--max-playlist-depth",
        type=int,
        default=2,
        help="Max nested HLS playlist depth to follow.",
    )
    parser.add_argument(
        "--probe-segments",
        type=int,
        default=3,
        help="Number of media segments sampled for HLS speed/playability check.",
    )
    parser.add_argument(
        "--max-segment-bytes",
        type=int,
        default=8 * 1024 * 1024,
        help="Max bytes read per segment sample.",
    )
    parser.add_argument(
        "--disable-speed-check",
        action="store_true",
        help="Disable realtime speed-ratio filtering for HLS segments.",
    )
    parser.add_argument(
        "--min-realtime-ratio",
        type=float,
        default=1.1,
        help="Minimum average ratio of segment duration / download time.",
    )
    parser.add_argument(
        "--min-single-realtime-ratio",
        type=float,
        default=0.9,
        help="Minimum allowed realtime ratio for any single sampled segment.",
    )
    parser.add_argument(
        "--min-segment-kbps",
        type=float,
        default=0.0,
        help="Minimum average sampled segment speed in kbps (0 disables).",
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
    if args.max_playlist_bytes < 1024:
        raise ValueError("--max-playlist-bytes must be >= 1024")
    if args.max_probe_bytes < 256:
        raise ValueError("--max-probe-bytes must be >= 256")
    if args.max_playlist_depth < 0:
        raise ValueError("--max-playlist-depth must be >= 0")
    if args.probe_segments < 1:
        raise ValueError("--probe-segments must be >= 1")
    if args.max_segment_bytes < 1024:
        raise ValueError("--max-segment-bytes must be >= 1024")
    if args.min_realtime_ratio <= 0:
        raise ValueError("--min-realtime-ratio must be > 0")
    if args.min_single_realtime_ratio <= 0:
        raise ValueError("--min-single-realtime-ratio must be > 0")
    if args.min_segment_kbps < 0:
        raise ValueError("--min-segment-kbps must be >= 0")

    report_path = (args.output or default_report_path()).resolve()

    if args.check_url:
        entry = StreamEntry(
            channel_name=args.check_channel_name,
            url=args.check_url,
            extinf_line=max(0, args.check_extinf_line),
            url_line=max(0, args.check_url_line),
        )
        result = probe_stream(
            entry=entry,
            timeout=args.timeout,
            retries=args.retries,
            user_agent=args.user_agent,
            strict_2xx=args.strict_2xx,
            max_playlist_bytes=args.max_playlist_bytes,
            max_probe_bytes=args.max_probe_bytes,
            max_playlist_depth=args.max_playlist_depth,
            probe_segments=args.probe_segments,
            max_segment_bytes=args.max_segment_bytes,
            enable_speed_check=not args.disable_speed_check,
            min_realtime_ratio=args.min_realtime_ratio,
            min_single_realtime_ratio=args.min_single_realtime_ratio,
            min_segment_kbps=args.min_segment_kbps,
        )
        print("Single source check")
        print(f"Channel: {entry.channel_name}")
        print(f"URL: {entry.url}")
        print(f"Result: {'VALID' if result.ok else 'INVALID'}")
        print(f"HTTP Status: {result.status_code if result.status_code is not None else '-'}")
        print(f"Check Stage: {result.method or '-'}")
        print(f"Reason: {result.error_message or '-'}")
        print(f"Elapsed: {result.elapsed_ms if result.elapsed_ms is not None else '-'} ms")

        if args.output:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                build_single_check_report(
                    entry=entry,
                    result=result,
                    timeout=args.timeout,
                    retries=args.retries,
                ),
                encoding="utf-8",
            )
            print(f"Report: {report_path}")

        if args.fail_on_invalid and not result.ok:
            return 1
        return 0

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
                args.max_playlist_bytes,
                args.max_probe_bytes,
                args.max_playlist_depth,
                args.probe_segments,
                args.max_segment_bytes,
                not args.disable_speed_check,
                args.min_realtime_ratio,
                args.min_single_realtime_ratio,
                args.min_segment_kbps,
            ): entry
            for entry in entries
        }
        for future in concurrent.futures.as_completed(future_to_entry):
            results.append(future.result())

    invalid_results = [result for result in results if not result.ok]
    valid_count = len(results) - len(invalid_results)
    channel_index = build_channel_result_index(results)

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
        probe_segments=args.probe_segments,
        max_segment_bytes=args.max_segment_bytes,
        enable_speed_check=not args.disable_speed_check,
        min_realtime_ratio=args.min_realtime_ratio,
        min_single_realtime_ratio=args.min_single_realtime_ratio,
        min_segment_kbps=args.min_segment_kbps,
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
            "has_alternative\talternative_count\tvalid_alternative_count\t"
            "alternative_url_lines\tcheck_stage\treason"
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
                f"{item.method or '-'}\t"
                f"{item.error_message or 'Unknown'}"
            )

    if args.fail_on_invalid and invalid_results:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
