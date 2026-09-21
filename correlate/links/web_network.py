"""Apache↔Suricata HTTP strong edge 생성.

Suricata의 검증된 XFF ``src_ip``와 Apache ``%a``를 표준화해 비교하고, UTC 시각과
method/path/status가 일치하는 유일한 후보만 자동 연결한다.
"""

import bisect
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from common.join_keys import web_network_match
from correlate.registry import register_linker
from tools.fetch_network_log import canonical_ip, raw_path_and_query


JOIN = "web_network"
DEFAULT_SECONDS = 1.0


def _timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _method(value):
    return value.upper() if isinstance(value, str) else value


def _status(value):
    if isinstance(value, bool):
        return value
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return value


@dataclass(frozen=True)
class ApacheRecord:
    timestamp: datetime
    event: dict
    src_ip: str
    method: object
    path: object
    status: object
    raw_ref: str


class ApacheIndex:
    def __init__(self, events):
        by_ip = defaultdict(list)
        for event in events:
            if not isinstance(event, dict) or event.get("layer") != "web":
                continue
            layer_data = event.get("layer_data")
            timestamp = _timestamp(event.get("timestamp"))
            src_ip = canonical_ip(event.get("src_ip"))
            raw_ref = event.get("raw_ref")
            if (
                not isinstance(layer_data, dict)
                or timestamp is None
                or src_ip is None
                or raw_ref in (None, "")
            ):
                continue
            path, _ = raw_path_and_query(layer_data.get("path"))
            by_ip[src_ip].append(ApacheRecord(
                timestamp=timestamp,
                event=event,
                src_ip=src_ip,
                method=_method(layer_data.get("method")),
                path=path,
                status=_status(layer_data.get("status")),
                raw_ref=str(raw_ref),
            ))

        self.by_ip = dict(by_ip)
        self.times = {}
        for src_ip, records in self.by_ip.items():
            records.sort(key=lambda record: (record.timestamp, record.raw_ref))
            self.times[src_ip] = [record.timestamp for record in records]

    def window(self, src_ip, timestamp, seconds):
        records = self.by_ip.get(src_ip, [])
        times = self.times.get(src_ip, [])
        delta = timedelta(seconds=float(seconds))
        left = bisect.bisect_left(times, timestamp - delta)
        right = bisect.bisect_right(times, timestamp + delta)
        return records[left:right]


def _network_request(event):
    layer_data = event["layer_data"]
    return {
        "method": _method(layer_data.get("method")),
        "path": layer_data.get("url_path"),
        "status": _status(layer_data.get("status")),
    }


def _exact(record, request):
    return (
        record.method == request["method"]
        and record.path == request["path"]
        and record.status == request["status"]
    )


def _common_join_match(record, network_timestamp, network_src_ip, seconds):
    """공통 join_keys 판정으로 canonical IP와 시간 근접성을 최종 확인한다."""
    web_event = {
        "timestamp": record.timestamp.isoformat(),
        "src_ip": record.src_ip,
    }
    network_event = {
        "timestamp": network_timestamp.isoformat(),
        "src_ip": network_src_ip,
    }
    return web_network_match(web_event, network_event, seconds)


@register_linker
def web_network_edges(events, seconds=DEFAULT_SECONDS):
    """검증된 XFF/IP와 요청 정보가 일치하는 유일한 strong edge만 반환한다."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError("seconds는 0 이상의 숫자여야 함")
    if seconds < 0:
        raise ValueError("seconds는 0 이상이어야 함")

    event_list = list(events)
    apache_index = ApacheIndex(event_list)
    network_http = []
    for event in event_list:
        if not isinstance(event, dict) or event.get("layer") != "network":
            continue
        layer_data = event.get("layer_data")
        if (
            not isinstance(layer_data, dict)
            or layer_data.get("event_type") != "http"
            or event.get("raw_ref") in (None, "")
        ):
            continue
        network_http.append(event)
    network_http.sort(
        key=lambda event: (str(event.get("timestamp") or ""), str(event["raw_ref"]))
    )

    edges = []
    for network_event in network_http:
        layer_data = network_event["layer_data"]
        if layer_data.get("xff_status") != "valid":
            continue
        timestamp = _timestamp(network_event.get("timestamp"))
        src_ip = canonical_ip(network_event.get("src_ip"))
        if timestamp is None or src_ip is None:
            continue

        request = _network_request(network_event)
        if any(value in (None, "") for value in request.values()):
            continue
        candidates = [
            record
            for record in apache_index.window(src_ip, timestamp, seconds)
            if _common_join_match(record, timestamp, src_ip, seconds)
            and _exact(record, request)
        ]
        if len(candidates) != 1:
            continue

        apache = candidates[0]
        dt_sec = abs((apache.timestamp - timestamp).total_seconds())
        edges.append({
            "a": apache.raw_ref,
            "b": str(network_event["raw_ref"]),
            "join": JOIN,
            "keys": {
                "grade": "strong",
                "src_ip": src_ip,
                "dt_sec": round(dt_sec, 6),
                "method": request["method"],
                "path": request["path"],
                "status": request["status"],
                "sensor_id": layer_data.get("sensor_id"),
                "flow_id": layer_data.get("flow_id"),
                "tx_id": layer_data.get("tx_id"),
            },
        })

    unique = {}
    for edge in edges:
        unique[(edge["a"], edge["b"], edge["join"])] = edge
    return [unique[key] for key in sorted(unique)]


__all__ = ["DEFAULT_SECONDS", "web_network_edges"]
