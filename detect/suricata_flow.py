"""Suricata HTTP 이벤트를 Alert의 보조 증거로 연결한다.

``flow_id``는 하나의 네트워크 흐름을 가리킬 뿐 HTTP 트랜잭션 하나를
가리키지는 않는다. 따라서 ``tx_id``가 있으면 sensor/flow/transaction을 모두
일치시키고, ``tx_id``가 없는 Alert에만 보수적인 시간·전송 튜플 폴백을 쓴다.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


DEFAULT_FALLBACK_SECONDS = 5


def _parse_timestamp(value):
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


def _present(value):
    return value is not None and value != ""


def _flow_key(event):
    layer_data = event.get("layer_data", {})
    sensor_id = layer_data.get("sensor_id")
    flow_id = layer_data.get("flow_id")
    if not _present(sensor_id) or not _present(flow_id):
        return None
    return str(sensor_id), str(flow_id)


def _transaction_key(event):
    flow_key = _flow_key(event)
    tx_id = event.get("layer_data", {}).get("tx_id")
    if flow_key is None or not _present(tx_id):
        return None
    return flow_key + (str(tx_id),)


def _transport_tuple(event):
    layer_data = event.get("layer_data", {})
    dest_port = layer_data.get("transport_dest_port")
    if not _present(dest_port):
        dest_port = layer_data.get("dest_port")
    values = (
        layer_data.get("transport_src_ip"),
        layer_data.get("transport_src_port"),
        layer_data.get("dest_ip"),
        dest_port,
        layer_data.get("protocol"),
    )
    if any(not _present(value) for value in values):
        return None
    return tuple(str(value).lower() for value in values)


def build_http_evidence_index(events):
    """정규화된 HTTP 이벤트를 정확 키와 flow 키로 인덱싱한다."""
    exact = defaultdict(list)
    by_flow = defaultdict(list)

    for event in events:
        if not isinstance(event, dict) or event.get("layer") != "network":
            continue
        layer_data = event.get("layer_data")
        if not isinstance(layer_data, dict) or layer_data.get("event_type") != "http":
            continue
        raw_ref = event.get("raw_ref")
        flow_key = _flow_key(event)
        if not _present(raw_ref) or flow_key is None:
            continue

        record = {
            "raw_ref": str(raw_ref),
            "timestamp": _parse_timestamp(event.get("timestamp")),
            "transport_tuple": _transport_tuple(event),
        }
        by_flow[flow_key].append(record)
        transaction_key = _transaction_key(event)
        if transaction_key is not None:
            exact[transaction_key].append(record)

    def _sort_records(records):
        records.sort(key=lambda record: (
            record["timestamp"] or datetime.min.replace(tzinfo=timezone.utc),
            record["raw_ref"],
        ))

    for records in exact.values():
        _sort_records(records)
    for records in by_flow.values():
        _sort_records(records)
    return {"exact": dict(exact), "by_flow": dict(by_flow)}


def find_http_evidence_refs(
    alert_event,
    index,
    fallback_seconds=DEFAULT_FALLBACK_SECONDS,
):
    """Alert에 안전하게 연결할 수 있는 HTTP ``raw_ref`` 목록을 반환한다.

    tx_id가 있으면 정확 일치만 허용한다. tx_id가 없을 때는 같은 sensor/flow,
    같은 전송 튜플, 시간 차 이내인 HTTP 후보가 정확히 한 건일 때만 연결한다.
    """
    if isinstance(fallback_seconds, bool) or not isinstance(
        fallback_seconds, (int, float)
    ):
        raise ValueError("fallback_seconds는 0 이상의 숫자여야 함")
    if fallback_seconds < 0:
        raise ValueError("fallback_seconds는 0 이상이어야 함")
    if not isinstance(alert_event, dict):
        return []

    transaction_key = _transaction_key(alert_event)
    if transaction_key is not None:
        return sorted({
            record["raw_ref"]
            for record in index.get("exact", {}).get(transaction_key, [])
        })

    flow_key = _flow_key(alert_event)
    alert_timestamp = _parse_timestamp(alert_event.get("timestamp"))
    alert_tuple = _transport_tuple(alert_event)
    if flow_key is None or alert_timestamp is None or alert_tuple is None:
        return []

    matches = []
    for record in index.get("by_flow", {}).get(flow_key, []):
        if record["timestamp"] is None or record["transport_tuple"] != alert_tuple:
            continue
        delta = abs((record["timestamp"] - alert_timestamp).total_seconds())
        if delta <= float(fallback_seconds):
            matches.append(record["raw_ref"])

    unique_matches = sorted(set(matches))
    return unique_matches if len(unique_matches) == 1 else []


__all__ = [
    "DEFAULT_FALLBACK_SECONDS",
    "build_http_evidence_index",
    "find_http_evidence_refs",
]
