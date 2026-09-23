"""Suricata 내부 Alert↔HTTP 연결.

정확 키는 sensor_id + flow_id + tx_id. Alert에 tx_id가 없을 때만 같은 sensor/flow,
같은 전송 5튜플, 제한된 시간창 안의 유일한 HTTP 후보를 보수적으로 연결한다.
"""

from collections import defaultdict
from datetime import datetime, timezone

from common.timeparse import parse_utc
from correlate.registry import register_linker
from tools.fetch_network_log import canonical_ip


JOIN = "suricata_flow"
DEFAULT_FALLBACK_SECONDS = 5.0


def _present(value):
    return value is not None and value != ""


def _timestamp(value):
    return parse_utc(value)


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
    """비교 가능한 (src_ip, src_port, dst_ip, dst_port, protocol)."""
    layer_data = event.get("layer_data", {})
    source_ip = canonical_ip(layer_data.get("transport_src_ip"))
    destination_ip = canonical_ip(
        layer_data.get("transport_dest_ip") or layer_data.get("dest_ip")
    )
    source_port = layer_data.get("transport_src_port")
    destination_port = (
        layer_data.get("transport_dest_port")
        if _present(layer_data.get("transport_dest_port"))
        else layer_data.get("dest_port")
    )
    protocol = layer_data.get("protocol")
    values = (source_ip, source_port, destination_ip, destination_port, protocol)
    if any(not _present(value) for value in values):
        return None
    return (
        str(source_ip),
        str(source_port),
        str(destination_ip),
        str(destination_port),
        str(protocol).lower(),
    )


def _reverse(transport_tuple):
    source_ip, source_port, destination_ip, destination_port, protocol = transport_tuple
    return destination_ip, destination_port, source_ip, source_port, protocol


def _same_transport(left, right):
    return left is not None and right is not None and (
        left == right or left == _reverse(right)
    )


def _record(event):
    return {
        "event": event,
        "raw_ref": str(event["raw_ref"]),
        "timestamp": _timestamp(event.get("timestamp")),
        "transport_tuple": _transport_tuple(event),
    }


def _edge(alert, http, match_mode, candidate_count, dt_sec):
    layer_data = alert["layer_data"]
    return {
        "a": str(alert["raw_ref"]),
        "b": http["raw_ref"],
        "join": JOIN,
        "keys": {
            "match_mode": match_mode,
            "sensor_id": layer_data.get("sensor_id"),
            "flow_id": layer_data.get("flow_id"),
            "tx_id": layer_data.get("tx_id"),
            "dt_sec": round(dt_sec, 6) if dt_sec is not None else None,
            "candidate_count": candidate_count,
        },
    }


@register_linker
def suricata_flow_edges(events, fallback_seconds=DEFAULT_FALLBACK_SECONDS):
    """정규화된 이벤트에서 Suricata Alert↔HTTP edge를 만든다."""
    if isinstance(fallback_seconds, bool) or not isinstance(
        fallback_seconds, (int, float)
    ):
        raise ValueError("fallback_seconds는 0 이상의 숫자여야 함")
    if fallback_seconds < 0:
        raise ValueError("fallback_seconds는 0 이상이어야 함")

    exact_http = defaultdict(list)
    flow_http = defaultdict(list)
    alerts = []

    for event in events:
        if not isinstance(event, dict) or event.get("layer") != "network":
            continue
        layer_data = event.get("layer_data")
        if not isinstance(layer_data, dict) or event.get("raw_ref") in (None, ""):
            continue
        event_type = layer_data.get("event_type")
        if event_type == "http":
            record = _record(event)
            flow_key = _flow_key(event)
            if flow_key is None:
                continue
            flow_http[flow_key].append(record)
            transaction_key = _transaction_key(event)
            if transaction_key is not None:
                exact_http[transaction_key].append(record)
        elif event_type == "alert" and _flow_key(event) is not None:
            alerts.append(event)

    def record_order(record):
        return (
            record["timestamp"] or datetime.min.replace(tzinfo=timezone.utc),
            record["raw_ref"],
        )

    for records in exact_http.values():
        records.sort(key=record_order)
    for records in flow_http.values():
        records.sort(key=record_order)
    alerts.sort(key=lambda event: (str(event.get("timestamp") or ""), str(event["raw_ref"])))

    edges = []
    for alert in alerts:
        alert_timestamp = _timestamp(alert.get("timestamp"))
        transaction_key = _transaction_key(alert)

        if transaction_key is not None:
            candidates = exact_http.get(transaction_key, [])
            for candidate in candidates:
                candidate_timestamp = candidate["timestamp"]
                dt_sec = None
                if alert_timestamp is not None and candidate_timestamp is not None:
                    dt_sec = abs((candidate_timestamp - alert_timestamp).total_seconds())
                edges.append(_edge(
                    alert,
                    candidate,
                    "sensor_flow_tx",
                    len(candidates),
                    dt_sec,
                ))
            continue

        alert_transport = _transport_tuple(alert)
        if alert_timestamp is None or alert_transport is None:
            continue

        candidates = []
        for candidate in flow_http.get(_flow_key(alert), []):
            candidate_timestamp = candidate["timestamp"]
            if candidate_timestamp is None or not _same_transport(
                alert_transport, candidate["transport_tuple"]
            ):
                continue
            dt_sec = abs((candidate_timestamp - alert_timestamp).total_seconds())
            if dt_sec <= float(fallback_seconds):
                candidates.append((candidate, dt_sec))

        if len(candidates) == 1:
            candidate, dt_sec = candidates[0]
            edges.append(_edge(
                alert,
                candidate,
                "flow_tuple_time_fallback",
                1,
                dt_sec,
            ))

    unique = {}
    for edge in edges:
        unique[(edge["a"], edge["b"], edge["join"])] = edge
    return [unique[key] for key in sorted(unique)]


__all__ = ["DEFAULT_FALLBACK_SECONDS", "suricata_flow_edges"]
