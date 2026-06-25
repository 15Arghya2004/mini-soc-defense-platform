"""
sentrix_core/normalization/plugins.py
Normalization plugins for various event sources.
"""
from sentrix_core.normalization.schema import CanonicalEvent, CanonicalEntity, CanonicalProcess, CanonicalFile, CanonicalUser, CanonicalThreat

def normalize_wazuh(raw: dict) -> CanonicalEvent:
    data = raw.get("data", {})
    rule = raw.get("rule", {})
    
    evt = CanonicalEvent(
        event_type="wazuh_alert",
        severity=str(rule.get("level", "info")),
        raw_event=raw
    )
    if "timestamp" in raw:
        evt.timestamp = raw["timestamp"]
    
    evt.source.ip = data.get("srcip", raw.get("agent", {}).get("ip"))
    evt.source.port = data.get("srcport")
    evt.destination.ip = data.get("dstip")
    evt.destination.port = data.get("dstport")
    
    evt.user.name = data.get("srcuser", data.get("dstuser"))
    
    evt.threat.signature = rule.get("description")
    groups = rule.get("groups", [])
    if groups:
        evt.threat.category = groups[0]
        
    return evt

def normalize_sysmon(raw: dict) -> CanonicalEvent:
    event_data = raw.get("EventData", {})
    sys = raw.get("System", {})
    
    event_id = sys.get("EventID")
    evt_type = f"sysmon_event_{event_id}"
    
    evt = CanonicalEvent(
        event_type=evt_type,
        severity="medium",
        raw_event=raw
    )
    
    if "TimeCreated" in sys and "SystemTime" in sys["TimeCreated"]:
        evt.timestamp = sys["TimeCreated"]["SystemTime"]
        
    # Process Creation
    if event_id == 1:
        evt.process.name = event_data.get("Image", "").split("\\")[-1] if event_data.get("Image") else None
        evt.process.path = event_data.get("Image")
        evt.process.command_line = event_data.get("CommandLine")
        try:
            evt.process.pid = int(event_data.get("ProcessId"))
        except:
            pass
        evt.user.name = event_data.get("User")
        
    # Network Connection
    elif event_id == 3:
        evt.source.ip = event_data.get("SourceIp")
        evt.source.port = event_data.get("SourcePort")
        evt.destination.ip = event_data.get("DestinationIp")
        evt.destination.port = event_data.get("DestinationPort")
        evt.process.name = event_data.get("Image", "").split("\\")[-1] if event_data.get("Image") else None
        
    return evt

def normalize_suricata(raw: dict) -> CanonicalEvent:
    evt = CanonicalEvent(
        event_type=raw.get("event_type", "suricata_alert"),
        severity=str(raw.get("alert", {}).get("severity", "info")),
        raw_event=raw
    )
    if "timestamp" in raw:
        evt.timestamp = raw["timestamp"]
        
    evt.source.ip = raw.get("src_ip")
    evt.source.port = raw.get("src_port")
    evt.destination.ip = raw.get("dest_ip")
    evt.destination.port = raw.get("dest_port")
    
    alert = raw.get("alert", {})
    if alert:
        evt.threat.signature = alert.get("signature")
        evt.threat.category = alert.get("category")
        
    return evt

def normalize_zeek(raw: dict) -> CanonicalEvent:
    """Normalize Zeek (Bro) network logs into CanonicalEvent."""
    log_type = raw.get("_path", raw.get("log_type", "conn"))
    evt = CanonicalEvent(
        event_type=f"zeek_{log_type}",
        severity="info",
        raw_event=raw,
    )
    if "ts" in raw:
        try:
            from datetime import datetime, timezone
            evt.timestamp = datetime.fromtimestamp(float(raw["ts"]), tz=timezone.utc).isoformat()
        except Exception:
            pass

    evt.source.ip = raw.get("id.orig_h") or raw.get("orig_h")
    try:
        evt.source.port = int(raw.get("id.orig_p") or raw.get("orig_p", 0)) or None
    except Exception:
        pass

    evt.destination.ip = raw.get("id.resp_h") or raw.get("resp_h")
    try:
        evt.destination.port = int(raw.get("id.resp_p") or raw.get("resp_p", 0)) or None
    except Exception:
        pass

    proto = raw.get("proto", "")
    evt.network["protocol"] = proto

    # Zeek conn log bytes
    bytes_out = raw.get("orig_bytes")
    if bytes_out is not None:
        evt.network["bytes_out"] = bytes_out

    # Zeek DNS log
    if log_type == "dns":
        query = raw.get("query", "")
        evt.network["dns_query"] = query
        evt.network["dns_query_length"] = len(query)

    # Zeek HTTP log
    if log_type == "http":
        evt.network["http_method"] = raw.get("method")
        evt.network["http_uri"]    = raw.get("uri")
        evt.network["http_host"]   = raw.get("host")
        resp_code = raw.get("status_code")
        if resp_code:
            evt.network["http_status"] = resp_code

    # Zeek files log — hash enrichment
    if log_type in ("files", "pe"):
        md5  = raw.get("md5")
        sha1 = raw.get("sha1")
        if md5:
            evt.file.hash_md5 = md5
        if sha1:
            evt.file.hash_sha256 = sha1  # best available in Zeek

    return evt


def normalize_siem_generic(raw: dict) -> CanonicalEvent:
    """
    Generic SIEM normalization for CEF / LEEF / proprietary JSON events
    that do not match a known source. Maps common field aliases.
    """
    evt = CanonicalEvent(
        event_type=raw.get("event_type", raw.get("eventType", raw.get("type", "siem_event"))),
        severity=str(raw.get("severity", raw.get("level", raw.get("syslog_severity", "info")))),
        raw_event=raw,
    )
    # Timestamp aliases
    for ts_key in ("timestamp", "time", "@timestamp", "eventTime", "startTime"):
        if ts_key in raw:
            evt.timestamp = str(raw[ts_key])
            break

    # Source IP aliases
    for src_key in ("source_ip", "src_ip", "sourceAddress", "src", "cs1"):
        if raw.get(src_key):
            evt.source.ip = raw[src_key]; break

    # Destination IP aliases
    for dst_key in ("destination_ip", "dst_ip", "destinationAddress", "dst", "cs2"):
        if raw.get(dst_key):
            evt.destination.ip = raw[dst_key]; break

    # Port aliases
    for sp_key in ("source_port", "src_port", "sourcePort", "spt"):
        if raw.get(sp_key):
            try: evt.source.port = int(raw[sp_key])
            except Exception: pass
            break

    for dp_key in ("destination_port", "dst_port", "destinationPort", "dpt"):
        if raw.get(dp_key):
            try: evt.destination.port = int(raw[dp_key])
            except Exception: pass
            break

    # User aliases
    for usr_key in ("username", "user", "suser", "duser", "account"):
        if raw.get(usr_key):
            evt.user.name = raw[usr_key]; break

    # Process aliases
    for proc_key in ("process", "process_name", "app", "applicationProtocol"):
        if raw.get(proc_key):
            evt.process.name = raw[proc_key]; break

    for cmd_key in ("command_line", "commandLine", "cmd"):
        if raw.get(cmd_key):
            evt.process.command_line = raw[cmd_key]; break

    return evt


def normalize_generic(raw: dict) -> CanonicalEvent:
    evt = CanonicalEvent(
        event_type=raw.get("event_type", raw.get("type", "generic_alert")),
        severity=str(raw.get("severity", raw.get("level", "info"))),
        raw_event=raw
    )
    evt.timestamp = raw.get("timestamp", raw.get("time", evt.timestamp))

    evt.source.ip = raw.get("source_ip", raw.get("src_ip"))
    evt.destination.ip = raw.get("destination_ip", raw.get("dst_ip"))
    evt.user.name = raw.get("username", raw.get("user"))

    return evt
