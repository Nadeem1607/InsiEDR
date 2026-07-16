import logging
import platform
import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, List, Dict

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger("dns_monitor")

class DNSMonitorCollector(BaseCollector):
    """
    Audits DNS queries from the Windows DNS Client Operational log.
    Captures network intent even if browser history or network connections are obfuscated.
    """
    name = "dns-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.channel = "Microsoft-Windows-DNS-Client/Operational"
        self.event_ids = {3008} # DNS Query events

    def _parse_dns_event(self, xml_text: str) -> Dict[str, Any] | None:
        try:
            root = ET.fromstring(xml_text)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            # Extract data fields
            data_nodes = root.findall(".//e:Data", namespaces=ns)
            data = {node.get("Name"): node.text for node in data_nodes if node.get("Name")}
            
            # Extract system fields
            system = root.find("e:System", namespaces=ns)
            time_node = system.find("e:TimeCreated", namespaces=ns) if system is not None else None
            ts_str = time_node.get("SystemTime") if time_node is not None else None
            
            execution = system.find("e:Execution", namespaces=ns) if system is not None else None
            pid = execution.get("ProcessID") if execution is not None else None

            return {
                "query": data.get("QueryName"),
                "query_type": data.get("QueryType"),
                "status": data.get("QueryStatus"),
                "pid": int(pid) if pid else None,
                "timestamp": ts_str
            }
        except Exception:
            return None

    def _load_bookmark(self) -> int:
        from agent.state import default_state_dir, read_json_file
        bookmark_file = default_state_dir() / "dns_monitor_bookmark.json"
        try:
            if bookmark_file.exists():
                return int(read_json_file(bookmark_file).get("last_record_number", 0))
        except Exception:
            pass
        return 0

    def _save_bookmark(self, record_number: int) -> None:
        from agent.state import default_state_dir, write_json_file
        bookmark_file = default_state_dir() / "dns_monitor_bookmark.json"
        try:
            write_json_file(bookmark_file, {
                "last_record_number": record_number,
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
        except Exception:
            pass

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32evtlog is None:
            return self.unsupported("DNS monitor requires Windows with pywin32.")

        try:
            bookmark = self._load_bookmark()
            max_record = bookmark
            
            # Query ONLY new DNS activity within the last 5 minutes to completely block old logs
            query = f"*[System[EventID=3008 and EventRecordID > {bookmark} and TimeCreated[timediff(@SystemTime) <= 300000]]]"
            handle = win32evtlog.EvtQuery(self.channel, win32evtlog.EvtQueryReverseDirection, query)
            
            queries = []
            seen_queries = set()
            
            count = 0
            while count < 500:
                events = win32evtlog.EvtNext(handle, 10)
                if not events:
                    break
                
                for event in events:
                    xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    
                    # Extract EventRecordID to update the bookmark
                    root = ET.fromstring(xml)
                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    record_node = root.find(".//e:System/e:EventRecordID", namespaces=ns)
                    rec_id = int(record_node.text) if record_node is not None else 0
                    if rec_id > max_record:
                        max_record = rec_id
                    
                    parsed = self._parse_dns_event(xml)
                    if parsed and parsed["query"]:
                        queries.append(parsed)
                        seen_queries.add(parsed["query"].lower())
                    count += 1
            
            self._save_bookmark(max_record)
            
            payload = {
                "dns_queries": queries[:100], # Detailed sample
                "total_queries_captured": len(queries),
                "unique_domains_queried": len(seen_queries),
                "channel": self.channel
            }
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            if "Access is denied" in str(exc):
                return self.unsupported("Access denied to DNS Client logs. Elevated privileges required.", quality="permission_limited")
            log.exception("DNS collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return DNSMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(collect(), indent=2))
