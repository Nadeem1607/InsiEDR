import os
import glob
import re

collector_dir = r"d:\Projects\AISH\InsiEDR\agent\collectors"
files = glob.glob(os.path.join(collector_dir, "*.py"))

patch_code = """
    try:
        # If this is the very first run (no bookmark), initialize it to the latest record
        # to avoid collecting historical logs.
        if bookmark == 0:
            latest = win32evtlog.ReadEventLog(handle, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            if latest:
                bookmark = latest[0].RecordNumber
                _save_bookmark(bookmark)
                return []
    except Exception:
        pass
"""

for file_path in files:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # We need to find where handle is initialized. Usually: `handle = win32evtlog.OpenEventLog(...)`
    # Let's just do it manually for safety.
