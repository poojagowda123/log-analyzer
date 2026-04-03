
import win32evtlog
import traceback

def check_log(log_name):
    print(f"--- Checking Log: {log_name} ---")
    server = 'localhost'
    try:
        handle = win32evtlog.OpenEventLog(server, log_name)
    except Exception as e:
        print(f"❌ Could not open {log_name}: {e}")
        return

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    try:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            print(f"⚠️  Log {log_name} is accessible but appears EMPTY (or no recent events).")
        else:
            print(f"✅ Found {len(events)} recent events in {log_name}. Showing top 5:")
            for i, event in enumerate(events[:5]):
                print(f"   [{event.TimeGenerated}] ID: {event.EventID} Source: {event.SourceName}")
                
    except Exception as e:
        print(f"❌ Error reading {log_name}: {e}")

if __name__ == "__main__":
    # Check the one we rely on
    check_log("Microsoft-Windows-DriverFrameworks-UserMode/Operational")
    
    # Check the fallback/alternative
    check_log("System")
