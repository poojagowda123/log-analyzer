
import win32evtlog

def check_system_pnp():
    print("--- Searching 'System' Log for Kernel-PnP Events ---")
    server = 'localhost'
    log_name = "System"
    
    try:
        handle = win32evtlog.OpenEventLog(server, log_name)
    except Exception as e:
        print(f"❌ Error: {e}")
        return

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    count = 0
    try:
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
                
            for event in events:
                if event.SourceName == "Microsoft-Windows-Kernel-PnP":
                    # Device Configured (400) or Started (410)
                    if event.EventID in [400, 410, 433]:
                        print(f"✅ FOUND PnP EVENT! [ID {event.EventID}]")
                        print(f"   Time: {event.TimeGenerated}")
                        print(f"   Message info: {event.StringInserts}")
                        count += 1
                        if count >= 5: return # Just show top 5
                        
    except Exception as e:
        print(f"Error iterating: {e}")

if __name__ == "__main__":
    check_system_pnp()
