
import win32evtlog
import time

def deep_scan_pnp():
    print("--- DEEP SCAN: Microsoft-Windows-Kernel-PnP ---")
    server = 'localhost'
    try:
        handle = win32evtlog.OpenEventLog(server, "System")
    except Exception as e:
        print(f"Failed to open System log: {e}")
        return

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    print("Scanning last 100 System events for ANY Kernel-PnP activity...")
    
    count = 0
    pnp_found = 0
    
    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events: break
        
        for event in events:
            count += 1
            if count > 2000: # Limit scan depth
                break
                
            if event.SourceName == "Microsoft-Windows-Kernel-PnP":
                pnp_found += 1
                if pnp_found > 10: break # Just show last 10 
                
                print(f"\n[EVENT FOUND]")
                print(f"Event ID: {event.EventID}")
                print(f"Time: {event.TimeGenerated}")
                try:
                    data = str(event.StringInserts)
                    print(f"Data: {data}")
                except:
                    print("Data: <Unreadable>")
                    
    print(f"\nScan Complete. Scanned {count} events, found {pnp_found} PnP events.")

if __name__ == "__main__":
    deep_scan_pnp()
