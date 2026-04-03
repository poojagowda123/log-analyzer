import win32evtlog

def read_security_logs():
    server = 'localhost'            # Local machine
    log_type = 'Security'           # Security log (authentication, access, etc.)
    
    print("Reading Windows Security Logs...")

    # Open event log
    handle = win32evtlog.OpenEventLog(server, log_type)
    
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break
        
        for event in events:
            print("----- EVENT -----")
            print("Time:", event.TimeGenerated)
            print("Event ID:", event.EventID)
            print("Source:", event.SourceName)
            print("Message:", event.StringInserts)
            print("-----------------")

if __name__ == "__main__":
    read_security_logs()
