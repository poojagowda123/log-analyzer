
import wmi
import time

def monitor_usb_realtime():
    print("Monitoring USB insertion (Press Ctrl+C to stop)...")
    raw_wql = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity'"
    c = wmi.WMI()
    watcher = c.watch_for(raw_wql=raw_wql)
    
    while True:
        try:
            usb = watcher()
            if 'USB' in usb.TargetInstance.Caption:
                print(f"✅ New USB Device Detected: {usb.TargetInstance.Caption}")
                print(f"   DeviceID: {usb.TargetInstance.DeviceID}")
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    monitor_usb_realtime()
