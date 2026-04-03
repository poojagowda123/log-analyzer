
print("Starting import test...", flush=True)
try:
    import networkx
    print("NetworkX imported.", flush=True)
    from pyvis.network import Network
    print("PyVis imported.", flush=True)
except Exception as e:
    print(f"Import failed: {e}", flush=True)
    import traceback
    traceback.print_exc()
