from pathlib import Path
case_root = Path("TriDsk-WKS02-C.1dfcd21bd3d01cc0-F.D3JVHAK4B16NM")
source = r"C:\Windows\System32\winevt\Logs\Security.evtx"
parts = source.split("\\")
drive = parts[0].replace(":", "%3A")
p = case_root / "uploads" / "auto" / drive / Path(*parts[1:])
print(p)
print(p.exists())
print(p.stat().st_size if p.exists() else None)
