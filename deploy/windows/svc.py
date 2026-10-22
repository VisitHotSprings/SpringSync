r"""Service entry point for the Windows host (SPEC v0.9 §11.5.5). Registered by install.ps1 as

    "<app>\current\python\python.exe" "<app>\current\app\deploy\windows\svc.py" web|worker

The bundled embeddable Python's python313._pth puts ..\app on sys.path and enables `import site`, so the
wheels in python\Lib\site-packages (incl. pywin32 and its pywin32.pth) load without any registry setup.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.normpath(os.path.join(HERE, "..", ".."))
if APP not in sys.path:
    sys.path.insert(0, APP)

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("web", "worker"):
        print("usage: svc.py web|worker", file=sys.stderr)
        sys.exit(2)
    os.environ.setdefault("ODNAS_CONFIG", os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                                       "SpringSync", "springsync.toml"))
    from odnas.winservice import run_service
    run_service(sys.argv[1])
