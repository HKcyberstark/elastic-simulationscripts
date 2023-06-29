import os
import common

posh = common.get_path("bin", "wmi.ps1")


def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    common.execute([powershell, "/c", posh], timeout=30, kill=True)

if __name__ == "__main__":
    exit(main())
