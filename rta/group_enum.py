import os
import common

posh = common.get_path("bin", "enum.ps1")


def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    common.execute([powershell, "/c", posh], timeout=30)

if __name__ == "__main__":
    exit(main())
