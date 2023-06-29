import os
import common

dll = common.get_path("bin", "a.dll")
def main():
    odbc = "C:\\Windows\\System32\\odbcconf.exe"

    # Must be executed from the RTA folder, or adjust the path below
    common.execute([odbc, "/S", "/A", "{REGSVR", f"'{dll}'", "}"], timeout=5, kill=True)

if __name__ == "__main__":
    exit(main())
