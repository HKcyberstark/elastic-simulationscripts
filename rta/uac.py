import os
import common
import time

akagi_22 = common.get_path("bin", "22Akagi64.exe")
akagi_23 = common.get_path("bin", "23Akagi64.exe")
akagi_30 = common.get_path("bin", "30Akagi64.exe")
akagi_32 = common.get_path("bin", "32Akagi64.exe")
akagi_33 = common.get_path("bin", "33Akagi64.exe")
akagi_34 = common.get_path("bin", "34Akagi64.exe")
akagi_36 = common.get_path("bin", "36Akagi64.exe")
akagi_38 = common.get_path("bin", "38Akagi64.exe")
akagi_39 = common.get_path("bin", "39Akagi64.exe")
akagi_41 = common.get_path("bin", "41Akagi64.exe")
akagi_43 = common.get_path("bin", "43Akagi64.exe")
akagi_53 = common.get_path("bin", "53Akagi64.exe")
akagi_58 = common.get_path("bin", "58Akagi64.exe")
posh = common.get_path("bin", "uac_tests.ps1")


def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute UACME method 22
    common.execute([akagi_22], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 23
    common.execute([akagi_23], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 30
    common.execute([akagi_30], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 32
    common.execute([akagi_32], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 33
    common.execute([akagi_33], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 34
    common.execute([akagi_34], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 36
    common.execute([akagi_36], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 38
    common.execute([akagi_38], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 39
    common.execute([akagi_39], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 41
    common.execute([akagi_41], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 43
    common.execute([akagi_43], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 53
    common.execute([akagi_53], timeout=45, kill=True)
    time.sleep(5)

    # Execute UACME method 58
    common.execute([akagi_58], timeout=45, kill=True)
    time.sleep(5)

    #Execute the ps1 script with multiple methods
    common.execute([powershell, "/c", posh])

if __name__ == "__main__":
    exit(main())
