import os
import common

def main():

    key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    value = "EnableLUA"
    data = 0

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass

    key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    value = "ConsentPromptBehaviorAdmin"
    data = 0

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass

    key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    value = "PromptOnSecureDesktop"
    data = 0

    with common.temporary_reg(common.HKLM, key, value, data, data_type="dword"):
        pass

if __name__ == "__main__":
    exit(main())
