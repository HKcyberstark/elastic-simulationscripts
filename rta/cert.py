import os
import common

procmon = common.get_path("bin", "procmon.exe")


def main():

    common.execute([procmon, "/AcceptEula"])

if __name__ == "__main__":
    exit(main())
