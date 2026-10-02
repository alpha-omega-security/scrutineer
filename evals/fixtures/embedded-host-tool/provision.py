import argparse

import serial


def send(port, firmware):
    with open(firmware, "rb") as handle:
        data = handle.read()
    with serial.Serial(port, 115200, timeout=2) as link:
        link.write(len(data).to_bytes(4, "big"))
        link.write(data)
        return link.readline().decode().strip()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Write a firmware file to a board")
    parser.add_argument("port")
    parser.add_argument("firmware")
    args = parser.parse_args()
    print(send(args.port, args.firmware))
