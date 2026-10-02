import json
import machine
import socket

import ota
import web

RELAY = machine.Pin(5, machine.Pin.OUT)


def serve():
    listener = socket.socket()
    listener.bind(("0.0.0.0", 80))
    listener.listen(1)
    while True:
        conn, _ = listener.accept()
        head, _, body = conn.recv(2048).decode().partition("\r\n\r\n")
        lines = head.split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
        status, payload = web.dispatch(method, path, headers, body)
        conn.send(("HTTP/1.0 %d\r\n\r\n" % status + json.dumps(payload)).encode())
        conn.close()
        RELAY.value(1 if web.SETTINGS["relay"] else 0)


serve()
