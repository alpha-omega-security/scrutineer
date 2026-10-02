import network

import settings


def connect():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(settings.SSID, settings.PASSWORD)
    return wlan


connect()
