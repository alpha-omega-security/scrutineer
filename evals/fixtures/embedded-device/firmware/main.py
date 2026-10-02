import json
import machine
import urequests

import config_bundle
import ota
import settings

STATE = {"boot_slot": "a", "config_version": 0, "pending": False}
SLOTS = {"a": 0x10000, "b": 0x110000}


def flash_write(slot, image):
    # Device glue: writes the inactive slot through the flash controller.
    flash = machine.Flash(SLOTS[slot])
    flash.write(image)


def check_updates():
    manifest = json.loads(urequests.get(settings.UPDATE_URL + "/manifest.json").text)
    image = urequests.get(manifest["url"]).content
    ota.apply_update(image, manifest, STATE, flash_write)
    if STATE["pending"]:
        machine.reset()


def check_config():
    with open("/device.key", "rb") as handle:
        device_key = handle.read()
    reply = urequests.get(settings.UPDATE_URL + "/config.json").json()
    config_bundle.apply_config_bundle(reply["bundle"].encode(), bytes.fromhex(reply["signature"]), STATE, device_key)


check_updates()
