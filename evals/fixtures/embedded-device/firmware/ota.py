import hashlib


def inactive_slot(state):
    return "b" if state["boot_slot"] == "a" else "a"


def apply_update(image, manifest, state, flash_write):
    """Install a downloaded firmware image into the inactive slot.

    The manifest and the image both come from the update server.
    """
    if hashlib.sha256(image).hexdigest() != manifest["sha256"]:
        return False
    slot = inactive_slot(state)
    flash_write(slot, image)
    state["boot_slot"] = slot
    state["pending"] = True
    return True
