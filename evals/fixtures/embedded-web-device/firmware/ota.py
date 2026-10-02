import hashlib


def install(image, manifest, flash_write):
    if hashlib.sha256(image).hexdigest() != manifest["sha256"]:
        return False
    flash_write("b", image)
    return True
