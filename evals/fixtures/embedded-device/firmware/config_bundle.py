import hashlib
import hmac
import json


def apply_config_bundle(bundle, signature, state, device_key):
    """Apply a fleet configuration bundle signed with the provisioned key."""
    expected = hmac.new(device_key, bundle, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return False
    config = json.loads(bundle)
    if config["version"] <= state["config_version"]:
        return False
    state["config_version"] = config["version"]
    state["config"] = config["values"]
    return True
