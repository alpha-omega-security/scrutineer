# Sensor firmware

`boot.py` joins Wi-Fi at power-up. `main.py` polls the update server and applies
what it downloads. `ota.py` holds the firmware update logic and
`config_bundle.py` the signed configuration logic. Neither has hardware
imports, so both can be exercised on a desktop.

The device provisions `DEVICE_KEY` at the factory. Configuration bundles are
signed with the matching fleet key and carry a monotonic version.
