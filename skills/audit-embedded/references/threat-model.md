# Embedded and IoT threat model

## Reference and limits

This is original, source-review guidance informed by the [OWASP IoT Security Verification Standard (ISVS) 1.0RC](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/tree/1.0RC/en), not a reproduction of the standard or an ISVS compliance assessment. ISVS 1.0RC is a release candidate, so treat its structure as provisional. Use the tag-pinned chapter links below; applicability depends on the software actually implemented on the device. Source review cannot establish fuse settings, secure boot configuration in ROM, secure-element behavior, manufacturing processes, radio behavior or production keys without additional evidence.

## Actors and assets

Distinguish a remote network attacker, a local network or radio-proximity attacker, an attacker with physical access to debug ports or flash, a malicious update server or on-path attacker, a compromised companion app or cloud service and a privileged manufacturer or provisioning station. Do not silently grant the attacker the signing key, a production debug unlock or a decapped chip. Protect firmware integrity, version monotonicity, device identity and credentials, provisioning secrets, user data and safety-relevant actuation.

Inventory each relevant boundary as an entry point, attacker-controlled value, effective guard chain and device-side effect. Include checks performed by a bootloader or ROM that are visible in the checkout, vendor SDK defaults pinned by the build and actions started by a received message. Record a component outside the scoped checkout, such as the bootloader, secure element firmware or cloud service, as unavailable evidence rather than treating it as unguarded.

## Firmware updates and rollback

References: [V1 IoT Ecosystem](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V1-IoT_Ecosystem_Requirements.md), [V3 Software Platform](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V3-Software_Platform_Requirements.md).

Trace an update from the transport that delivers the image to the code that writes flash and marks a slot bootable. Look for authenticity checks that bind the image to a trusted key, such as a signature verified with a key stored on the device. A hash that arrives in the same unauthenticated manifest or channel as the image proves only transfer integrity, so an attacker who controls the server or network can supply any image and its digest. Check that verification happens before the slot is marked bootable and that the verified bytes are the bytes written. Look for version or counter checks that stop an attacker replaying an older signed image or configuration. Check where the counter is stored. Trust in a TLS channel is a design property only when certificate validation is enabled and the trust anchor is appropriate; disabled verification is a finding when it carries an update. A rollback guard enforced only by the update server is an assumption about the device. Separate an absent rollback counter from an intentional recovery path that is documented and gated.

## Boot chain

Reference: [V3 Software Platform](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V3-Software_Platform_Requirements.md).

Identify what the bootloader or first-stage code verifies before transferring control. Also check what it trusts from writable storage such as environment variables, a boot configuration file or an unsigned secondary image. Source patterns include a loader that jumps to an address read from flash without verification, a fallback that boots an unverified slot or a signature check whose result is ignored on an error path. Whether the ROM enforces secure boot, whether the verification key is fused and whether the slot layout is locked depend on hardware and manufacturing evidence, so record them as unverified assumptions unless the checkout proves otherwise. A downgrade to a documented factory image gated by physical presence is a design property, not an automatic finding.

## Provisioning and device credentials

References: [V2 User Space Application](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V2-User_Space_Application_Requirements.md), [V1 IoT Ecosystem](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V1-IoT_Ecosystem_Requirements.md).

Trace how a device obtains its identity and secrets: factory injection, first-boot enrollment, a pairing flow or a cloud claim. Look for credentials compiled into firmware that are shared by every unit, passwords derived from public identifiers such as a MAC address or serial number, provisioning endpoints left reachable after enrollment and secrets written to logs or exposed over a debug console. A per-device secret stored in protected storage is a design property when the checkout shows how it is generated and bound. A shared default credential that the first-party code accepts for a privileged operation is a finding when it is reachable without physical access. Whether secrets are unique per unit at the factory, whether a secure element holds them and whether the provisioning station is trusted are manufacturing facts to record as assumptions.

## Debug interfaces and physical access

Reference: [V5 Hardware Platform](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V5-Hardware_Platform_Requirements.md).

Look in firmware for debug shells, test commands, UART consoles that accept privileged input, hidden backdoor commands or code that enables a debug port or disables a lock at runtime. A debug command reachable from the network or radio is a finding when it grants a privileged effect. A console that needs physical access is a design property when the product's threat model scopes physical attackers out. It is a finding only when the checkout states a stronger guarantee that the code violates. JTAG or SWD lock state, readout protection, fuse programming and tamper detection are hardware properties that source cannot establish, so record them as unverified assumptions with the evidence needed. Do not report a missing physical hardening feature alone.

## Device communication

Reference: [V4 Communication](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/1.0RC/en/V4-Communication_Requirements.md).

Cover machine-to-machine protocols such as MQTT and CoAP, Bluetooth services and pairing, Wi-Fi setup and local discovery. Trace each received message to its handler and ask who may send it, how the sender is authenticated and what device effect results. Look for disabled certificate validation, a pairing mode that accepts any peer without user confirmation, unauthenticated control characteristics, setup access points with fixed credentials that stay open and discovery responses that disclose secrets. An unauthenticated read-only status broadcast can be an intended property. When the device exposes an HTTP management interface, `audit-web` covers it; here, record only the device-specific effects it reaches. Use `audit-memory` for parser memory safety rather than duplicating its checklist.

## Evidence discipline

Every vulnerability needs a reachable first-party source-to-effect path and a concrete security consequence under stated attacker prerequisites. Record checked enforcement points as negative results, intentional semantics as design properties and anything that needs hardware, fuse, secure-element, manufacturing or deployment evidence as an unverified assumption. Static review establishes a source argument, not an executed reproduction, ISVS certification or hardware testing.
