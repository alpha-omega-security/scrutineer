# secure_notes

A Flutter plugin that stores short notes in the platform keystore: the Android Keystore through `SecureNotesPlugin.kt` and the iOS Keychain through `SecureNotesPlugin.swift`. Apps call `SecureNotes.save` and `SecureNotes.read` from Dart. The `example/` app exists only to exercise the plugin during development and is not published.
