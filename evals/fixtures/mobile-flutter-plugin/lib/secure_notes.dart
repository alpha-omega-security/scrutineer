import 'package:flutter/services.dart';

class SecureNotes {
  static const MethodChannel _channel = MethodChannel('secure_notes');

  static Future<void> save(String key, String value) =>
      _channel.invokeMethod('save', {'key': key, 'value': value});

  static Future<String?> read(String key) =>
      _channel.invokeMethod<String>('read', {'key': key});
}
