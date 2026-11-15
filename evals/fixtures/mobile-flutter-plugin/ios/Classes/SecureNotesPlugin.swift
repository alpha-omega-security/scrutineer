import Flutter
import Security

public class SecureNotesPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "secure_notes", binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(SecureNotesPlugin(), channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any], let key = args["key"] as? String else {
      result(FlutterError(code: "args", message: "key is required", details: nil))
      return
    }
    switch call.method {
    case "save":
      save(key: key, value: args["value"] as? String ?? "")
      result(nil)
    case "read":
      result(read(key: key))
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func query(_ key: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "secure_notes", kSecAttrAccount as String: key]
  }

  private func save(key: String, value: String) {
    SecItemDelete(query(key) as CFDictionary)
    var item = query(key)
    item[kSecValueData as String] = Data(value.utf8)
    item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    SecItemAdd(item as CFDictionary, nil)
  }

  private func read(key: String) -> String? {
    var item = query(key)
    item[kSecReturnData as String] = true
    var out: AnyObject?
    guard SecItemCopyMatching(item as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
    return String(data: data, encoding: .utf8)
  }
}
