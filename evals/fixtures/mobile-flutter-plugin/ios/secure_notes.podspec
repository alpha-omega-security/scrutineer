Pod::Spec.new do |s|
  s.name             = 'secure_notes'
  s.version          = '0.3.1'
  s.summary          = 'Store short notes in the iOS Keychain.'
  s.homepage         = 'https://github.com/example/secure_notes'
  s.license          = { :type => 'MIT' }
  s.author           = 'Example'
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform         = :ios, '12.0'
  s.swift_version    = '5.0'
end
