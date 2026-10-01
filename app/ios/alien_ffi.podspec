Pod::Spec.new do |s|
  s.name             = 'alien_ffi'
  s.version          = '0.1.0'
  s.summary          = 'AlienMsg Rust crypto core (static XCFramework).'
  s.homepage         = 'https://local.invalid'
  s.license          = { :type => 'Proprietary' }
  s.author           = { 'AlienMsg' => 'dev@local.invalid' }
  s.source           = { :path => '.' }
  s.vendored_frameworks = 'Frameworks/AlienFfi.xcframework'
  s.platform         = :ios, '12.0'
  s.static_framework = true
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version    = '5.0'
end
