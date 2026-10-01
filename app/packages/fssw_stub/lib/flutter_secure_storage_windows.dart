import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';

/// Pure-Dart stand-in for the Windows secure-storage plugin.
///
/// The real plugin compiles C++ that needs ATL/MFC headers (atlstr.h), which
/// a minimal Visual Studio Build Tools install lacks. AlienMsg never calls
/// this on Windows — secrets there go through DPAPI in alien-ffi — so every
/// method here just throws if something does reach it.
class FlutterSecureStorageWindows extends FlutterSecureStoragePlatform {
  FlutterSecureStorageWindows();

  static void registerWith() {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageWindows();
  }

  static Never _unused() =>
      throw UnsupportedError('Windows secrets use DPAPI via alien-ffi');

  @override
  Future<bool> containsKey(
          {required String key, required Map<String, String> options}) =>
      _unused();

  @override
  Future<void> delete(
          {required String key, required Map<String, String> options}) =>
      _unused();

  @override
  Future<void> deleteAll({required Map<String, String> options}) => _unused();

  @override
  Future<String?> read(
          {required String key, required Map<String, String> options}) =>
      _unused();

  @override
  Future<Map<String, String>> readAll(
          {required Map<String, String> options}) =>
      _unused();

  @override
  Future<void> write(
          {required String key,
          required String value,
          required Map<String, String> options}) =>
      _unused();
}
