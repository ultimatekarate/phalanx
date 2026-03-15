import 'dart:ffi';
import 'dart:io';

/// Loads the native phalanx-ffi shared library for the current platform.
///
/// Android: loads `libphalanx_ffi.so` via DynamicLibrary.open
/// iOS: uses DynamicLibrary.process() (statically linked)
DynamicLibrary loadPhalanxLibrary() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libphalanx_ffi.so');
  } else if (Platform.isIOS) {
    return DynamicLibrary.process();
  } else {
    throw UnsupportedError(
      'Phalanx is not supported on ${Platform.operatingSystem}',
    );
  }
}
