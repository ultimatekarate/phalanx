import 'dart:io';

import 'package:flutter/services.dart';

/// Toggle platform-level screen capture protection for screens displaying
/// the BIP-39 recovery phrase.
///
/// **Android**: sets `FLAG_SECURE` on the activity's window via a method
/// channel. This blocks screenshots, screen recording, and the recents-
/// screen thumbnail. Symmetric `enableSecure()` / `disableSecure()` calls
/// keep the rest of the app screenshottable.
///
/// **iOS**: Apple doesn't expose a screenshot-prevention API. The Flutter
/// `AppDelegate` would need a `UIApplicationWillResignActiveNotification`
/// observer that overlays a blur view (covering the multitasking snapshot
/// Apple captures on backgrounding) and a `UIScreen.isCaptured` observer
/// for screen recording. iOS support is currently a no-op stub: when the
/// `AppDelegate` is in place, fill in the method-channel handler and the
/// calls below will start working without changing this Dart API.
class ScreenSecurity {
  ScreenSecurity._();

  static const _channel = MethodChannel('phalanx/screen_security');
  static int _enabledRefcount = 0;

  /// Enable screen-capture protection. Reference-counted: nested calls
  /// stack, so each `enableSecure()` must be paired with a `disableSecure()`.
  /// Only the first `enable` and the last `disable` actually touch the
  /// platform (avoids race conditions when multiple sensitive screens are
  /// open, e.g., the genesis screen on top of which a dialog appears).
  static Future<void> enableSecure() async {
    _enabledRefcount++;
    if (_enabledRefcount == 1) {
      await _setSecure(true);
    }
  }

  /// Disable screen-capture protection. Idempotent below zero (refcount
  /// is clamped) so a runaway `disable` won't accidentally turn off
  /// security for a still-active sensitive screen.
  static Future<void> disableSecure() async {
    if (_enabledRefcount == 0) return;
    _enabledRefcount--;
    if (_enabledRefcount == 0) {
      await _setSecure(false);
    }
  }

  static Future<void> _setSecure(bool enabled) async {
    try {
      if (Platform.isAndroid) {
        await _channel.invokeMethod<void>('setSecure', enabled);
      }
      // iOS: stub. The platform channel handler doesn't exist yet; the
      // call would throw a MissingPluginException. Skip cleanly until
      // the AppDelegate scaffold lands.
    } on PlatformException {
      // Best-effort: never propagate a screen-security error up the
      // widget tree. A failed enable just leaves the screenshot path open
      // — degraded but not broken. The phrase warnings in the UI remain.
    } on MissingPluginException {
      // Same: silently degrade on platforms without a handler installed.
    }
  }
}
