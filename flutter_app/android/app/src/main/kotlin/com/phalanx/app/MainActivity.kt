package com.phalanx.app

import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/// MainActivity hosts the Flutter engine and a small method channel for
/// platform-level toggles that have no good plugin equivalent.
///
/// Channels:
///   - `phalanx/screen_security` — toggles `FLAG_SECURE` on the window
///     to block screenshots, screen recording, and the recents-screen
///     thumbnail. See `lib/services/screen_security.dart`.
class MainActivity : FlutterActivity() {
    private val screenSecurityChannel = "phalanx/screen_security"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, screenSecurityChannel)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "setSecure" -> {
                        val enabled = call.arguments as? Boolean
                        if (enabled == null) {
                            result.error("INVALID_ARG", "setSecure expects a Boolean", null)
                            return@setMethodCallHandler
                        }
                        // FLAG_SECURE must be toggled on the UI thread. We're
                        // on the platform thread here, which is fine for
                        // setFlags/clearFlags per Android docs.
                        if (enabled) {
                            window.setFlags(
                                WindowManager.LayoutParams.FLAG_SECURE,
                                WindowManager.LayoutParams.FLAG_SECURE,
                            )
                        } else {
                            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        }
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }
}
