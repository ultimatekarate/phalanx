import 'dart:async';
import 'dart:io';

import 'package:battery_plus/battery_plus.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'providers/phalanx_provider.dart';
import 'screens/capture_screen.dart';
import 'screens/genesis_phrase_screen.dart';
import 'screens/peers_screen.dart';
import 'screens/playback_screen.dart';
import 'screens/settings_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  // Lock to portrait — evidence capture is portrait-first
  SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
  ]);

  // Full-screen immersive — no status bar, no nav bar
  SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);

  runApp(const ProviderScope(child: PhalanxApp()));
}

class PhalanxApp extends ConsumerStatefulWidget {
  const PhalanxApp({super.key});

  @override
  ConsumerState<PhalanxApp> createState() => _PhalanxAppState();
}

class _PhalanxAppState extends ConsumerState<PhalanxApp>
    with WidgetsBindingObserver {
  final Battery _battery = Battery();
  Timer? _sensorTimer;
  bool _engineReady = false;
  String? _genesisPhrase;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initEngine();
  }

  Future<void> _initEngine() async {
    final bridge = ref.read(phalanxProvider);

    try {
      // Storage path: app documents directory
      final storagePath = _getStoragePath();
      // Ensure storage directory exists before Rust bootstrap
      final dir = Directory(storagePath);
      if (!dir.existsSync()) {
        dir.createSync(recursive: true);
      }
      // TODO: In production, prompt user for passphrase on first run,
      // store in secure keychain. For now, use environment or default.
      const passphrase = 'phalanx-mobile-dev';

      final genesisPhrase = bridge.create(storagePath, passphrase);
      bridge.start();

      setState(() {
        _engineReady = true;
        _genesisPhrase = genesisPhrase;
      });

      // Start sensor polling
      _startSensorPolling();
    } catch (e) {
      debugPrint('Phalanx engine init failed: $e');
    }
  }

  String _getStoragePath() {
    // Platform-specific app data directory
    if (Platform.isAndroid) {
      return '/data/data/com.phalanx.app/files/phalanx';
    } else if (Platform.isIOS) {
      return '${Platform.environment['HOME']}/Documents/phalanx';
    }
    return './phalanx_data';
  }

  void _startSensorPolling() {
    // Push battery + thermal readings to Rust every 10 seconds
    _sensorTimer = Timer.periodic(const Duration(seconds: 10), (_) async {
      if (!_engineReady) return;
      final bridge = ref.read(phalanxProvider);

      try {
        final level = await _battery.batteryLevel;
        final state = await _battery.batteryState;
        bridge.updateBattery(
          level,
          state == BatteryState.charging || state == BatteryState.full,
        );

        // Thermal: platform-specific. Default to 25C if unavailable.
        bridge.updateThermal(25);
      } catch (_) {
        // Sensor read failed — non-fatal
      }
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!_engineReady) return;
    final bridge = ref.read(phalanxProvider);

    switch (state) {
      case AppLifecycleState.resumed:
        bridge.updateLifecycle(true); // Foregrounded
        break;
      case AppLifecycleState.paused:
      case AppLifecycleState.inactive:
      case AppLifecycleState.detached:
      case AppLifecycleState.hidden:
        bridge.updateLifecycle(false); // Backgrounded → Dormant
        break;
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _sensorTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final emergencyMode = ref.watch(emergencyModeProvider);

    // Show loading → genesis phrase → capture, in sequence
    final Widget home;
    if (!_engineReady) {
      home = const Scaffold(
        backgroundColor: Colors.black,
        body: Center(child: CircularProgressIndicator(color: Colors.white)),
      );
    } else if (_genesisPhrase != null) {
      home = GenesisPhraseScreen(
        phrase: _genesisPhrase!,
        onAcknowledged: () {
          setState(() => _genesisPhrase = null);
        },
      );
    } else {
      home = CaptureScreen(emergencyMode: emergencyMode);
    }

    return MaterialApp(
      title: 'Phalanx',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: Colors.black,
        appBarTheme: AppBarTheme(
          backgroundColor: Colors.grey[900],
          elevation: 0,
        ),
      ),
      home: home,
      routes: {
        '/playback': (_) => const PlaybackScreen(),
        '/peers': (_) => const PeersScreen(),
        '/settings': (_) => const SettingsScreen(),
      },
    );
  }
}
