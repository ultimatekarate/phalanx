import 'dart:async';
import 'dart:collection';
import 'dart:io';

import 'package:app_links/app_links.dart';
import 'package:battery_plus/battery_plus.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'ffi/community_models.dart';
import 'providers/communities_provider.dart';
import 'providers/phalanx_provider.dart';
import 'screens/capture_screen.dart';
import 'screens/community/community_confirm_screen.dart';
import 'screens/community/community_detail_screen.dart';
import 'screens/community/community_join_screen.dart';
import 'screens/community/community_list_screen.dart';
import 'screens/community/community_vouch_screen.dart';
import 'screens/genesis_phrase_screen.dart';
import 'screens/onboarding_choice_screen.dart';
import 'screens/peers_screen.dart';
import 'screens/playback_screen.dart';
import 'screens/restore_phrase_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/verify_phrase_screen.dart';
import 'services/community_link_service.dart';

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
  bool _needsOnboarding = false;
  String? _genesisPhrase;

  // TODO: replace with a hardware-keystore-backed key (Android Keystore /
  // iOS Keychain via flutter_secure_storage). Dev-only placeholder; the
  // identity-at-rest encryption is only as strong as this string until
  // the keystore work lands.
  static const _devPassphrase = 'phalanx-mobile-dev';

  // Deep-link plumbing.
  //
  // R9 ordering: `AppLinks().getInitialLink()` can return the cold-launch
  // URI before Flutter has built its first frame, and therefore before any
  // ProviderScope / Navigator exists. We buffer every URI into
  // [_deepLinkBuffer] until the first frame fires, then drain the buffer.
  final AppLinks _appLinks = AppLinks();
  StreamSubscription<Uri>? _linkSubscription;
  final Queue<Uri> _deepLinkBuffer = Queue<Uri>();
  bool _deepLinkDrained = false;
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initEngine();
    _subscribeDeepLinks();
  }

  Future<void> _initEngine() async {
    try {
      final storagePath = _getStoragePath();
      final dir = Directory(storagePath);
      if (!dir.existsSync()) {
        dir.createSync(recursive: true);
      }

      // Branch on whether an identity is already on disk. If yes, load and
      // proceed normally. If no, surface the onboarding choice — the user
      // either generates a new identity or restores from a recovery phrase.
      // We deliberately do NOT call `bridge.create()` for the no-identity
      // case any more, because `create` silently generates a fresh identity
      // — fine for first-time setup, but it would silently overwrite the
      // recovery flow if the user intends to restore.
      final identityExists =
          File('$storagePath${Platform.pathSeparator}identity.bin').existsSync();

      if (identityExists) {
        await _loadExistingIdentity(storagePath);
      } else {
        setState(() {
          _needsOnboarding = true;
        });
      }
    } catch (e) {
      debugPrint('Phalanx engine init failed: $e');
    }
  }

  Future<void> _loadExistingIdentity(String storagePath) async {
    final bridge = ref.read(phalanxProvider);
    bridge.create(storagePath, _devPassphrase); // returns null on load
    bridge.start();
    setState(() {
      _engineReady = true;
      _needsOnboarding = false;
    });
    _startSensorPolling();
  }

  Future<void> _createNewIdentity() async {
    final bridge = ref.read(phalanxProvider);
    try {
      final storagePath = _getStoragePath();
      final genesisPhrase = bridge.create(storagePath, _devPassphrase);
      bridge.start();
      setState(() {
        _engineReady = true;
        _needsOnboarding = false;
        _genesisPhrase = genesisPhrase;
      });
      _startSensorPolling();
    } catch (e) {
      debugPrint('Phalanx engine init (create) failed: $e');
    }
  }

  void _onRestoredFromPhrase() {
    final bridge = ref.read(phalanxProvider);
    try {
      bridge.start();
      setState(() {
        _engineReady = true;
        _needsOnboarding = false;
      });
      _startSensorPolling();
      // Pop the restore screen back to home (which is now the capture
      // screen because _engineReady just flipped).
      _navigatorKey.currentState?.popUntil((route) => route.isFirst);
    } catch (e) {
      debugPrint('Phalanx engine start (after restore) failed: $e');
    }
  }

  void _pushRestorePhraseScreen() {
    final bridge = ref.read(phalanxProvider);
    _navigatorKey.currentState?.push(
      MaterialPageRoute<void>(
        builder: (_) => RestorePhraseScreen(
          bridge: bridge,
          storagePath: _getStoragePath(),
          passphrase: _devPassphrase,
          onRestored: _onRestoredFromPhrase,
        ),
      ),
    );
  }

  void _subscribeDeepLinks() {
    // Warm-path stream subscription starts right away — it simply enqueues
    // until the first frame has rendered (see [_drainDeepLinks]).
    _linkSubscription = _appLinks.uriLinkStream.listen(
      (uri) => _onDeepLink(uri),
      onError: (Object err) => debugPrint('Deep-link stream error: $err'),
    );

    // Cold-launch path: drain after the first frame so `ProviderScope` and
    // the `Navigator` are both ready to accept a push.
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      try {
        final initial = await _appLinks.getInitialLink();
        if (initial != null) _onDeepLink(initial);
      } catch (e) {
        debugPrint('Failed to read initial deep-link: $e');
      }
      _drainDeepLinks();
    });
  }

  void _onDeepLink(Uri uri) {
    if (!_deepLinkDrained) {
      _deepLinkBuffer.add(uri);
      return;
    }
    _dispatchDeepLink(uri);
  }

  void _drainDeepLinks() {
    _deepLinkDrained = true;
    while (_deepLinkBuffer.isNotEmpty) {
      _dispatchDeepLink(_deepLinkBuffer.removeFirst());
    }
  }

  void _dispatchDeepLink(Uri uri) {
    Uint8List bytes;
    try {
      bytes = decodeJoinPayload(uri.toString());
    } on LinkDecodeError catch (e) {
      debugPrint('Deep-link rejected: ${e.message}');
      final messenger = _navigatorKey.currentState?.overlay?.context;
      if (messenger != null) {
        ScaffoldMessenger.of(messenger).showSnackBar(
          SnackBar(content: Text('Community link rejected: ${e.message}')),
        );
      }
      return;
    }

    // Enqueue for the confirmation screen — R1 requires human review
    // before any import. Never import silently.
    final container = ProviderScope.containerOf(_navigatorKey.currentContext!);
    container.read(pendingJoinQueueProvider.notifier).enqueue(bytes);

    // Push the confirm route. The screen reads its payload from either
    // the routing argument (foreground scan) or the queue (cold/warm
    // deep-link). Here we pass bytes directly.
    _navigatorKey.currentState?.pushNamed(
      '/community/confirm',
      arguments: bytes,
    );
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
    _linkSubscription?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final emergencyMode = ref.watch(emergencyModeProvider);

    // Show loading → onboarding choice → genesis phrase → capture, in
    // sequence. The onboarding choice only appears on a fresh install (no
    // identity.bin on disk). After it lands the user either sees the
    // genesis phrase (new identity) or the capture screen (restored).
    final Widget home;
    if (!_engineReady && _needsOnboarding) {
      home = OnboardingChoiceScreen(
        onCreateNew: _createNewIdentity,
        onRestoreExisting: _pushRestorePhraseScreen,
      );
    } else if (!_engineReady) {
      home = const Scaffold(
        backgroundColor: Colors.black,
        body: Center(child: CircularProgressIndicator(color: Colors.white)),
      );
    } else if (_genesisPhrase != null) {
      home = GenesisPhraseScreen(
        phrase: _genesisPhrase!,
        onAcknowledged: () {
          // R7: after acknowledgment, push the verification screen instead
          // of jumping straight to capture. The phrase stays live in
          // `_genesisPhrase` until verification passes so the back button
          // can return the user to re-review.
          final phrase = _genesisPhrase!;
          _navigatorKey.currentState?.push(
            MaterialPageRoute<void>(
              builder: (_) => VerifyPhraseScreen(
                phrase: phrase,
                onVerified: () {
                  setState(() => _genesisPhrase = null);
                  _navigatorKey.currentState
                      ?.popUntil((route) => route.isFirst);
                },
              ),
            ),
          );
        },
      );
    } else {
      home = CaptureScreen(emergencyMode: emergencyMode);
    }

    return MaterialApp(
      title: 'Phalanx',
      debugShowCheckedModeBanner: false,
      navigatorKey: _navigatorKey,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: Colors.black,
        appBarTheme: AppBarTheme(
          backgroundColor: Colors.grey[900],
          elevation: 0,
        ),
      ),
      home: home,
      onGenerateRoute: _onGenerateRoute,
      routes: {
        '/playback': (_) => const PlaybackScreen(),
        '/peers': (_) => const PeersScreen(),
        '/settings': (_) => const SettingsScreen(),
        '/community': (_) => const CommunityListScreen(),
        '/community/join': (_) => const CommunityJoinScreen(),
        '/community/vouch': (_) => const CommunityVouchScreen(),
      },
    );
  }

  Route<dynamic>? _onGenerateRoute(RouteSettings settings) {
    switch (settings.name) {
      case '/community/confirm':
        final arg = settings.arguments;
        if (arg is Uint8List) {
          return MaterialPageRoute<void>(
            builder: (_) => CommunityConfirmScreen(payloadBytes: arg),
          );
        }
        return null;
      case '/community/detail':
        final arg = settings.arguments;
        if (arg is CommunityId) {
          return MaterialPageRoute<void>(
            builder: (_) => CommunityDetailScreen(communityId: arg),
          );
        }
        return null;
      default:
        return null;
    }
  }
}
