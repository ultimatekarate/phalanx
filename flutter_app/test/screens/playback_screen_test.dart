import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';

import 'package:phalanx/ffi/phalanx_bridge.dart';
import 'package:phalanx/providers/phalanx_provider.dart';
import 'package:phalanx/screens/playback_screen.dart';

/// Mock bridge — overrides the Riverpod provider so no native library is loaded.
///
/// PhalanxBridge's constructor loads a DynamicLibrary, which fails in test.
/// Mocktail generates a subclass that never calls super(), so the native
/// bindings are never touched.
class MockPhalanxBridge extends Mock implements PhalanxBridge {}

void main() {
  late MockPhalanxBridge mockBridge;

  setUp(() {
    mockBridge = MockPhalanxBridge();
    // Default stubs for the recording list poll
    when(() => mockBridge.listRecordings()).thenReturn([]);
  });

  Widget buildTestApp({List<Override> overrides = const []}) {
    return ProviderScope(
      overrides: [
        phalanxProvider.overrideWithValue(mockBridge),
        ...overrides,
      ],
      child: const MaterialApp(
        home: PlaybackScreen(),
      ),
    );
  }

  group('PlaybackScreen', () {
    testWidgets('shows empty state when no recordings', (tester) async {
      await tester.pumpWidget(buildTestApp());
      await tester.pumpAndSettle();

      expect(find.text('No recordings yet.\nPress the red button to start.'), findsOneWidget);
      expect(find.text('Recordings'), findsOneWidget);
    });

    testWidgets('shows recording list when recordings exist', (tester) async {
      when(() => mockBridge.listRecordings()).thenReturn([
        'rec-did:key:-1709294400000',
        'rec-did:key:-1709294460000',
      ]);
      when(() => mockBridge.debugRecordingInfo(any())).thenReturn('shards=50,key=true');

      await tester.pumpWidget(buildTestApp());
      await tester.pumpAndSettle();

      // Should show formatted timestamps (not raw IDs)
      expect(find.byType(ListTile), findsNWidgets(2));
    });

    testWidgets('has correct app bar title', (tester) async {
      await tester.pumpWidget(buildTestApp());
      await tester.pumpAndSettle();

      expect(find.text('Recordings'), findsOneWidget);
    });

    testWidgets('scaffold has black background', (tester) async {
      await tester.pumpWidget(buildTestApp());
      await tester.pumpAndSettle();

      final scaffold = tester.widget<Scaffold>(find.byType(Scaffold));
      expect(scaffold.backgroundColor, Colors.black);
    });

    testWidgets('list tile has popup menu with all actions', (tester) async {
      when(() => mockBridge.listRecordings()).thenReturn([
        'rec-did:key:-1709294400000',
      ]);
      when(() => mockBridge.debugRecordingInfo(any())).thenReturn('shards=10,key=true');

      await tester.pumpWidget(buildTestApp());
      await tester.pumpAndSettle();

      // Tap the popup menu button
      await tester.tap(find.byIcon(Icons.more_vert));
      await tester.pumpAndSettle();

      expect(find.text('Play'), findsOneWidget);
      expect(find.text('Share'), findsOneWidget);
      expect(find.text('Delete (debug)'), findsOneWidget);
      expect(find.text('Forget Forever'), findsOneWidget);
    });
  });
}
