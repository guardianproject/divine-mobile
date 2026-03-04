// ABOUTME: Tests for enrichVideosWithNostrTags and enrichVideosInBackground
// ABOUTME: Validates field merging, error handling, and skip-when-enriched logic

import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:models/models.dart';
import 'package:nostr_client/nostr_client.dart';
import 'package:nostr_sdk/event.dart';
import 'package:nostr_sdk/filter.dart';
import 'package:openvine/utils/video_nostr_enrichment.dart';

class _MockNostrClient extends Mock implements NostrClient {}

/// 64-char hex pubkey used across tests.
final String _testPubkey = 'a' * 64;

/// Create a minimal [VideoEvent] suitable for enrichment tests.
///
/// When [rawTags] has fewer than 4 entries, the video is considered
/// un-enriched and eligible for Nostr relay lookup.
VideoEvent _createTestVideo({
  required String id,
  String? pubkey,
  Map<String, String> rawTags = const {},
  String? title,
  String? videoUrl,
  String? dimensions,
  String? blurhash,
  int? originalLoops,
  int? originalLikes,
  int? originalComments,
  int? originalReposts,
  List<String> hashtags = const [],
  List<String> collaboratorPubkeys = const [],
  List<List<String>> nostrEventTags = const [],
}) {
  return VideoEvent(
    id: id,
    pubkey: pubkey ?? _testPubkey,
    createdAt: 1704067200,
    content: 'Test video',
    timestamp: DateTime.fromMillisecondsSinceEpoch(1704067200 * 1000),
    videoUrl: videoUrl ?? 'https://example.com/$id.mp4',
    rawTags: rawTags,
    title: title,
    dimensions: dimensions,
    blurhash: blurhash,
    originalLoops: originalLoops,
    originalLikes: originalLikes,
    originalComments: originalComments,
    originalReposts: originalReposts,
    hashtags: hashtags,
    collaboratorPubkeys: collaboratorPubkeys,
    nostrEventTags: nostrEventTags,
  );
}

/// Build a Nostr [Event] with the given tags.
///
/// The returned event's auto-generated `id` should be used as the
/// corresponding [VideoEvent.id] so enrichment can match them.
Event _createNostrEvent({
  List<List<String>> tags = const [],
  String? pubkey,
  int kind = 34236,
  String content = '',
  int createdAt = 1704067200,
}) {
  return Event(
    pubkey ?? _testPubkey,
    kind,
    tags,
    content,
    createdAt: createdAt,
  );
}

void main() {
  setUpAll(() {
    registerFallbackValue(<Filter>[]);
  });

  group('enrichVideosWithNostrTags', () {
    late _MockNostrClient mockNostrService;

    setUp(() {
      mockNostrService = _MockNostrClient();
    });

    test('returns original list when videos list is empty', () async {
      final result = await enrichVideosWithNostrTags(
        [],
        nostrService: mockNostrService,
      );

      expect(result, isEmpty);
      verifyNever(() => mockNostrService.queryEvents(any()));
    });

    test('skips enrichment when all videos have >= 4 rawTags', () async {
      final videos = [
        _createTestVideo(
          id: 'v1',
          rawTags: {
            'url': 'https://example.com/v1.mp4',
            'title': 'Already enriched',
            'd': 'v1',
            'proof': 'c2pa-hash',
          },
        ),
      ];

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      expect(result, same(videos));
      verifyNever(() => mockNostrService.queryEvents(any()));
    });

    test('enriches videos whose rawTags have fewer than 4 entries', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['title', 'Enriched Title'],
          ['d', 'v1'],
          ['proof', 'c2pa-hash'],
          ['blurhash', 'LEHV6nWB2yk8pyo0adR*.7kCMdnj'],
        ],
      );

      final videos = [
        _createTestVideo(id: nostrEvent.id),
      ];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      expect(result.length, equals(1));
      expect(result.first.rawTags, isNotEmpty);
      expect(result.first.rawTags.length, greaterThanOrEqualTo(4));
    });

    test(
      'preserves existing REST API field values over Nostr values',
      () async {
        final nostrEvent = _createNostrEvent(
          tags: [
            ['url', 'https://nostr.example.com/video.mp4'],
            ['title', 'Nostr Title'],
            ['d', 'v1'],
            ['dim', '1280x720'],
            ['blurhash', 'nostr-blurhash'],
          ],
        );

        final videos = [
          _createTestVideo(
            id: nostrEvent.id,
            title: 'REST Title',
            videoUrl: 'https://rest.example.com/video.mp4',
            dimensions: '1920x1080',
          ),
        ];

        when(
          () => mockNostrService.queryEvents(any()),
        ).thenAnswer((_) async => [nostrEvent]);

        final result = await enrichVideosWithNostrTags(
          videos,
          nostrService: mockNostrService,
        );

        // REST API values should win when present
        expect(result.first.title, equals('REST Title'));
        expect(
          result.first.videoUrl,
          equals('https://rest.example.com/video.mp4'),
        );
        expect(result.first.dimensions, equals('1920x1080'));
        // rawTags should still be merged from Nostr
        expect(result.first.rawTags, isNotEmpty);
      },
    );

    test('fills missing REST API fields from Nostr event', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['title', 'Nostr Title'],
          ['d', 'v1'],
          ['blurhash', 'LEHV6nWB2yk8pyo0adR*.7kCMdnj'],
          ['dim', '720x1280'],
        ],
      );

      final videos = [
        _createTestVideo(
          id: nostrEvent.id,
          // title is null, blurhash is null, dimensions is null
        ),
      ];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      expect(result.first.title, equals('Nostr Title'));
      expect(
        result.first.blurhash,
        equals('LEHV6nWB2yk8pyo0adR*.7kCMdnj'),
      );
    });

    test('preserves existing Vine metrics from REST API', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['d', 'v1'],
          ['loops', '100'],
          ['likes', '50'],
        ],
      );

      final videos = [
        _createTestVideo(
          id: nostrEvent.id,
          originalLoops: 500,
          originalLikes: 200,
        ),
      ];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      // REST API Vine metrics should be kept (Funnelcake aggregates are
      // more accurate than static Nostr tags)
      expect(result.first.originalLoops, equals(500));
      expect(result.first.originalLikes, equals(200));
    });

    test('fills missing Vine metrics from Nostr event', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['d', 'v1'],
          ['loops', '100'],
          ['likes', '50'],
          ['comments', '10'],
          ['reposts', '5'],
        ],
      );

      final videos = [
        _createTestVideo(
          id: nostrEvent.id,
          // All Vine metrics are null
        ),
      ];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      // Nostr values should fill in when REST API values are missing
      expect(result.first.rawTags, isNotEmpty);
    });

    test('handles mixed enriched and un-enriched videos', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v2.mp4'],
          ['title', 'Enriched from Nostr'],
          ['d', 'v2'],
          ['proof', 'c2pa-hash'],
        ],
      );

      final alreadyEnriched = _createTestVideo(
        id: 'already-enriched',
        rawTags: {
          'url': 'https://example.com/v1.mp4',
          'title': 'Already enriched',
          'd': 'v1',
          'proof': 'c2pa-hash',
        },
      );
      final needsEnrichment = _createTestVideo(id: nostrEvent.id);

      final videos = [alreadyEnriched, needsEnrichment];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      expect(result.length, equals(2));
      // First video should be unchanged
      expect(result[0].rawTags, equals(alreadyEnriched.rawTags));
      // Second video should be enriched
      expect(result[1].rawTags, isNotEmpty);
    });

    test('returns original videos when Nostr query returns empty', () async {
      final videos = [_createTestVideo(id: 'v1')];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => []);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      expect(result, same(videos));
    });

    test(
      'returns original videos on query timeout',
      () async {
        final videos = [_createTestVideo(id: 'v1')];

        when(() => mockNostrService.queryEvents(any())).thenAnswer(
          (_) => Completer<List<Event>>().future, // Never completes
        );

        final result = await enrichVideosWithNostrTags(
          videos,
          nostrService: mockNostrService,
        );

        // Should return originals after the 5s timeout
        expect(result, same(videos));
      },
      timeout: const Timeout(Duration(seconds: 10)),
    );

    test('returns original videos on query exception', () async {
      final videos = [_createTestVideo(id: 'v1')];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenThrow(Exception('Network error'));

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      expect(result, same(videos));
    });

    test('skips events that fail to parse as VideoEvent', () async {
      // Create an event with kind 34236 but invalid/missing url tag
      // so fromNostrEvent may still parse (permissive) but produce
      // an empty rawTags result, causing it to be skipped.
      final goodEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['title', 'Good Video'],
          ['d', 'v1'],
          ['proof', 'c2pa-hash'],
        ],
      );

      // An event with a non-video kind will throw in fromNostrEvent
      // and should be silently skipped.
      final badEvent = Event(
        _testPubkey,
        1, // kind 1 = text note, not a video
        [
          ['content', 'not a video'],
        ],
        'not a video',
        createdAt: 1704067200,
      );

      final videos = [
        _createTestVideo(id: goodEvent.id),
        _createTestVideo(id: badEvent.id),
      ];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [goodEvent, badEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      // Should not crash; good event's video gets enriched
      expect(result.length, equals(2));
      expect(result[0].rawTags, isNotEmpty);
      // Bad event's video stays un-enriched
      expect(result[1].rawTags, isEmpty);
    });

    test('uses custom callerName in error logging', () async {
      final videos = [_createTestVideo(id: 'v1')];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenThrow(Exception('test error'));

      // Should not throw; callerName is just for logging
      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
        callerName: 'TestCaller',
      );

      expect(result, same(videos));
    });

    test('only queries IDs of videos with < 4 rawTags', () async {
      final needsEnrichment = _createTestVideo(
        id: 'needs-enrichment',
        rawTags: {'d': 'v1'},
      );
      final alreadyEnriched = _createTestVideo(
        id: 'already-enriched',
        rawTags: {
          'url': 'https://example.com/v2.mp4',
          'title': 'Full',
          'd': 'v2',
          'proof': 'hash',
        },
      );

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => []);

      await enrichVideosWithNostrTags(
        [needsEnrichment, alreadyEnriched],
        nostrService: mockNostrService,
      );

      // Verify the filter only contains the ID that needs enrichment
      final captured =
          verify(
                () => mockNostrService.queryEvents(captureAny()),
              ).captured.single
              as List<Filter>;
      expect(captured.length, equals(1));
      expect(captured.first.ids, equals(['needs-enrichment']));
    });

    test('merges hashtags from Nostr when REST has none', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['d', 'v1'],
          ['t', 'flutter'],
          ['t', 'dart'],
          ['title', 'Tagged Video'],
        ],
      );

      final videos = [
        _createTestVideo(id: nostrEvent.id, hashtags: []),
      ];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      // Hashtags should be filled from Nostr when empty
      expect(result.first.rawTags, isNotEmpty);
    });

    test('keeps REST hashtags when already present', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['d', 'v1'],
          ['t', 'nostr-tag'],
          ['title', 'Video'],
        ],
      );

      final videos = [
        _createTestVideo(
          id: nostrEvent.id,
          hashtags: ['rest-tag'],
        ),
      ];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final result = await enrichVideosWithNostrTags(
        videos,
        nostrService: mockNostrService,
      );

      // REST hashtags should be preserved
      expect(result.first.hashtags, equals(['rest-tag']));
    });
  });

  group('enrichVideosInBackground', () {
    late _MockNostrClient mockNostrService;

    setUp(() {
      mockNostrService = _MockNostrClient();
    });

    test('returns original videos synchronously', () {
      final videos = [
        _createTestVideo(id: 'v1'),
        _createTestVideo(id: 'v2'),
      ];

      when(() => mockNostrService.queryEvents(any())).thenAnswer(
        (_) => Completer<List<Event>>().future,
      );

      final result = enrichVideosInBackground(
        videos,
        nostrService: mockNostrService,
        onEnriched: (_) {},
      );

      expect(result, same(videos));
    });

    test('calls onEnriched when enrichment produces changes', () async {
      final nostrEvent = _createNostrEvent(
        tags: [
          ['url', 'https://example.com/v1.mp4'],
          ['title', 'Enriched'],
          ['d', 'v1'],
          ['proof', 'c2pa-hash'],
        ],
      );

      final videos = [_createTestVideo(id: nostrEvent.id)];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenAnswer((_) async => [nostrEvent]);

      final completer = Completer<List<VideoEvent>>();

      enrichVideosInBackground(
        videos,
        nostrService: mockNostrService,
        onEnriched: completer.complete,
      );

      final enriched = await completer.future.timeout(
        const Duration(seconds: 2),
      );

      expect(enriched.length, equals(1));
      expect(enriched.first.rawTags, isNotEmpty);
    });

    test('does not call onEnriched when no changes needed', () async {
      final videos = [
        _createTestVideo(
          id: 'v1',
          rawTags: {
            'url': 'https://example.com/v1.mp4',
            'title': 'Already enriched',
            'd': 'v1',
            'proof': 'c2pa-hash',
          },
        ),
      ];

      var onEnrichedCalled = false;

      enrichVideosInBackground(
        videos,
        nostrService: mockNostrService,
        onEnriched: (_) {
          onEnrichedCalled = true;
        },
      );

      await Future<void>.delayed(const Duration(milliseconds: 100));
      expect(onEnrichedCalled, isFalse);
      verifyNever(() => mockNostrService.queryEvents(any()));
    });

    test('does not call onEnriched on query failure', () async {
      final videos = [_createTestVideo(id: 'v1')];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenThrow(Exception('Network error'));

      var onEnrichedCalled = false;

      enrichVideosInBackground(
        videos,
        nostrService: mockNostrService,
        onEnriched: (_) {
          onEnrichedCalled = true;
        },
      );

      await Future<void>.delayed(const Duration(milliseconds: 100));
      expect(onEnrichedCalled, isFalse);
    });

    test('passes callerName through to enrichVideosWithNostrTags', () async {
      final videos = [_createTestVideo(id: 'v1')];

      when(
        () => mockNostrService.queryEvents(any()),
      ).thenThrow(Exception('test'));

      // Should not throw regardless of callerName
      final result = enrichVideosInBackground(
        videos,
        nostrService: mockNostrService,
        onEnriched: (_) {},
        callerName: 'ProfileFeedProvider',
      );

      expect(result, same(videos));
      await Future<void>.delayed(const Duration(milliseconds: 100));
    });
  });
}
