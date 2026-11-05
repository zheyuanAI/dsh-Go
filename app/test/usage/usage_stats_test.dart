// Anonymous usage statistics end to end on the phone's side, the network
// faked: nothing before the person was told; each past day once, the day
// after; back 7 days at most; off means no request and nothing kept; a new
// install id every 90 days; 3 quiet tries a day; a body with exactly the
// contract's fields; and the counts coming from where they happen.

import 'dart:convert';

import 'package:dsh_app/phone/phone_channel.dart';
import 'package:dsh_app/usage/usage_ledger.dart';
import 'package:dsh_app/usage/usage_net.dart';
import 'package:dsh_app/usage/usage_stats.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support.dart';

const noticed = {
  UsageStatsController.noticedKey: true,
  UsageStatsController.enabledKey: true,
  UsageStatsController.consentKey: true,
};

late FakeUsageHttp http;
late DateTime now;
VoidCallback? resume;

Future<void> settle() async {
  for (var i = 0; i < 30; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Future<ProviderContainer> start({
  Map<String, Object> prefs = const {},
  String? engine,
  PhoneChannel? phone,
  UsageDevice phoneFacts = testDevice,
  bool serviceAvailable = true,
}) async {
  SharedPreferences.setMockInitialValues(prefs);
  final container = ProviderContainer(
    overrides: usageOverrides(
      clock: () => now,
      http: http,
      onResumes: (onResume) => resume = onResume,
      engine: engine,
      phone: phone,
      device: phoneFacts,
      serviceAvailable: serviceAvailable,
    ),
  );
  addTearDown(container.dispose);
  container.read(usageStatsProvider);
  await settle();
  return container;
}

extension on ProviderContainer {
  UsageStatsController get usage => read(usageStatsProvider.notifier);

  Future<void> count(UsageCount c, [int times = 1]) async {
    for (var i = 0; i < times; i++) {
      usage.count(c);
    }
    await settle();
  }

  /// Back to the app, the way Android says so.
  Future<void> comeBack() async {
    resume!();
    await settle();
  }
}

Future<Map<String, Object?>> stored() async {
  final prefs = await SharedPreferences.getInstance();
  return {for (final k in prefs.getKeys()) k: prefs.get(k)};
}

void main() {
  final wasActive = UsageBuild.active;
  setUp(() {
    UsageBuild.active = true;
    http = FakeUsageHttp();
    now = DateTime(2026, 10, 28, 9);
    resume = null;
  });
  tearDown(() => UsageBuild.active = wasActive);

  test('an unreachable site never receives an opted-in report', () async {
    final c = await start(prefs: noticed, serviceAvailable: false);
    await c.count(UsageCount.turns);
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();
    expect(http.requests, isEmpty);
  });

  test('moving from the previous fork endpoint requires fresh consent', () async {
    final c = await start(
      prefs: {
        UsageStatsController.enabledKey: true,
        UsageStatsController.noticedKey: true,
        'usage_stats_opt_in_v1': true,
        UsageStatsController.iidKey: 'old-install-id',
      },
    );
    expect(c.read(usageStatsProvider).enabled, isFalse);
    expect((await stored()).containsKey(UsageStatsController.iidKey), isFalse);
    expect(http.requests, isEmpty);
  });

  test('nothing is counted or sent until explicit opt-in, even after seeing the switch', () async {
    final c = await start();
    expect(c.read(usageStatsProvider).enabled, isFalse, reason: 'off by default');
    await c.count(UsageCount.turns, 3);
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();
    expect(http.requests, isEmpty);
    expect((await stored()).keys.where((k) => k.startsWith('usage_stats_days')), isEmpty);

    // Merely displaying the switch is not permission to report.
    await c.usage.markNoticed();
    await c.count(UsageCount.turns);
    await c.comeBack();
    expect(c.read(usageStatsProvider).collecting, isFalse);
    expect(http.requests, isEmpty);
    expect((await stored()).containsKey(UsageStatsController.daysKey), isFalse);
    await c.usage.setEnabled(true);
    await c.count(UsageCount.turns);
    now = DateTime(2026, 10, 30, 9);
    await c.comeBack();
    expect(http.days, ['2026-10-29']);
    expect((http.requests.single['counts']! as Map)['turns'], 1);
  });

  test('upgrading discards legacy opt-out consent and queued identifiers before any send', () async {
    final ledger = UsageLedger()..count(UsageCount.turns, DateTime(2026, 10, 27));
    final c = await start(
      prefs: {
        UsageStatsController.enabledKey: true,
        UsageStatsController.noticedKey: true,
        UsageStatsController.daysKey: ledger.encode(),
        UsageStatsController.iidKey: 'legacy-install-id',
        UsageStatsController.iidSinceKey: now.millisecondsSinceEpoch,
        UsageStatsController.failedAtKey: now.millisecondsSinceEpoch,
        UsageStatsController.closedDayKey: '2026-10-27',
      },
    );
    await c.usage.send();
    await c.count(UsageCount.turns);
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();
    expect(c.read(usageStatsProvider).enabled, isFalse);
    expect(http.requests, isEmpty);
    final prefs = await stored();
    for (final key in [
      UsageStatsController.daysKey,
      UsageStatsController.iidKey,
      UsageStatsController.iidSinceKey,
      UsageStatsController.failedAtKey,
      UsageStatsController.closedDayKey,
    ]) {
      expect(prefs.containsKey(key), isFalse, reason: key);
    }
    await c.usage.setEnabled(true);
    await c.count(UsageCount.voice);
    now = DateTime(2026, 10, 30, 9);
    await c.comeBack();
    expect(http.days, ['2026-10-29']);
    expect(http.requests.single['iid'], isNot('legacy-install-id'));
    expect((http.requests.single['counts']! as Map)['turns'], 0);
  });

  test('a past day goes out once, the day after; today waits for tomorrow', () async {
    final c = await start(prefs: noticed);
    await c.count(UsageCount.turns, 2);
    await c.count(UsageCount.voice);
    await c.comeBack();
    expect(http.requests, isEmpty, reason: 'today is still being counted');

    now = DateTime(2026, 10, 29, 8);
    await c.comeBack();
    await c.comeBack();
    now = DateTime(2026, 10, 29, 22);
    await c.comeBack();
    expect(http.days, ['2026-10-28'], reason: 'one request for the 28th, however often the app comes back');
    expect(http.requests.single['counts'], {'turns': 2, 'voice': 1, 'phone': 0, 'share': 0, 'gen': 0, 'plugins': 0});

    now = DateTime(2026, 10, 30, 8);
    await c.comeBack();
    expect(http.days, ['2026-10-28', '2026-10-29'], reason: 'the 29th was a day in use, with nothing counted');
  });

  test('a cold start sends what is due, at most 7 days back, oldest first', () async {
    final ledger = UsageLedger();
    for (var d = 15; d <= 27; d++) {
      ledger.count(UsageCount.share, DateTime(2026, 10, d, 20));
    }
    final c = await start(prefs: {...noticed, UsageStatsController.daysKey: ledger.encode()});
    expect(http.days, [for (var d = 21; d <= 27; d++) '2026-10-$d']);
    await c.comeBack();
    expect(http.requests, hasLength(7));
    // All sent, nothing older kept; today (in use) is all that is left.
    final left = UsageLedger.decode((await stored())[UsageStatsController.daysKey] as String?);
    expect(left.days.keys, ['2026-10-28']);
  });

  test('off: no request at all, and the install id and every count are gone at once', () async {
    final c = await start(prefs: noticed);
    await c.count(UsageCount.turns, 4);
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();
    expect(http.requests, hasLength(1));
    final firstId = http.requests.single['iid'];
    await c.count(UsageCount.gen);
    expect((await stored())[UsageStatsController.iidKey], firstId);

    await c.usage.setEnabled(false);
    await settle();
    final prefs = await stored();
    expect(prefs[UsageStatsController.enabledKey], isFalse);
    for (final key in [
      UsageStatsController.iidKey,
      UsageStatsController.iidSinceKey,
      UsageStatsController.daysKey,
      UsageStatsController.failedAtKey,
    ]) {
      expect(prefs.containsKey(key), isFalse, reason: key);
    }

    // Days go by with the app in use: still not a single request.
    for (var d = 29; d <= 31; d++) {
      now = DateTime(2026, 10, d, 12);
      await c.count(UsageCount.turns, 2);
      c.usage.plugins(3);
      await c.comeBack();
      await c.usage.send();
    }
    expect(http.requests, hasLength(1));
    expect((await stored()).containsKey(UsageStatsController.daysKey), isFalse);

    // A cold start remembers it is off.
    final again = await start(prefs: Map<String, Object>.from(await stored()));
    expect(again.read(usageStatsProvider).enabled, isFalse);
    now = DateTime(2026, 11, 2, 9);
    await again.comeBack();
    expect(http.requests, hasLength(1));

    // On again: a new id, nothing from before.
    await again.usage.setEnabled(true);
    await again.count(UsageCount.voice);
    now = DateTime(2026, 11, 3, 9);
    await again.comeBack();
    expect(http.requests, hasLength(2));
    expect(http.requests.last['iid'], isNot(firstId));
    expect(http.requests.last['day'], '2026-11-02');
  });

  test('the install id is kept 89 days and replaced on the 90th', () async {
    final c = await start(prefs: noticed);
    final made = DateTime(2026, 10, 29, 9);
    now = made;
    await c.comeBack();
    final first = http.requests.single['iid']! as String;
    expect(first, matches(RegExp(r'^[A-Za-z0-9_-]{22}$')));

    now = made.add(const Duration(days: 88));
    await c.comeBack();
    now = made.add(const Duration(days: 89));
    await c.comeBack();
    expect(http.requests.last['iid'], first);

    now = made.add(const Duration(days: 90));
    await c.comeBack();
    expect(http.requests, hasLength(3));
    expect(http.requests.last['iid'], isNot(first));
    expect(http.requests.last['iid'], matches(RegExp(r'^[A-Za-z0-9_-]{22}$')));
  });

  test('a failed send: quietly tried again later, 3 tries at most, never in a burst', () async {
    final c = await start(prefs: noticed);
    await c.count(UsageCount.turns);
    now = DateTime(2026, 10, 29, 9);
    await c.count(UsageCount.turns);
    http.offline = true;
    now = DateTime(2026, 10, 30, 9);
    await c.comeBack();
    // Two days due: the round stops at the first failure.
    expect(http.days, ['2026-10-28']);

    // Straight back: too soon to try again.
    await c.comeBack();
    await c.comeBack();
    expect(http.requests, hasLength(1));

    // Too many requests, and a server error: failures too.
    http
      ..offline = false
      ..replies.addAll([429, 503]);
    now = now.add(const Duration(minutes: 11));
    await c.comeBack();
    now = now.add(const Duration(minutes: 11));
    await c.comeBack();
    expect(http.days, ['2026-10-28', '2026-10-28', '2026-10-28']);

    // The 28th is given up after 3; the 29th still has all of its tries.
    http.offline = false;
    now = now.add(const Duration(minutes: 11));
    await c.comeBack();
    expect(http.days, ['2026-10-28', '2026-10-28', '2026-10-28', '2026-10-29']);
    await c.comeBack();
    expect(http.requests, hasLength(4));
  });

  test('400, 413, 415: that day is given up at once; the next one goes in the same round', () async {
    for (final refusal in [400, 413, 415]) {
      http = FakeUsageHttp()..replies.add(refusal);
      final ledger = UsageLedger()
        ..touch(DateTime(2026, 10, 26, 9))
        ..touch(DateTime(2026, 10, 27, 9));
      final c = await start(prefs: {...noticed, UsageStatsController.daysKey: ledger.encode()});
      expect(http.days, ['2026-10-26', '2026-10-27'], reason: '$refusal');
      now = now.add(const Duration(minutes: 30));
      await c.comeBack();
      expect(http.requests, hasLength(2), reason: '$refusal: never tried again');
      final left = UsageLedger.decode((await stored())[UsageStatsController.daysKey] as String?);
      expect(left.days.keys, ['2026-10-28'], reason: '$refusal');
      now = DateTime(2026, 10, 28, 9);
    }
  });

  test('404: the host collects nothing now; not again today, and no try used', () async {
    http.replies.add(404);
    final ledger = UsageLedger()..touch(DateTime(2026, 10, 27, 9));
    final prefs = {...noticed, UsageStatsController.daysKey: ledger.encode()};
    final c = await start(prefs: prefs);
    expect(http.days, ['2026-10-27']);
    for (final later in [const Duration(minutes: 11), const Duration(hours: 6)]) {
      now = DateTime(2026, 10, 28, 9).add(later);
      await c.comeBack();
    }
    expect(http.requests, hasLength(1));
    // A cold start the same day remembers it.
    final again = await start(prefs: Map<String, Object>.from(await stored()));
    await again.comeBack();
    expect(http.requests, hasLength(1));
    // The next day, it goes (with all of its tries).
    now = DateTime(2026, 10, 29, 9);
    await again.comeBack();
    expect(http.days, ['2026-10-27', '2026-10-27', '2026-10-28']);
  });

  test('a body the host would refuse is never sent', () async {
    // No native side: no build number, no ABI.
    final c = await start(
      prefs: noticed,
      phoneFacts: const UsageDevice(app: '0.9.9', sdk: 34, maker: 'vivo'),
    );
    await c.count(UsageCount.turns);
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();
    expect(http.requests, isEmpty);
    final left = UsageLedger.decode((await stored())[UsageStatsController.daysKey] as String?);
    expect(left.days.keys, ['2026-10-29'], reason: 'the 28th is dropped, not kept for ever');
  });

  test('every body sent passes the host\'s rules', () async {
    final ledger = UsageLedger();
    for (var d = 21; d <= 27; d++) {
      ledger
        ..count(UsageCount.turns, DateTime(2026, 10, d, 10))
        ..engine(d.isEven ? 'direct' : 'proot', DateTime(2026, 10, d, 10))
        ..plugins(d - 20, DateTime(2026, 10, d, 10));
    }
    await start(prefs: {...noticed, UsageStatsController.daysKey: ledger.encode()});
    expect(http.requests, hasLength(7));
    for (final body in http.requests) {
      expect(usageProblem(body, now), isNull, reason: '$body');
      expect(body['iid'], matches(RegExp(r'^[A-Za-z0-9_-]{21}[AQgw]$')));
    }
  });

  test('the request: the endpoint, and nothing but the contract\'s fields', () async {
    final c = await start(prefs: noticed, engine: 'direct');
    await c.count(UsageCount.turns, 5);
    await c.count(UsageCount.voice, 2);
    await c.count(UsageCount.share);
    await c.count(UsageCount.gen);
    c.usage.plugins(3);
    await settle();
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();

    expect(http.urls.single, Uri.parse('https://dsh-go-services.zheyuan1997.chatgpt.site/api/usage/v1'));
    final body = http.requests.single;
    expect(body.keys.toSet(), usagePayloadKeys);
    final counts = body['counts']! as Map<String, Object?>;
    expect(counts.keys.toSet(), usageCountKeys);
    expect(body, {
      'v': 1,
      'iid': body['iid'],
      'day': '2026-10-28',
      'app': '0.9.9',
      'build': 10301000,
      'sdk': 34,
      'abi': 'arm64-v8a',
      'maker': 'vivo',
      'lang': 'zh',
      'engine': 'direct',
      'counts': {'turns': 5, 'voice': 2, 'phone': 0, 'share': 1, 'gen': 1, 'plugins': 3},
    });
    // Nothing in it reads like content or an identifier of the phone.
    final text = jsonEncode(body);
    for (final word in ['model', 'android_id', 'imei', 'serial', 'host', 'key', 'token', 'text']) {
      expect(text.toLowerCase(), isNot(contains('"$word')), reason: word);
    }
  });

  test('a day the engine did not run says none', () async {
    final c = await start(prefs: noticed);
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();
    expect(http.requests.single['engine'], 'none');
  });

  test('phone control: each task counts once, when it starts', () async {
    final phone = FakePhone();
    final c = await start(prefs: noticed, phone: phone);
    PhoneStatus task(bool active, int id) => PhoneStatus(
      task: PhoneTaskStatus(id: id, active: active),
    );
    for (final s in [task(true, 1), task(true, 1), task(false, 1), task(true, 2), task(true, 3), task(false, 3)]) {
      phone.pushes.add(s);
      await settle();
    }
    now = DateTime(2026, 10, 29, 9);
    await c.comeBack();
    expect((http.requests.single['counts']! as Map)['phone'], 3);
  });

  test('phoneTaskStarted: a new number or active again', () {
    const idle = PhoneTaskStatus();
    expect(phoneTaskStarted(idle, const PhoneTaskStatus(active: true)), isTrue);
    expect(phoneTaskStarted(const PhoneTaskStatus(active: true), const PhoneTaskStatus(active: true)), isFalse);
    expect(
      phoneTaskStarted(const PhoneTaskStatus(id: 1, active: true), const PhoneTaskStatus(id: 2, active: true)),
      isTrue,
    );
    expect(phoneTaskStarted(const PhoneTaskStatus(id: 1, active: true), const PhoneTaskStatus(id: 1)), isFalse);
  });

  test('debug builds and tests count nothing and send nothing', () async {
    final c = await start(prefs: noticed);
    UsageBuild.active = false;
    await c.count(UsageCount.turns);
    now = DateTime(2026, 10, 29, 9);
    await c.usage.foreground();
    expect(http.requests, isEmpty);
  });
}
