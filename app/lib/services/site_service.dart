import 'dart:async';
import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:http/http.dart' as http;

const siteServiceOrigin = 'https://dsh-go-services.zheyuan1997.chatgpt.site';

class SiteServiceStatus {
  const SiteServiceStatus({this.sharing = false, this.usage = false});
  final bool sharing;
  final bool usage;
}

/// A bounded, anonymous probe. Redirects and login pages are unavailable.
Future<SiteServiceStatus> probeSiteService({http.Client? client}) async {
  final transport = client ?? http.Client();
  try {
    final request = http.Request('GET', Uri.parse('$siteServiceOrigin/api/health'))..followRedirects = false;
    return await (() async {
      final response = await transport.send(request);
      if (response.statusCode != 200 || response.contentLength != null && response.contentLength! > 2048) {
        return const SiteServiceStatus();
      }
      final bytes = <int>[];
      await for (final chunk in response.stream) {
        bytes.addAll(chunk);
        if (bytes.length > 2048) return const SiteServiceStatus();
      }
      final body = jsonDecode(utf8.decode(bytes));
      if (body is! Map || body['service'] != 'dsh-go-services' || body['v'] != 1) return const SiteServiceStatus();
      return SiteServiceStatus(sharing: body['sharing'] == true, usage: body['usage'] == true);
    })().timeout(const Duration(seconds: 5));
  } catch (_) {
    return const SiteServiceStatus();
  } finally {
    transport.close();
  }
}

final siteServiceProbeProvider = Provider<Future<SiteServiceStatus> Function()>((ref) => probeSiteService);

/// Rechecks while a feature is visible; reopening it also starts a fresh probe.
final siteServiceStatusProvider = FutureProvider.autoDispose<SiteServiceStatus>((ref) async {
  final timer = Timer(const Duration(minutes: 1), ref.invalidateSelf);
  ref.onDispose(timer.cancel);
  return ref.read(siteServiceProbeProvider)();
});
