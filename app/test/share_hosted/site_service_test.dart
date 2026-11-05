import 'dart:convert';

import 'package:dsh_app/services/site_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test('health probe has no payload or credentials and disables redirects', () async {
    final status = await probeSiteService(
      client: MockClient((request) async {
        expect(request.url.toString(), '$siteServiceOrigin/api/health');
        expect(request.method, 'GET');
        expect(request.followRedirects, isFalse);
        expect(request.body, isEmpty);
        expect(request.headers['authorization'], isNull);
        return http.Response(jsonEncode({'service': 'dsh-go-services', 'v': 1, 'sharing': true, 'usage': true}), 200);
      }),
    );
    expect(status.sharing, isTrue);
    expect(status.usage, isTrue);
  });

  for (final (name, response) in [
    ('redirect', http.Response('', 302, headers: {'location': '/signin-with-chatgpt'})),
    ('login page', http.Response('<html>Sign in</html>', 200)),
    ('wrong service', http.Response('{"service":"other","v":1,"sharing":true}', 200)),
    ('oversized response', http.Response('x' * 2049, 200)),
    ('unavailable', http.Response('', 503)),
  ]) {
    test('$name disables both features', () async {
      final status = await probeSiteService(client: MockClient((_) async => response));
      expect(status.sharing, isFalse);
      expect(status.usage, isFalse);
    });
  }

  test('network errors disable both features', () async {
    final status = await probeSiteService(client: MockClient((_) async => throw http.ClientException('offline')));
    expect(status.sharing, isFalse);
    expect(status.usage, isFalse);
  });
}
