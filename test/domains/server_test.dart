// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'package:analysis_server_lib/analysis_server_lib.dart';
import 'package:test/test.dart';

void main() => defineTests();

void defineTests() {
  group('server', () {
    AnalysisServer? client;

    setUp(() async {
      client = await AnalysisServer.create();
    });

    tearDown(() {
      client?.dispose();
    });

    test('onConnected', () async {
      await client!.server.onConnected.first;
    });

    test('getVersion', () async {
      VersionResult result = await client!.server.getVersion();
      expect(result.version, isNotEmpty);
      expect(result.version, startsWith('1.'));
    });

    test('shutdown', () async {
      await client!.server.shutdown();
      int exitCode = await client!.processCompleter.future;
      client = null;

      expect(exitCode, 0);
    });
  });
}
