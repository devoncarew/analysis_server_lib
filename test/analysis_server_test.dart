// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'package:analysis_server_lib/analysis_server_lib.dart';
import 'package:test/test.dart';

void main() => defineTests();

// TODO: improve tests

void defineTests() {
  group('analysis server', () {
    test('responds to version', () async {
      AnalysisServer client;

      try {
        client = await AnalysisServer.create();
        await client.server.onConnected.first;

        VersionResult result = await client.server.getVersion();
        expect(result.version, isNotEmpty);
        expect(result.version, startsWith('1.'));
      } finally {
        client?.dispose();
      }
    });
  });
}
