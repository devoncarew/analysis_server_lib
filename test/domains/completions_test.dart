// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'package:analysis_server_lib/analysis_server_lib.dart';
import 'package:test/test.dart';

import '../src/helper.dart';

void main() => defineTests();

void defineTests() {
  group('completion', () {
    late ServerHelper helper;

    setUp(() async {
      helper = await ServerHelper.create();
    });

    tearDown(() {
      helper.dispose();
    });

    // Note - this is testing an experimental API.
    test('getSuggestions2', () async {
      await helper.init();
      String main =
          await helper.createFile('main.dart', "main() { print('hello'); }");
      await helper.onAnalysisFinished.first;
      expect(helper.errors, isEmpty);

      Suggestions2Result result =
          await helper.server.completion.getSuggestions2(main, 11, 100);

      expect(result.replacementLength, 5);
      expect(result.replacementOffset, 9);
      expect(result.suggestions, isNotEmpty);
      expect(
        result.suggestions.any((item) => item.completion == 'print'),
        true,
        reason: "Contains 'print'",
      );
    });
  });
}
