// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'package:analysis_server_lib/analysis_server_lib.dart';
import 'package:test/test.dart';

import '../src/helper.dart';

void main() => defineTests();

void defineTests() {
  group('analysis', () {
    late ServerHelper helper;

    setUp(() async {
      helper = await ServerHelper.create();
    });

    tearDown(() {
      helper.dispose();
    });

    test('analyze', () async {
      await helper.init();
      await helper.createFile('main.dart', "main() { print('hello'); }");
      await helper.onAnalysisFinished.first;
      expect(helper.errors, isEmpty);
    });

    test('analyze with errors', () async {
      await helper.init();
      await helper.createFile('main.dart', "main() { print('hello') }");
      await helper.onAnalysisFinished.first;
      expect(helper.errors.keys, hasLength(1));
      List<AnalysisError> errors = helper.errors.values.first;
      expect(errors, hasLength(1));
    });
  });
}
