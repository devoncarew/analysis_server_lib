// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'package:analysis_server_lib/analysis_server_lib.dart';
import 'package:test/test.dart';

import '../src/helper.dart';

void main() => defineTests();

void defineTests() {
  group('edit', () {
    late ServerHelper helper;

    setUp(() async {
      helper = await ServerHelper.create();
    });

    tearDown(() {
      helper.dispose();
    });

    test('format', () async {
      await helper.init();
      String main =
          await helper.createFile('main.dart', "main() { print('hello'); }");
      FormatResult result = await helper.server.edit.format(main, 0, 0);
      expect(result.edits, hasLength(1));
      SourceEdit edit = result.edits.first;
      expect(edit.replacement, '''
main() {
  print('hello');
}
''');
    });

    test('getRefactoring', () async {
      await helper.init();
      String main = await helper.createFile('main.dart', "foo() { }");
      RefactoringResult? result = await helper.server.edit.getRefactoring(
        Refactorings.RENAME,
        main,
        0,
        0,
        false,
        options: new RenameRefactoringOptions(newName: 'bar'),
      );

      expect(result!.initialProblems, isEmpty);
      expect(result.optionsProblems, isEmpty);
      expect(result.finalProblems, isEmpty);

      // feedback
      RenameFeedback feedback = result.feedback as RenameFeedback;
      expect(feedback, isNotNull);
      expect(feedback.oldName, 'foo');

      // edits
      SourceChange change = result.change!;
      expect(change.edits, hasLength(1));
      SourceFileEdit fileEdit = change.edits.first;
      expect(fileEdit.edits, hasLength(1));
      expect(fileEdit.edits.first.replacement, 'bar');

      expect(result.potentialEdits, isNull);
    });
  });
}
