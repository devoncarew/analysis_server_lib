// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:async';
import 'dart:io';

import 'package:analysis_server_lib/analysis_server_lib.dart';
import 'package:path/path.dart' as path;

class ServerHelper {
  static Future<ServerHelper> create() async {
    return new ServerHelper(await AnalysisServer.create());
  }

  final AnalysisServer server;
  Directory tempDir;
  Map<String, List<AnalysisError>> errors = {};

  ServerHelper(this.server)
      : tempDir = Directory.systemTemp.createTempSync('tests');

  Future init() {
    server.analysis.onErrors.listen((AnalysisErrors e) {
      if (e.errors.isEmpty) {
        errors.remove(e.file);
      } else {
        errors[e.file] = e.errors;
      }
    });

    server.server.setSubscriptions(['STATUS']);
    return server.analysis.setAnalysisRoots([tempDir.path], []);
  }

  Stream get onAnalysisFinished {
    return server.server.onStatus.where((ServerStatus status) {
      return status.analysis != null && status.analysis!.isAnalyzing == false;
    });
  }

  Future<String> createFile(String filePath, String text) {
    String fullPath = path.join(tempDir.path, filePath);
    return server.analysis.updateContent(
      {fullPath: new AddContentOverlay(text)},
    ).then((_) => fullPath);
  }

  void dispose() {
    server.dispose();
    tempDir.deleteSync(recursive: true);
  }
}
