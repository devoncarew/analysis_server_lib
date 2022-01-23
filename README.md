# analysis_server_lib

A library to access Dart's analysis server API.

[![Buid status](https://github.com/devoncarew/analysis_server_lib/actions/workflows/build.yaml/badge.svg)](https://github.com/devoncarew/analysis_server_lib/actions/workflows/build.yaml)
[![pub package](https://img.shields.io/pub/v/analysis_server_lib.svg)](https://pub.dev/packages/analysis_server_lib)

## What is the analysis server?

The analysis server is a long-running process that provides analysis results to other tools.
It is designed to provide on-going analysis of one or more code bases as those code bases are
changing.

## Using the server

Clients (typically tools, such as an editor) are expected to run the analysis server in a separate
process and communicate with it over a JSON protocol. The protocol is specified
[here](https://htmlpreview.github.io/?https://github.com/dart-lang/sdk/blob/master/pkg/analysis_server/doc/api.html).

Here's a simple example of starting and communicating with the server:

```dart
import 'package:analysis_server_lib/analysis_server_lib.dart';

main() async {
  AnalysisServer server = await AnalysisServer.create();
  await server.server.onConnected.first;

  VersionResult version = await server.server.getVersion();
  print(version.version);
  
  server.dispose();
}
```
