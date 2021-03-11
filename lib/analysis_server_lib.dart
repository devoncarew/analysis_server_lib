// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a generated file.

/// A library to access the analysis server API.
///
/// [AnalysisServer] is the main entry-point to this library.
library analysis_server_lib;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:logging/logging.dart';
import 'package:path/path.dart' as path;

/// @experimental
const String experimental = 'experimental';

final Logger _logger = new Logger('analysis_server');

const String generatedProtocolVersion = '1.32.1';

typedef void MethodSend(String methodName);

/// A class to communicate with an analysis server instance.
///
/// Here's a simple example of starting and communicating with the server:
///
/// ```dart
/// import 'package:analysis_server_lib/analysis_server_lib.dart';
///
/// main() async {
///   AnalysisServer server = await AnalysisServer.create();
///   await server.server.onConnected.first;
///
///   VersionResult version = await server.server.getVersion();
///   print(version.version);
///
///   server.dispose();
/// }
/// ```
class AnalysisServer {
  /// Create and connect to a new analysis server instance.
  ///
  /// - [sdkPath] override the default sdk path
  /// - [scriptPath] override the default entry-point script to use for the
  ///     analysis server
  /// - [onRead] called every time data is read from the server
  /// - [onWrite] called every time data is written to the server
  static Future<AnalysisServer> create(
      {String? sdkPath,
      String? scriptPath,
      void Function(String str)? onRead,
      void Function(String str)? onWrite,
      List<String>? vmArgs,
      List<String>? serverArgs,
      String? clientId,
      String? clientVersion,
      Map<String, String>? processEnvironment}) async {
    Completer<int> processCompleter = new Completer();

    String vmPath;
    if (sdkPath != null) {
      vmPath =
          path.join(sdkPath, 'bin', Platform.isWindows ? 'dart.exe' : 'dart');
    } else {
      sdkPath = path.dirname(path.dirname(Platform.resolvedExecutable));
      vmPath = Platform.resolvedExecutable;
    }
    scriptPath ??= '$sdkPath/bin/snapshots/analysis_server.dart.snapshot';

    List<String> args = [scriptPath, '--sdk', sdkPath];
    if (vmArgs != null) args.insertAll(0, vmArgs);
    if (serverArgs != null) args.addAll(serverArgs);
    if (clientId != null) args.add('--client-id=$clientId');
    if (clientVersion != null) args.add('--client-version=$clientVersion');

    Process process =
        await Process.start(vmPath, args, environment: processEnvironment);
    // ignore: unused_local_variable
    Future unawaited =
        process.exitCode.then((code) => processCompleter.complete(code));

    Stream<String> inStream = process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .map((String message) {
      if (onRead != null) onRead(message);
      return message;
    });

    AnalysisServer server = new AnalysisServer(inStream, (String message) {
      if (onWrite != null) onWrite(message);
      process.stdin.writeln(message);
    }, processCompleter, process.kill);

    return server;
  }

  final Completer<int> processCompleter;
  final Function? _processKillHandler;

  StreamSubscription? _streamSub;
  late Function _writeMessage;
  int _id = 0;
  Map<String, Completer> _completers = {};
  Map<String, String> _methodNames = {};
  JsonCodec _jsonEncoder = new JsonCodec(toEncodable: _toEncodable);
  Map<String, Domain> _domains = {};
  StreamController<String> _onSend = new StreamController.broadcast();
  StreamController<String> _onReceive = new StreamController.broadcast();
  MethodSend? _willSend;

  late final ServerDomain _server = ServerDomain(this);
  late final AnalysisDomain _analysis = AnalysisDomain(this);
  late final CompletionDomain _completion = CompletionDomain(this);
  late final SearchDomain _search = SearchDomain(this);
  late final EditDomain _edit = EditDomain(this);
  late final ExecutionDomain _execution = ExecutionDomain(this);
  late final DiagnosticDomain _diagnostic = DiagnosticDomain(this);
  late final AnalyticsDomain _analytics = AnalyticsDomain(this);
  late final KytheDomain _kythe = KytheDomain(this);
  late final FlutterDomain _flutter = FlutterDomain(this);

  /// Connect to an existing analysis server instance.
  AnalysisServer(Stream<String> inStream, void writeMessage(String message),
      this.processCompleter,
      [this._processKillHandler]) {
    configure(inStream, writeMessage);
  }

  ServerDomain get server => _server;
  AnalysisDomain get analysis => _analysis;
  CompletionDomain get completion => _completion;
  SearchDomain get search => _search;
  EditDomain get edit => _edit;
  ExecutionDomain get execution => _execution;
  DiagnosticDomain get diagnostic => _diagnostic;
  AnalyticsDomain get analytics => _analytics;
  KytheDomain get kythe => _kythe;
  FlutterDomain get flutter => _flutter;

  Stream<String> get onSend => _onSend.stream;
  Stream<String> get onReceive => _onReceive.stream;

  set willSend(MethodSend fn) {
    _willSend = fn;
  }

  void configure(Stream<String> inStream, void writeMessage(String message)) {
    _streamSub = inStream.listen(_processMessage);
    _writeMessage = writeMessage;
  }

  void dispose() {
    if (_streamSub != null) _streamSub!.cancel();
    //_completers.values.forEach((c) => c.completeError('disposed'));
    _completers.clear();

    if (_processKillHandler != null) {
      _processKillHandler!();
    }
  }

  void _processMessage(String message) {
    _onReceive.add(message);

    if (!message.startsWith('{')) {
      _logger.warning('unknown message: ${message}');
      return;
    }

    try {
      var json = jsonDecode(message);

      if (json['id'] == null) {
        // Handle a notification.
        String? event = json['event'];
        if (event == null) {
          _logger.severe('invalid message: ${message}');
        } else {
          String prefix = event.substring(0, event.indexOf('.'));
          if (_domains[prefix] == null) {
            _logger.severe('no domain for notification: ${message}');
          } else {
            _domains[prefix]!._handleEvent(event, json['params']);
          }
        }
      } else {
        Completer? completer = _completers.remove(json['id']);
        String? methodName = _methodNames.remove(json['id']);

        if (completer == null) {
          _logger.severe('unmatched request response: ${message}');
        } else if (json['error'] != null) {
          completer
              .completeError(RequestError.parse(methodName!, json['error']));
        } else {
          completer.complete(json['result'] ?? const {});
        }
      }
    } catch (e) {
      _logger.severe('unable to decode message: ${message}, ${e}');
    }
  }

  Future<Map> _call(String method, [Map? args]) {
    String id = '${++_id}';
    Completer<Map> completer = _completers[id] = new Completer<Map>();
    _methodNames[id] = method;
    final Map m = {'id': id, 'method': method};
    if (args != null) m['params'] = args;
    String message = _jsonEncoder.encode(m);
    if (_willSend != null) _willSend!(method);
    _onSend.add(message);
    _writeMessage(message);
    return completer.future;
  }

  static dynamic _toEncodable(obj) => obj is Jsonable ? obj.toMap() : obj;
}

abstract class Domain {
  final AnalysisServer server;
  final String name;

  Map<String, StreamController<Map>> _controllers = {};
  Map<String, Stream> _streams = {};

  Domain(this.server, this.name) {
    server._domains[name] = this;
  }

  Future<Map> _call(String method, [Map? args]) => server._call(method, args);

  Stream<E> _listen<E>(String name, E cvt(Map m)) {
    if (_streams[name] == null) {
      StreamController<Map> controller =
          _controllers[name] = new StreamController<Map>.broadcast();
      _streams[name] = controller.stream.map<E>(cvt);
    }

    return _streams[name] as Stream<E>;
  }

  void _handleEvent(String name, dynamic event) {
    StreamController? controller = _controllers[name];
    if (controller != null) {
      controller.add(event);
    }
  }

  String toString() => 'Domain ${name}';
}

abstract class Jsonable {
  Map toMap();
}

abstract class RefactoringOptions implements Jsonable {}

abstract class ContentOverlayType {
  final String type;

  ContentOverlayType(this.type);
}

class RequestError {
  static RequestError parse(String method, Map m) {
    return new RequestError(method, m['code'], m['message'],
        stackTrace: m['stackTrace']);
  }

  final String method;
  final String code;
  final String message;
  final String? stackTrace;

  RequestError(this.method, this.code, this.message, {this.stackTrace});

  String toString() =>
      '[Analyzer RequestError method: ${method}, code: ${code}, message: ${message}]';
}

Map _stripNullValues(Map m) {
  Map copy = {};

  for (var key in m.keys) {
    var value = m[key];
    if (value != null) copy[key] = value;
  }

  return copy;
}

// server domain

/// The server domain contains API’s related to the execution of the server.
class ServerDomain extends Domain {
  ServerDomain(AnalysisServer server) : super(server, 'server');

  /// Reports that the server is running. This notification is issued once after
  /// the server has started running but before any requests are processed to
  /// let the client know that it started correctly.
  ///
  /// It is not possible to subscribe to or unsubscribe from this notification.
  Stream<ServerConnected> get onConnected {
    return _listen('server.connected', ServerConnected.parse);
  }

  /// Reports that an unexpected error has occurred while executing the server.
  /// This notification is not used for problems with specific requests (which
  /// are returned as part of the response) but is used for exceptions that
  /// occur while performing other tasks, such as analysis or preparing
  /// notifications.
  ///
  /// It is not possible to subscribe to or unsubscribe from this notification.
  Stream<ServerError> get onError {
    return _listen('server.error', ServerError.parse);
  }

  /// The stream of entries describing events happened in the server.
  Stream<ServerLog> get onLog {
    return _listen('server.log', ServerLog.parse);
  }

  /// Reports the current status of the server. Parameters are omitted if there
  /// has been no change in the status represented by that parameter.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"STATUS"` in the list of services passed in a
  /// server.setSubscriptions request.
  Stream<ServerStatus> get onStatus {
    return _listen('server.status', ServerStatus.parse);
  }

  /// Return the version number of the analysis server.
  Future<VersionResult> getVersion() =>
      _call('server.getVersion').then(VersionResult.parse);

  /// Cleanly shutdown the analysis server. Requests that are received after
  /// this request will not be processed. Requests that were received before
  /// this request, but for which a response has not yet been sent, will not be
  /// responded to. No further responses or notifications will be sent after the
  /// response to this request has been sent.
  Future shutdown() => _call('server.shutdown');

  /// Subscribe for services. All previous subscriptions are replaced by the
  /// given set of services.
  ///
  /// It is an error if any of the elements in the list are not valid services.
  /// If there is an error, then the current subscriptions will remain
  /// unchanged.
  Future setSubscriptions(List<String> subscriptions) =>
      _call('server.setSubscriptions', {'subscriptions': subscriptions});
}

class ServerConnected {
  static ServerConnected parse(Map m) =>
      new ServerConnected(m['version'], m['pid']);

  /// The version number of the analysis server.
  final String version;

  /// The process id of the analysis server process.
  final int pid;

  ServerConnected(this.version, this.pid);
}

class ServerError {
  static ServerError parse(Map m) =>
      new ServerError(m['isFatal'], m['message'], m['stackTrace']);

  /// True if the error is a fatal error, meaning that the server will shutdown
  /// automatically after sending this notification.
  final bool isFatal;

  /// The error message indicating what kind of error was encountered.
  final String message;

  /// The stack trace associated with the generation of the error, used for
  /// debugging the server.
  final String stackTrace;

  ServerError(this.isFatal, this.message, this.stackTrace);
}

class ServerLog {
  static ServerLog parse(Map m) =>
      new ServerLog(ServerLogEntry.parse(m['entry']));

  final ServerLogEntry entry;

  ServerLog(this.entry);
}

class ServerStatus {
  static ServerStatus parse(Map m) => new ServerStatus(
      analysis:
          m['analysis'] == null ? null : AnalysisStatus.parse(m['analysis']),
      pub: m['pub'] == null ? null : PubStatus.parse(m['pub']));

  /// The current status of analysis, including whether analysis is being
  /// performed and if so what is being analyzed.
  final AnalysisStatus? analysis;
  @deprecated
  final PubStatus? pub;

  ServerStatus({this.analysis, this.pub});
}

class VersionResult {
  static VersionResult parse(Map m) => new VersionResult(m['version']);

  /// The version number of the analysis server.
  final String version;

  VersionResult(this.version);
}

// analysis domain

/// The analysis domain contains API’s related to the analysis of files.
class AnalysisDomain extends Domain {
  AnalysisDomain(AnalysisServer server) : super(server, 'analysis');

  /// Reports the paths of the files that are being analyzed.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"ANALYZED_FILES"` in the list of services passed
  /// in an analysis.setGeneralSubscriptions request.
  Stream<AnalysisAnalyzedFiles> get onAnalyzedFiles {
    return _listen('analysis.analyzedFiles', AnalysisAnalyzedFiles.parse);
  }

  /// Reports closing labels relevant to a given file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"CLOSING_LABELS"` in the list of services passed
  /// in an analysis.setSubscriptions request.
  Stream<AnalysisClosingLabels> get onClosingLabels {
    return _listen('analysis.closingLabels', AnalysisClosingLabels.parse);
  }

  /// Reports the errors associated with a given file. The set of errors
  /// included in the notification is always a complete list that supersedes any
  /// previously reported errors.
  Stream<AnalysisErrors> get onErrors {
    return _listen('analysis.errors', AnalysisErrors.parse);
  }

  /// Reports that any analysis results that were previously associated with the
  /// given files should be considered to be invalid because those files are no
  /// longer being analyzed, either because the analysis root that contained it
  /// is no longer being analyzed or because the file no longer exists.
  ///
  /// If a file is included in this notification and at some later time a
  /// notification with results for the file is received, clients should assume
  /// that the file is once again being analyzed and the information should be
  /// processed.
  ///
  /// It is not possible to subscribe to or unsubscribe from this notification.
  Stream<AnalysisFlushResults> get onFlushResults {
    return _listen('analysis.flushResults', AnalysisFlushResults.parse);
  }

  /// Reports the folding regions associated with a given file. Folding regions
  /// can be nested, but will not be overlapping. Nesting occurs when a foldable
  /// element, such as a method, is nested inside another foldable element such
  /// as a class.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"FOLDING"` in the list of services passed in an
  /// analysis.setSubscriptions request.
  Stream<AnalysisFolding> get onFolding {
    return _listen('analysis.folding', AnalysisFolding.parse);
  }

  /// Reports the highlight regions associated with a given file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"HIGHLIGHTS"` in the list of services passed in an
  /// analysis.setSubscriptions request.
  Stream<AnalysisHighlights> get onHighlights {
    return _listen('analysis.highlights', AnalysisHighlights.parse);
  }

  /// Reports the classes that are implemented or extended and class members
  /// that are implemented or overridden in a file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"IMPLEMENTED"` in the list of services passed in
  /// an analysis.setSubscriptions request.
  Stream<AnalysisImplemented> get onImplemented {
    return _listen('analysis.implemented', AnalysisImplemented.parse);
  }

  /// Reports that the navigation information associated with a region of a
  /// single file has become invalid and should be re-requested.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"INVALIDATE"` in the list of services passed in an
  /// analysis.setSubscriptions request.
  Stream<AnalysisInvalidate> get onInvalidate {
    return _listen('analysis.invalidate', AnalysisInvalidate.parse);
  }

  /// Reports the navigation targets associated with a given file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"NAVIGATION"` in the list of services passed in an
  /// analysis.setSubscriptions request.
  Stream<AnalysisNavigation> get onNavigation {
    return _listen('analysis.navigation', AnalysisNavigation.parse);
  }

  /// Reports the occurrences of references to elements within a single file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"OCCURRENCES"` in the list of services passed in
  /// an analysis.setSubscriptions request.
  Stream<AnalysisOccurrences> get onOccurrences {
    return _listen('analysis.occurrences', AnalysisOccurrences.parse);
  }

  /// Reports the outline associated with a single file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"OUTLINE"` in the list of services passed in an
  /// analysis.setSubscriptions request.
  Stream<AnalysisOutline> get onOutline {
    return _listen('analysis.outline', AnalysisOutline.parse);
  }

  /// Reports the overriding members in a file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"OVERRIDES"` in the list of services passed in an
  /// analysis.setSubscriptions request.
  Stream<AnalysisOverrides> get onOverrides {
    return _listen('analysis.overrides', AnalysisOverrides.parse);
  }

  /// Return the errors associated with the given file. If the errors for the
  /// given file have not yet been computed, or the most recently computed
  /// errors for the given file are out of date, then the response for this
  /// request will be delayed until they have been computed. If some or all of
  /// the errors for the file cannot be computed, then the subset of the errors
  /// that can be computed will be returned and the response will contain an
  /// error to indicate why the errors could not be computed. If the content of
  /// the file changes after this request was received but before a response
  /// could be sent, then an error of type `CONTENT_MODIFIED` will be generated.
  ///
  /// This request is intended to be used by clients that cannot asynchronously
  /// apply updated error information. Clients that **can** apply error
  /// information as it becomes available should use the information provided by
  /// the 'analysis.errors' notification.
  ///
  /// If a request is made for a file which does not exist, or which is not
  /// currently subject to analysis (e.g. because it is not associated with any
  /// analysis root specified to analysis.setAnalysisRoots), an error of type
  /// `GET_ERRORS_INVALID_FILE` will be generated.
  Future<ErrorsResult> getErrors(String? file) {
    final Map m = {'file': file};
    return _call('analysis.getErrors', m).then(ErrorsResult.parse);
  }

  /// Return the hover information associate with the given location. If some or
  /// all of the hover information is not available at the time this request is
  /// processed the information will be omitted from the response.
  Future<HoverResult> getHover(String? file, int? offset) {
    final Map m = {'file': file, 'offset': offset};
    return _call('analysis.getHover', m).then(HoverResult.parse);
  }

  /// Return a description of all of the elements referenced in a given region
  /// of a given file that come from imported libraries.
  ///
  /// If a request is made for a file that does not exist, or that is not
  /// currently subject to analysis (e.g. because it is not associated with any
  /// analysis root specified via analysis.setAnalysisRoots), an error of type
  /// `GET_IMPORTED_ELEMENTS_INVALID_FILE` will be generated.
  @experimental
  Future<ImportedElementsResult> getImportedElements(
      String? file, int? offset, int? length) {
    final Map m = {'file': file, 'offset': offset, 'length': length};
    return _call('analysis.getImportedElements', m)
        .then(ImportedElementsResult.parse);
  }

  /// Return library dependency information for use in client-side indexing and
  /// package URI resolution.
  ///
  /// Clients that are only using the libraries field should consider using the
  /// analyzedFiles notification instead.
  Future<LibraryDependenciesResult> getLibraryDependencies() =>
      _call('analysis.getLibraryDependencies')
          .then(LibraryDependenciesResult.parse);

  /// Return the navigation information associated with the given region of the
  /// given file. If the navigation information for the given file has not yet
  /// been computed, or the most recently computed navigation information for
  /// the given file is out of date, then the response for this request will be
  /// delayed until it has been computed. If the content of the file changes
  /// after this request was received but before a response could be sent, then
  /// an error of type `CONTENT_MODIFIED` will be generated.
  ///
  /// If a navigation region overlaps (but extends either before or after) the
  /// given region of the file it will be included in the result. This means
  /// that it is theoretically possible to get the same navigation region in
  /// response to multiple requests. Clients can avoid this by always choosing a
  /// region that starts at the beginning of a line and ends at the end of a
  /// (possibly different) line in the file.
  ///
  /// If a request is made for a file which does not exist, or which is not
  /// currently subject to analysis (e.g. because it is not associated with any
  /// analysis root specified to analysis.setAnalysisRoots), an error of type
  /// `GET_NAVIGATION_INVALID_FILE` will be generated.
  Future<NavigationResult> getNavigation(
      String? file, int? offset, int? length) {
    final Map m = {'file': file, 'offset': offset, 'length': length};
    return _call('analysis.getNavigation', m).then(NavigationResult.parse);
  }

  @deprecated
  Future<ReachableSourcesResult> getReachableSources(String? file) {
    final Map m = {'file': file};
    return _call('analysis.getReachableSources', m)
        .then(ReachableSourcesResult.parse);
  }

  /// Return the signature information associated with the given location in the
  /// given file. If the signature information for the given file has not yet
  /// been computed, or the most recently computed signature information for the
  /// given file is out of date, then the response for this request will be
  /// delayed until it has been computed. If a request is made for a file which
  /// does not exist, or which is not currently subject to analysis (e.g.
  /// because it is not associated with any analysis root specified to
  /// analysis.setAnalysisRoots), an error of type `GET_SIGNATURE_INVALID_FILE`
  /// will be generated. If the location given is not inside the argument list
  /// for a function (including method and constructor) invocation, then an
  /// error of type `GET_SIGNATURE_INVALID_OFFSET` will be generated. If the
  /// location is inside an argument list but the function is not defined or
  /// cannot be determined (such as a method invocation where the target has
  /// type 'dynamic') then an error of type `GET_SIGNATURE_UNKNOWN_FUNCTION`
  /// will be generated.
  @experimental
  Future<SignatureResult> getSignature(String? file, int? offset) {
    final Map m = {'file': file, 'offset': offset};
    return _call('analysis.getSignature', m).then(SignatureResult.parse);
  }

  /// Force re-reading of all potentially changed files, re-resolving of all
  /// referenced URIs, and corresponding re-analysis of everything affected in
  /// the current analysis roots.
  Future reanalyze() => _call('analysis.reanalyze');

  /// Sets the root paths used to determine which files to analyze. The set of
  /// files to be analyzed are all of the files in one of the root paths that
  /// are not either explicitly or implicitly excluded. A file is explicitly
  /// excluded if it is in one of the excluded paths. A file is implicitly
  /// excluded if it is in a subdirectory of one of the root paths where the
  /// name of the subdirectory starts with a period (that is, a hidden
  /// directory).
  ///
  /// Note that this request determines the set of requested analysis roots. The
  /// actual set of analysis roots at any given time is the intersection of this
  /// set with the set of files and directories actually present on the
  /// filesystem. When the filesystem changes, the actual set of analysis roots
  /// is automatically updated, but the set of requested analysis roots is
  /// unchanged. This means that if the client sets an analysis root before the
  /// root becomes visible to server in the filesystem, there is no error; once
  /// the server sees the root in the filesystem it will start analyzing it.
  /// Similarly, server will stop analyzing files that are removed from the file
  /// system but they will remain in the set of requested roots.
  ///
  /// If an included path represents a file, then server will look in the
  /// directory containing the file for a pubspec.yaml file. If none is found,
  /// then the parents of the directory will be searched until such a file is
  /// found or the root of the file system is reached. If such a file is found,
  /// it will be used to resolve package: URI’s within the file.
  Future setAnalysisRoots(List<String>? included, List<String>? excluded,
      {Map<String, String>? packageRoots}) {
    final Map m = {'included': included, 'excluded': excluded};
    if (packageRoots != null) m['packageRoots'] = packageRoots;
    return _call('analysis.setAnalysisRoots', m);
  }

  /// Subscribe for general services (that is, services that are not specific to
  /// individual files). All previous subscriptions are replaced by the given
  /// set of services.
  ///
  /// It is an error if any of the elements in the list are not valid services.
  /// If there is an error, then the current subscriptions will remain
  /// unchanged.
  Future setGeneralSubscriptions(List<String> subscriptions) => _call(
      'analysis.setGeneralSubscriptions', {'subscriptions': subscriptions});

  /// Set the priority files to the files in the given list. A priority file is
  /// a file that is given priority when scheduling which analysis work to do
  /// first. The list typically contains those files that are visible to the
  /// user and those for which analysis results will have the biggest impact on
  /// the user experience. The order of the files within the list is
  /// significant: the first file will be given higher priority than the second,
  /// the second higher priority than the third, and so on.
  ///
  /// Note that this request determines the set of requested priority files. The
  /// actual set of priority files is the intersection of the requested set of
  /// priority files with the set of files currently subject to analysis. (See
  /// analysis.setSubscriptions for a description of files that are subject to
  /// analysis.)
  ///
  /// If a requested priority file is a directory it is ignored, but remains in
  /// the set of requested priority files so that if it later becomes a file it
  /// can be included in the set of actual priority files.
  Future setPriorityFiles(List<String> files) =>
      _call('analysis.setPriorityFiles', {'files': files});

  /// Subscribe for services that are specific to individual files. All previous
  /// subscriptions are replaced by the current set of subscriptions. If a given
  /// service is not included as a key in the map then no files will be
  /// subscribed to the service, exactly as if the service had been included in
  /// the map with an explicit empty list of files.
  ///
  /// Note that this request determines the set of requested subscriptions. The
  /// actual set of subscriptions at any given time is the intersection of this
  /// set with the set of files currently subject to analysis. The files
  /// currently subject to analysis are the set of files contained within an
  /// actual analysis root but not excluded, plus all of the files transitively
  /// reachable from those files via import, export and part directives. (See
  /// analysis.setAnalysisRoots for an explanation of how the actual analysis
  /// roots are determined.) When the actual analysis roots change, the actual
  /// set of subscriptions is automatically updated, but the set of requested
  /// subscriptions is unchanged.
  ///
  /// If a requested subscription is a directory it is ignored, but remains in
  /// the set of requested subscriptions so that if it later becomes a file it
  /// can be included in the set of actual subscriptions.
  ///
  /// It is an error if any of the keys in the map are not valid services. If
  /// there is an error, then the existing subscriptions will remain unchanged.
  Future setSubscriptions(Map<String, List<String>> subscriptions) =>
      _call('analysis.setSubscriptions', {'subscriptions': subscriptions});

  /// Update the content of one or more files. Files that were previously
  /// updated but not included in this update remain unchanged. This effectively
  /// represents an overlay of the filesystem. The files whose content is
  /// overridden are therefore seen by server as being files with the given
  /// content, even if the files do not exist on the filesystem or if the file
  /// path represents the path to a directory on the filesystem.
  Future updateContent(Map<String, ContentOverlayType> files) =>
      _call('analysis.updateContent', {'files': files});

  @deprecated
  Future updateOptions(AnalysisOptions options) =>
      _call('analysis.updateOptions', {'options': options});
}

class AnalysisAnalyzedFiles {
  static AnalysisAnalyzedFiles parse(Map m) =>
      new AnalysisAnalyzedFiles(new List.from(m['directories']));

  /// A list of the paths of the files that are being analyzed.
  final List<String> directories;

  AnalysisAnalyzedFiles(this.directories);
}

class AnalysisClosingLabels {
  static AnalysisClosingLabels parse(Map m) => new AnalysisClosingLabels(
      m['file'],
      new List.from(m['labels'].map((obj) => ClosingLabel.parse(obj))));

  /// The file the closing labels relate to.
  final String file;

  /// Closing labels relevant to the file. Each item represents a useful label
  /// associated with some range with may be useful to display to the user
  /// within the editor at the end of the range to indicate what construct is
  /// closed at that location. Closing labels include constructor/method calls
  /// and List arguments that span multiple lines. Note that the ranges that are
  /// returned can overlap each other because they may be associated with
  /// constructs that can be nested.
  final List<ClosingLabel> labels;

  AnalysisClosingLabels(this.file, this.labels);
}

class AnalysisErrors {
  static AnalysisErrors parse(Map m) => new AnalysisErrors(m['file'],
      new List.from(m['errors'].map((obj) => AnalysisError.parse(obj))));

  /// The file containing the errors.
  final String file;

  /// The errors contained in the file.
  final List<AnalysisError> errors;

  AnalysisErrors(this.file, this.errors);
}

class AnalysisFlushResults {
  static AnalysisFlushResults parse(Map m) =>
      new AnalysisFlushResults(new List.from(m['files']));

  /// The files that are no longer being analyzed.
  final List<String> files;

  AnalysisFlushResults(this.files);
}

class AnalysisFolding {
  static AnalysisFolding parse(Map m) => new AnalysisFolding(m['file'],
      new List.from(m['regions'].map((obj) => FoldingRegion.parse(obj))));

  /// The file containing the folding regions.
  final String file;

  /// The folding regions contained in the file.
  final List<FoldingRegion> regions;

  AnalysisFolding(this.file, this.regions);
}

class AnalysisHighlights {
  static AnalysisHighlights parse(Map m) => new AnalysisHighlights(m['file'],
      new List.from(m['regions'].map((obj) => HighlightRegion.parse(obj))));

  /// The file containing the highlight regions.
  final String file;

  /// The highlight regions contained in the file. Each highlight region
  /// represents a particular syntactic or semantic meaning associated with some
  /// range. Note that the highlight regions that are returned can overlap other
  /// highlight regions if there is more than one meaning associated with a
  /// particular region.
  final List<HighlightRegion> regions;

  AnalysisHighlights(this.file, this.regions);
}

class AnalysisImplemented {
  static AnalysisImplemented parse(Map m) => new AnalysisImplemented(
      m['file'],
      new List.from(m['classes'].map((obj) => ImplementedClass.parse(obj))),
      new List.from(m['members'].map((obj) => ImplementedMember.parse(obj))));

  /// The file with which the implementations are associated.
  final String file;

  /// The classes defined in the file that are implemented or extended.
  final List<ImplementedClass> classes;

  /// The member defined in the file that are implemented or overridden.
  final List<ImplementedMember> members;

  AnalysisImplemented(this.file, this.classes, this.members);
}

class AnalysisInvalidate {
  static AnalysisInvalidate parse(Map m) =>
      new AnalysisInvalidate(m['file'], m['offset'], m['length'], m['delta']);

  /// The file whose information has been invalidated.
  final String file;

  /// The offset of the invalidated region.
  final int offset;

  /// The length of the invalidated region.
  final int length;

  /// The delta to be applied to the offsets in information that follows the
  /// invalidated region in order to update it so that it doesn't need to be
  /// re-requested.
  final int delta;

  AnalysisInvalidate(this.file, this.offset, this.length, this.delta);
}

class AnalysisNavigation {
  static AnalysisNavigation parse(Map m) => new AnalysisNavigation(
      m['file'],
      new List.from(m['regions'].map((obj) => NavigationRegion.parse(obj))),
      new List.from(m['targets'].map((obj) => NavigationTarget.parse(obj))),
      new List.from(m['files']));

  /// The file containing the navigation regions.
  final String file;

  /// The navigation regions contained in the file. The regions are sorted by
  /// their offsets. Each navigation region represents a list of targets
  /// associated with some range. The lists will usually contain a single
  /// target, but can contain more in the case of a part that is included in
  /// multiple libraries or in Dart code that is compiled against multiple
  /// versions of a package. Note that the navigation regions that are returned
  /// do not overlap other navigation regions.
  final List<NavigationRegion> regions;

  /// The navigation targets referenced in the file. They are referenced by
  /// `NavigationRegion`s by their index in this array.
  final List<NavigationTarget> targets;

  /// The files containing navigation targets referenced in the file. They are
  /// referenced by `NavigationTarget`s by their index in this array.
  final List<String> files;

  AnalysisNavigation(this.file, this.regions, this.targets, this.files);
}

class AnalysisOccurrences {
  static AnalysisOccurrences parse(Map m) => new AnalysisOccurrences(m['file'],
      new List.from(m['occurrences'].map((obj) => Occurrences.parse(obj))));

  /// The file in which the references occur.
  final String file;

  /// The occurrences of references to elements within the file.
  final List<Occurrences> occurrences;

  AnalysisOccurrences(this.file, this.occurrences);
}

class AnalysisOutline {
  static AnalysisOutline parse(Map m) =>
      new AnalysisOutline(m['file'], m['kind'], Outline.parse(m['outline']),
          libraryName: m['libraryName']);

  /// The file with which the outline is associated.
  final String file;

  /// The kind of the file.
  final String kind;

  /// The outline associated with the file.
  final Outline outline;

  /// The name of the library defined by the file using a "library" directive,
  /// or referenced by a "part of" directive. If both "library" and "part of"
  /// directives are present, then the "library" directive takes precedence.
  /// This field will be omitted if the file has neither "library" nor "part of"
  /// directives.
  final String? libraryName;

  AnalysisOutline(this.file, this.kind, this.outline, {this.libraryName});
}

class AnalysisOverrides {
  static AnalysisOverrides parse(Map m) => new AnalysisOverrides(m['file'],
      new List.from(m['overrides'].map((obj) => Override.parse(obj))));

  /// The file with which the overrides are associated.
  final String file;

  /// The overrides associated with the file.
  final List<Override> overrides;

  AnalysisOverrides(this.file, this.overrides);
}

class ErrorsResult {
  static ErrorsResult parse(Map m) => new ErrorsResult(
      new List.from(m['errors'].map((obj) => AnalysisError.parse(obj))));

  /// The errors associated with the file.
  final List<AnalysisError> errors;

  ErrorsResult(this.errors);
}

class HoverResult {
  static HoverResult parse(Map m) => new HoverResult(
      new List.from(m['hovers'].map((obj) => HoverInformation.parse(obj))));

  /// The hover information associated with the location. The list will be empty
  /// if no information could be determined for the location. The list can
  /// contain multiple items if the file is being analyzed in multiple contexts
  /// in conflicting ways (such as a part that is included in multiple
  /// libraries).
  final List<HoverInformation> hovers;

  HoverResult(this.hovers);
}

class ImportedElementsResult {
  static ImportedElementsResult parse(Map m) => new ImportedElementsResult(
      new List.from(m['elements'].map((obj) => ImportedElements.parse(obj))));

  /// The information about the elements that are referenced in the specified
  /// region of the specified file that come from imported libraries.
  final List<ImportedElements> elements;

  ImportedElementsResult(this.elements);
}

class LibraryDependenciesResult {
  static LibraryDependenciesResult parse(Map m) =>
      new LibraryDependenciesResult(
          new List.from(m['libraries']), new Map.from(m['packageMap']));

  /// A list of the paths of library elements referenced by files in existing
  /// analysis roots.
  final List<String> libraries;

  /// A mapping from context source roots to package maps which map package
  /// names to source directories for use in client-side package URI resolution.
  final Map<String, Map<String, List<String>>> packageMap;

  LibraryDependenciesResult(this.libraries, this.packageMap);
}

class NavigationResult {
  static NavigationResult parse(Map m) => new NavigationResult(
      new List.from(m['files']),
      new List.from(m['targets'].map((obj) => NavigationTarget.parse(obj))),
      new List.from(m['regions'].map((obj) => NavigationRegion.parse(obj))));

  /// A list of the paths of files that are referenced by the navigation
  /// targets.
  final List<String> files;

  /// A list of the navigation targets that are referenced by the navigation
  /// regions.
  final List<NavigationTarget> targets;

  /// A list of the navigation regions within the requested region of the file.
  final List<NavigationRegion> regions;

  NavigationResult(this.files, this.targets, this.regions);
}

class ReachableSourcesResult {
  static ReachableSourcesResult parse(Map m) =>
      new ReachableSourcesResult(new Map.from(m['sources']));

  /// A mapping from source URIs to directly reachable source URIs. For example,
  /// a file "foo.dart" that imports "bar.dart" would have the corresponding
  /// mapping { "file:///foo.dart" : ["file:///bar.dart"] }. If "bar.dart" has
  /// further imports (or exports) there will be a mapping from the URI
  /// "file:///bar.dart" to them. To check if a specific URI is reachable from a
  /// given file, clients can check for its presence in the resulting key set.
  final Map<String, List<String>> sources;

  ReachableSourcesResult(this.sources);
}

class SignatureResult {
  static SignatureResult parse(Map m) => new SignatureResult(m['name'],
      new List.from(m['parameters'].map((obj) => ParameterInfo.parse(obj))),
      dartdoc: m['dartdoc']);

  /// The name of the function being invoked at the given offset.
  final String name;

  /// A list of information about each of the parameters of the function being
  /// invoked.
  final List<ParameterInfo> parameters;

  /// The dartdoc associated with the function being invoked. Other than the
  /// removal of the comment delimiters, including leading asterisks in the case
  /// of a block comment, the dartdoc is unprocessed markdown. This data is
  /// omitted if there is no referenced element, or if the element has no
  /// dartdoc.
  final String? dartdoc;

  SignatureResult(this.name, this.parameters, {this.dartdoc});
}

// completion domain

/// The code completion domain contains commands related to getting code
/// completion suggestions.
class CompletionDomain extends Domain {
  CompletionDomain(AnalysisServer server) : super(server, 'completion');

  /// Reports the completion suggestions that should be presented to the user.
  /// The set of suggestions included in the notification is always a complete
  /// list that supersedes any previously reported suggestions.
  Stream<CompletionResults> get onResults {
    return _listen('completion.results', CompletionResults.parse);
  }

  /// Reports the pre-computed, candidate completions from symbols defined in a
  /// corresponding library. This notification may be sent multiple times. When
  /// a notification is processed, clients should replace any previous
  /// information about the libraries in the list of changedLibraries, discard
  /// any information about the libraries in the list of removedLibraries, and
  /// preserve any previously received information about any libraries that are
  /// not included in either list.
  Stream<CompletionAvailableSuggestions> get onAvailableSuggestions {
    return _listen('completion.availableSuggestions',
        CompletionAvailableSuggestions.parse);
  }

  /// Reports existing imports in a library. This notification may be sent
  /// multiple times for a library. When a notification is processed, clients
  /// should replace any previous information for the library.
  Stream<CompletionExistingImports> get onExistingImports {
    return _listen(
        'completion.existingImports', CompletionExistingImports.parse);
  }

  /// Request that completion suggestions for the given offset in the given file
  /// be returned.
  Future<SuggestionsResult> getSuggestions(String? file, int? offset) {
    final Map m = {'file': file, 'offset': offset};
    return _call('completion.getSuggestions', m).then(SuggestionsResult.parse);
  }

  /// Subscribe for completion services. All previous subscriptions are replaced
  /// by the given set of services.
  ///
  /// It is an error if any of the elements in the list are not valid services.
  /// If there is an error, then the current subscriptions will remain
  /// unchanged.
  Future setSubscriptions(List<String> subscriptions) =>
      _call('completion.setSubscriptions', {'subscriptions': subscriptions});

  @deprecated
  Future registerLibraryPaths(List<LibraryPathSet> paths) =>
      _call('completion.registerLibraryPaths', {'paths': paths});

  /// Clients must make this request when the user has selected a completion
  /// suggestion from an `AvailableSuggestionSet`. Analysis server will respond
  /// with the text to insert as well as any `SourceChange` that needs to be
  /// applied in case the completion requires an additional import to be added.
  /// It is an error if the id is no longer valid, for instance if the library
  /// has been removed after the completion suggestion is accepted.
  Future<SuggestionDetailsResult> getSuggestionDetails(
      String? file, int? id, String? label, int? offset) {
    final Map m = {'file': file, 'id': id, 'label': label, 'offset': offset};
    return _call('completion.getSuggestionDetails', m)
        .then(SuggestionDetailsResult.parse);
  }

  /// Inspect analysis server's knowledge about all of a file's tokens including
  /// their lexeme, type, and what element kinds would have been appropriate for
  /// the token's program location.
  @experimental
  Future<ListTokenDetailsResult> listTokenDetails(String? file) {
    final Map m = {'file': file};
    return _call('completion.listTokenDetails', m)
        .then(ListTokenDetailsResult.parse);
  }
}

class CompletionResults {
  static CompletionResults parse(Map m) => new CompletionResults(
      m['id'],
      m['replacementOffset'],
      m['replacementLength'],
      new List.from(m['results'].map((obj) => CompletionSuggestion.parse(obj))),
      m['isLast'],
      libraryFile: m['libraryFile'],
      includedSuggestionSets: m['includedSuggestionSets'] == null
          ? null
          : new List.from(m['includedSuggestionSets']
              .map((obj) => IncludedSuggestionSet.parse(obj))),
      includedElementKinds: m['includedElementKinds'] == null
          ? null
          : new List.from(m['includedElementKinds']),
      includedSuggestionRelevanceTags:
          m['includedSuggestionRelevanceTags'] == null
              ? null
              : new List.from(m['includedSuggestionRelevanceTags']
                  .map((obj) => IncludedSuggestionRelevanceTag.parse(obj))));

  /// The id associated with the completion.
  final String id;

  /// The offset of the start of the text to be replaced. This will be different
  /// than the offset used to request the completion suggestions if there was a
  /// portion of an identifier before the original offset. In particular, the
  /// replacementOffset will be the offset of the beginning of said identifier.
  final int replacementOffset;

  /// The length of the text to be replaced if the remainder of the identifier
  /// containing the cursor is to be replaced when the suggestion is applied
  /// (that is, the number of characters in the existing identifier).
  final int replacementLength;

  /// The completion suggestions being reported. The notification contains all
  /// possible completions at the requested cursor position, even those that do
  /// not match the characters the user has already typed. This allows the
  /// client to respond to further keystrokes from the user without having to
  /// make additional requests.
  final List<CompletionSuggestion> results;

  /// True if this is that last set of results that will be returned for the
  /// indicated completion.
  final bool isLast;

  /// The library file that contains the file where completion was requested.
  /// The client might use it for example together with the `existingImports`
  /// notification to filter out available suggestions. If there were changes to
  /// existing imports in the library, the corresponding `existingImports`
  /// notification will be sent before the completion notification.
  final String? libraryFile;

  /// References to `AvailableSuggestionSet` objects previously sent to the
  /// client. The client can include applicable names from the referenced
  /// library in code completion suggestions.
  final List<IncludedSuggestionSet>? includedSuggestionSets;

  /// The client is expected to check this list against the `ElementKind` sent
  /// in `IncludedSuggestionSet` to decide whether or not these symbols should
  /// should be presented to the user.
  final List<String>? includedElementKinds;

  /// The client is expected to check this list against the values of the field
  /// `relevanceTags` of `AvailableSuggestion` to decide if the suggestion
  /// should be given a different relevance than the `IncludedSuggestionSet`
  /// that contains it. This might be used for example to give higher relevance
  /// to suggestions of matching types.
  ///
  /// If an `AvailableSuggestion` has relevance tags that match more than one
  /// `IncludedSuggestionRelevanceTag`, the maximum relevance boost is used.
  final List<IncludedSuggestionRelevanceTag>? includedSuggestionRelevanceTags;

  CompletionResults(this.id, this.replacementOffset, this.replacementLength,
      this.results, this.isLast,
      {this.libraryFile,
      this.includedSuggestionSets,
      this.includedElementKinds,
      this.includedSuggestionRelevanceTags});
}

class CompletionAvailableSuggestions {
  static CompletionAvailableSuggestions parse(Map m) =>
      new CompletionAvailableSuggestions(
          changedLibraries: m['changedLibraries'] == null
              ? null
              : new List.from(m['changedLibraries']
                  .map((obj) => AvailableSuggestionSet.parse(obj))),
          removedLibraries: m['removedLibraries'] == null
              ? null
              : new List.from(m['removedLibraries']));

  /// A list of pre-computed, potential completions coming from this set of
  /// completion suggestions.
  final List<AvailableSuggestionSet>? changedLibraries;

  /// A list of library ids that no longer apply.
  final List<int>? removedLibraries;

  CompletionAvailableSuggestions(
      {this.changedLibraries, this.removedLibraries});
}

class CompletionExistingImports {
  static CompletionExistingImports parse(Map m) =>
      new CompletionExistingImports(
          m['file'], ExistingImports.parse(m['imports']));

  /// The defining file of the library.
  final String file;

  /// The existing imports in the library.
  final ExistingImports imports;

  CompletionExistingImports(this.file, this.imports);
}

class SuggestionsResult {
  static SuggestionsResult parse(Map m) => new SuggestionsResult(m['id']);

  /// The identifier used to associate results with this completion request.
  final String id;

  SuggestionsResult(this.id);
}

class SuggestionDetailsResult {
  static SuggestionDetailsResult parse(Map m) =>
      new SuggestionDetailsResult(m['completion'],
          change: m['change'] == null ? null : SourceChange.parse(m['change']));

  /// The full text to insert, including any optional import prefix.
  final String completion;

  /// A change for the client to apply in case the library containing the
  /// accepted completion suggestion needs to be imported. The field will be
  /// omitted if there are no additional changes that need to be made.
  final SourceChange? change;

  SuggestionDetailsResult(this.completion, {this.change});
}

class ListTokenDetailsResult {
  static ListTokenDetailsResult parse(Map m) => new ListTokenDetailsResult(
      new List.from(m['tokens'].map((obj) => TokenDetails.parse(obj))));

  /// A list of the file's scanned tokens including analysis information about
  /// them.
  final List<TokenDetails> tokens;

  ListTokenDetailsResult(this.tokens);
}

// search domain

/// The search domain contains commands related to searches that can be
/// performed against the code base.
class SearchDomain extends Domain {
  SearchDomain(AnalysisServer server) : super(server, 'search');

  /// Reports some or all of the results of performing a requested search.
  /// Unlike other notifications, this notification contains search results that
  /// should be added to any previously received search results associated with
  /// the same search id.
  Stream<SearchResults> get onResults {
    return _listen('search.results', SearchResults.parse);
  }

  /// Perform a search for references to the element defined or referenced at
  /// the given offset in the given file.
  ///
  /// An identifier is returned immediately, and individual results will be
  /// returned via the search.results notification as they become available.
  Future<FindElementReferencesResult> findElementReferences(
      String? file, int? offset, bool? includePotential) {
    final Map m = {
      'file': file,
      'offset': offset,
      'includePotential': includePotential
    };
    return _call('search.findElementReferences', m)
        .then(FindElementReferencesResult.parse);
  }

  /// Perform a search for declarations of members whose name is equal to the
  /// given name.
  ///
  /// An identifier is returned immediately, and individual results will be
  /// returned via the search.results notification as they become available.
  Future<FindMemberDeclarationsResult> findMemberDeclarations(String? name) {
    final Map m = {'name': name};
    return _call('search.findMemberDeclarations', m)
        .then(FindMemberDeclarationsResult.parse);
  }

  /// Perform a search for references to members whose name is equal to the
  /// given name. This search does not check to see that there is a member
  /// defined with the given name, so it is able to find references to undefined
  /// members as well.
  ///
  /// An identifier is returned immediately, and individual results will be
  /// returned via the search.results notification as they become available.
  Future<FindMemberReferencesResult> findMemberReferences(String? name) {
    final Map m = {'name': name};
    return _call('search.findMemberReferences', m)
        .then(FindMemberReferencesResult.parse);
  }

  /// Perform a search for declarations of top-level elements (classes,
  /// typedefs, getters, setters, functions and fields) whose name matches the
  /// given pattern.
  ///
  /// An identifier is returned immediately, and individual results will be
  /// returned via the search.results notification as they become available.
  Future<FindTopLevelDeclarationsResult> findTopLevelDeclarations(
      String? pattern) {
    final Map m = {'pattern': pattern};
    return _call('search.findTopLevelDeclarations', m)
        .then(FindTopLevelDeclarationsResult.parse);
  }

  /// Return top-level and class member declarations.
  @experimental
  Future<ElementDeclarationsResult> getElementDeclarations(
      {String? file, String? pattern, int? maxResults}) {
    final Map m = {};
    if (file != null) m['file'] = file;
    if (pattern != null) m['pattern'] = pattern;
    if (maxResults != null) m['maxResults'] = maxResults;
    return _call('search.getElementDeclarations', m)
        .then(ElementDeclarationsResult.parse);
  }

  /// Return the type hierarchy of the class declared or referenced at the given
  /// location.
  Future<TypeHierarchyResult> getTypeHierarchy(String? file, int? offset,
      {bool? superOnly}) {
    final Map m = {'file': file, 'offset': offset};
    if (superOnly != null) m['superOnly'] = superOnly;
    return _call('search.getTypeHierarchy', m).then(TypeHierarchyResult.parse);
  }
}

class SearchResults {
  static SearchResults parse(Map m) => new SearchResults(
      m['id'],
      new List.from(m['results'].map((obj) => SearchResult.parse(obj))),
      m['isLast']);

  /// The id associated with the search.
  final String id;

  /// The search results being reported.
  final List<SearchResult> results;

  /// True if this is that last set of results that will be returned for the
  /// indicated search.
  final bool isLast;

  SearchResults(this.id, this.results, this.isLast);
}

class FindElementReferencesResult {
  static FindElementReferencesResult parse(Map m) =>
      new FindElementReferencesResult(
          id: m['id'],
          element: m['element'] == null ? null : Element.parse(m['element']));

  /// The identifier used to associate results with this search request.
  ///
  /// If no element was found at the given location, this field will be absent,
  /// and no results will be reported via the search.results notification.
  final String? id;

  /// The element referenced or defined at the given offset and whose references
  /// will be returned in the search results.
  ///
  /// If no element was found at the given location, this field will be absent.
  final Element? element;

  FindElementReferencesResult({this.id, this.element});
}

class FindMemberDeclarationsResult {
  static FindMemberDeclarationsResult parse(Map m) =>
      new FindMemberDeclarationsResult(m['id']);

  /// The identifier used to associate results with this search request.
  final String id;

  FindMemberDeclarationsResult(this.id);
}

class FindMemberReferencesResult {
  static FindMemberReferencesResult parse(Map m) =>
      new FindMemberReferencesResult(m['id']);

  /// The identifier used to associate results with this search request.
  final String id;

  FindMemberReferencesResult(this.id);
}

class FindTopLevelDeclarationsResult {
  static FindTopLevelDeclarationsResult parse(Map m) =>
      new FindTopLevelDeclarationsResult(m['id']);

  /// The identifier used to associate results with this search request.
  final String id;

  FindTopLevelDeclarationsResult(this.id);
}

class ElementDeclarationsResult {
  static ElementDeclarationsResult parse(Map m) =>
      new ElementDeclarationsResult(
          new List.from(
              m['declarations'].map((obj) => ElementDeclaration.parse(obj))),
          new List.from(m['files']));

  /// The list of declarations.
  final List<ElementDeclaration> declarations;

  /// The list of the paths of files with declarations.
  final List<String> files;

  ElementDeclarationsResult(this.declarations, this.files);
}

class TypeHierarchyResult {
  static TypeHierarchyResult parse(Map m) => new TypeHierarchyResult(
      hierarchyItems: m['hierarchyItems'] == null
          ? null
          : new List.from(
              m['hierarchyItems'].map((obj) => TypeHierarchyItem.parse(obj))));

  /// A list of the types in the requested hierarchy. The first element of the
  /// list is the item representing the type for which the hierarchy was
  /// requested. The index of other elements of the list is unspecified, but
  /// correspond to the integers used to reference supertype and subtype items
  /// within the items.
  ///
  /// This field will be absent if the code at the given file and offset does
  /// not represent a type, or if the file has not been sufficiently analyzed to
  /// allow a type hierarchy to be produced.
  final List<TypeHierarchyItem>? hierarchyItems;

  TypeHierarchyResult({this.hierarchyItems});
}

// edit domain

/// The edit domain contains commands related to edits that can be applied to
/// the code.
class EditDomain extends Domain {
  EditDomain(AnalysisServer server) : super(server, 'edit');

  /// Format the contents of a single file. The currently selected region of
  /// text is passed in so that the selection can be preserved across the
  /// formatting operation. The updated selection will be as close to matching
  /// the original as possible, but whitespace at the beginning or end of the
  /// selected region will be ignored. If preserving selection information is
  /// not required, zero (0) can be specified for both the selection offset and
  /// selection length.
  ///
  /// If a request is made for a file which does not exist, or which is not
  /// currently subject to analysis (e.g. because it is not associated with any
  /// analysis root specified to analysis.setAnalysisRoots), an error of type
  /// `FORMAT_INVALID_FILE` will be generated. If the source contains syntax
  /// errors, an error of type `FORMAT_WITH_ERRORS` will be generated.
  Future<FormatResult> format(
      String? file, int? selectionOffset, int? selectionLength,
      {int? lineLength}) {
    final Map m = {
      'file': file,
      'selectionOffset': selectionOffset,
      'selectionLength': selectionLength
    };
    if (lineLength != null) m['lineLength'] = lineLength;
    return _call('edit.format', m).then(FormatResult.parse);
  }

  /// Return the set of assists that are available at the given location. An
  /// assist is distinguished from a refactoring primarily by the fact that it
  /// affects a single file and does not require user input in order to be
  /// performed.
  Future<AssistsResult> getAssists(String? file, int? offset, int? length) {
    final Map m = {'file': file, 'offset': offset, 'length': length};
    return _call('edit.getAssists', m).then(AssistsResult.parse);
  }

  /// Get a list of the kinds of refactorings that are valid for the given
  /// selection in the given file.
  Future<AvailableRefactoringsResult> getAvailableRefactorings(
      String? file, int? offset, int? length) {
    final Map m = {'file': file, 'offset': offset, 'length': length};
    return _call('edit.getAvailableRefactorings', m)
        .then(AvailableRefactoringsResult.parse);
  }

  /// Request information about edit.dartfix such as the list of known fixes
  /// that can be specified in an edit.dartfix request.
  @experimental
  Future<DartfixInfoResult> getDartfixInfo() =>
      _call('edit.getDartfixInfo').then(DartfixInfoResult.parse);

  /// Analyze the specified sources for fixes that can be applied in bulk and
  /// return a set of suggested edits for those sources. These edits may include
  /// changes to sources outside the set of specified sources if a change in a
  /// specified source requires it.
  @experimental
  Future<BulkFixesResult> bulkFixes(List<String>? included) {
    final Map m = {'included': included};
    return _call('edit.bulkFixes', m).then(BulkFixesResult.parse);
  }

  /// Analyze the specified sources for recommended changes and return a set of
  /// suggested edits for those sources. These edits may include changes to
  /// sources outside the set of specified sources if a change in a specified
  /// source requires it.
  ///
  /// If includedFixes is specified, then those fixes will be applied. If
  /// includePedanticFixes is specified, then fixes associated with the pedantic
  /// rule set will be applied in addition to whatever fixes are specified in
  /// includedFixes if any. If neither includedFixes nor includePedanticFixes is
  /// specified, then no fixes will be applied. If excludedFixes is specified,
  /// then those fixes will not be applied regardless of whether they are
  /// specified in includedFixes.
  @experimental
  Future<DartfixResult> dartfix(List<String>? included,
      {List<String>? includedFixes,
      bool? includePedanticFixes,
      List<String>? excludedFixes,
      int? port,
      String? outputDir}) {
    final Map m = {'included': included};
    if (includedFixes != null) m['includedFixes'] = includedFixes;
    if (includePedanticFixes != null) {
      m['includePedanticFixes'] = includePedanticFixes;
    }
    if (excludedFixes != null) m['excludedFixes'] = excludedFixes;
    if (port != null) m['port'] = port;
    if (outputDir != null) m['outputDir'] = outputDir;
    return _call('edit.dartfix', m).then(DartfixResult.parse);
  }

  /// Return the set of fixes that are available for the errors at a given
  /// offset in a given file.
  ///
  /// If a request is made for a file which does not exist, or which is not
  /// currently subject to analysis (e.g. because it is not associated with any
  /// analysis root specified to analysis.setAnalysisRoots), an error of type
  /// `GET_FIXES_INVALID_FILE` will be generated.
  Future<FixesResult> getFixes(String? file, int? offset) {
    final Map m = {'file': file, 'offset': offset};
    return _call('edit.getFixes', m).then(FixesResult.parse);
  }

  /// Get the changes required to convert the postfix template at the given
  /// location into the template's expanded form.
  Future<PostfixCompletionResult> getPostfixCompletion(
      String? file, String? key, int? offset) {
    final Map m = {'file': file, 'key': key, 'offset': offset};
    return _call('edit.getPostfixCompletion', m)
        .then(PostfixCompletionResult.parse);
  }

  /// Get the changes required to perform a refactoring.
  ///
  /// If another refactoring request is received during the processing of this
  /// one, an error of type `REFACTORING_REQUEST_CANCELLED` will be generated.
  Future<RefactoringResult?> getRefactoring(
      String? kind, String? file, int? offset, int? length, bool? validateOnly,
      {RefactoringOptions? options}) {
    final Map m = {
      'kind': kind,
      'file': file,
      'offset': offset,
      'length': length,
      'validateOnly': validateOnly
    };
    if (options != null) m['options'] = options;
    return _call('edit.getRefactoring', m)
        .then((m) => RefactoringResult.parse(kind, m));
  }

  /// Get the changes required to convert the partial statement at the given
  /// location into a syntactically valid statement. If the current statement is
  /// already valid the change will insert a newline plus appropriate
  /// indentation at the end of the line containing the offset. If a change that
  /// makes the statement valid cannot be determined (perhaps because it has not
  /// yet been implemented) the statement will be considered already valid and
  /// the appropriate change returned.
  @experimental
  Future<StatementCompletionResult> getStatementCompletion(
      String? file, int? offset) {
    final Map m = {'file': file, 'offset': offset};
    return _call('edit.getStatementCompletion', m)
        .then(StatementCompletionResult.parse);
  }

  /// Determine if the request postfix completion template is applicable at the
  /// given location in the given file.
  @experimental
  Future<IsPostfixCompletionApplicableResult> isPostfixCompletionApplicable(
      String? file, String? key, int? offset) {
    final Map m = {'file': file, 'key': key, 'offset': offset};
    return _call('edit.isPostfixCompletionApplicable', m)
        .then(IsPostfixCompletionApplicableResult.parse);
  }

  /// Return a list of all postfix templates currently available.
  @experimental
  Future<ListPostfixCompletionTemplatesResult>
      listPostfixCompletionTemplates() =>
          _call('edit.listPostfixCompletionTemplates')
              .then(ListPostfixCompletionTemplatesResult.parse);

  /// Return a list of edits that would need to be applied in order to ensure
  /// that all of the elements in the specified list of imported elements are
  /// accessible within the library.
  ///
  /// If a request is made for a file that does not exist, or that is not
  /// currently subject to analysis (e.g. because it is not associated with any
  /// analysis root specified via analysis.setAnalysisRoots), an error of type
  /// `IMPORT_ELEMENTS_INVALID_FILE` will be generated.
  @experimental
  Future<ImportElementsResult> importElements(
      String? file, List<ImportedElements>? elements,
      {int? offset}) {
    final Map m = {'file': file, 'elements': elements};
    if (offset != null) m['offset'] = offset;
    return _call('edit.importElements', m).then(ImportElementsResult.parse);
  }

  /// Sort all of the directives, unit and class members of the given Dart file.
  ///
  /// If a request is made for a file that does not exist, does not belong to an
  /// analysis root or is not a Dart file, `SORT_MEMBERS_INVALID_FILE` will be
  /// generated.
  ///
  /// If the Dart file has scan or parse errors, `SORT_MEMBERS_PARSE_ERRORS`
  /// will be generated.
  Future<SortMembersResult> sortMembers(String? file) {
    final Map m = {'file': file};
    return _call('edit.sortMembers', m).then(SortMembersResult.parse);
  }

  /// Organizes all of the directives - removes unused imports and sorts
  /// directives of the given Dart file according to the (Dart Style
  /// Guide)[https://dart.dev/guides/language/effective-dart/style].
  ///
  /// If a request is made for a file that does not exist, does not belong to an
  /// analysis root or is not a Dart file, `FILE_NOT_ANALYZED` will be
  /// generated.
  ///
  /// If directives of the Dart file cannot be organized, for example because it
  /// has scan or parse errors, or by other reasons, `ORGANIZE_DIRECTIVES_ERROR`
  /// will be generated. The message will provide details about the reason.
  Future<OrganizeDirectivesResult> organizeDirectives(String? file) {
    final Map m = {'file': file};
    return _call('edit.organizeDirectives', m)
        .then(OrganizeDirectivesResult.parse);
  }
}

class FormatResult {
  static FormatResult parse(Map m) => new FormatResult(
      new List.from(m['edits'].map((obj) => SourceEdit.parse(obj))),
      m['selectionOffset'],
      m['selectionLength']);

  /// The edit(s) to be applied in order to format the code. The list will be
  /// empty if the code was already formatted (there are no changes).
  final List<SourceEdit> edits;

  /// The offset of the selection after formatting the code.
  final int selectionOffset;

  /// The length of the selection after formatting the code.
  final int selectionLength;

  FormatResult(this.edits, this.selectionOffset, this.selectionLength);
}

class AssistsResult {
  static AssistsResult parse(Map m) => new AssistsResult(
      new List.from(m['assists'].map((obj) => SourceChange.parse(obj))));

  /// The assists that are available at the given location.
  final List<SourceChange> assists;

  AssistsResult(this.assists);
}

class AvailableRefactoringsResult {
  static AvailableRefactoringsResult parse(Map m) =>
      new AvailableRefactoringsResult(new List.from(m['kinds']));

  /// The kinds of refactorings that are valid for the given selection.
  final List<String> kinds;

  AvailableRefactoringsResult(this.kinds);
}

class DartfixInfoResult {
  static DartfixInfoResult parse(Map m) => new DartfixInfoResult(
      new List.from(m['fixes'].map((obj) => DartFix.parse(obj))));

  /// A list of fixes that can be specified in an edit.dartfix request.
  final List<DartFix> fixes;

  DartfixInfoResult(this.fixes);
}

class BulkFixesResult {
  static BulkFixesResult parse(Map m) => new BulkFixesResult(
      new List.from(m['edits'].map((obj) => SourceFileEdit.parse(obj))),
      new List.from(m['details'].map((obj) => BulkFix.parse(obj))));

  /// A list of source edits to apply the recommended changes.
  final List<SourceFileEdit> edits;

  /// Details that summarize the fixes associated with the recommended changes.
  final List<BulkFix> details;

  BulkFixesResult(this.edits, this.details);
}

class DartfixResult {
  static DartfixResult parse(Map m) => new DartfixResult(
      new List.from(
          m['suggestions'].map((obj) => DartFixSuggestion.parse(obj))),
      new List.from(
          m['otherSuggestions'].map((obj) => DartFixSuggestion.parse(obj))),
      m['hasErrors'],
      new List.from(m['edits'].map((obj) => SourceFileEdit.parse(obj))),
      details: m['details'] == null ? null : new List.from(m['details']),
      port: m['port'],
      urls: m['urls'] == null ? null : new List.from(m['urls']));

  /// A list of recommended changes that can be automatically made by applying
  /// the 'edits' included in this response.
  final List<DartFixSuggestion> suggestions;

  /// A list of recommended changes that could not be automatically made.
  final List<DartFixSuggestion> otherSuggestions;

  /// True if the analyzed source contains errors that might impact the
  /// correctness of the recommended changes that can be automatically applied.
  final bool hasErrors;

  /// A list of source edits to apply the recommended changes.
  final List<SourceFileEdit> edits;

  /// Messages that should be displayed to the user that describe details of the
  /// fix generation. For example, the messages might (a) point out details that
  /// users might want to explore before committing the changes or (b) describe
  /// exceptions that were thrown but that did not stop the fixes from being
  /// produced. The list will be omitted if it is empty.
  final List<String>? details;

  /// The port on which the preview tool will respond to GET requests. The field
  /// is omitted if a preview was not requested.
  final int? port;

  /// The URLs that users can visit in a browser to see a preview of the
  /// proposed changes. There is one URL for each of the included file paths.
  /// The field is omitted if a preview was not requested.
  final List<String>? urls;

  DartfixResult(
      this.suggestions, this.otherSuggestions, this.hasErrors, this.edits,
      {this.details, this.port, this.urls});
}

class FixesResult {
  static FixesResult parse(Map m) => new FixesResult(
      new List.from(m['fixes'].map((obj) => AnalysisErrorFixes.parse(obj))));

  /// The fixes that are available for the errors at the given offset.
  final List<AnalysisErrorFixes> fixes;

  FixesResult(this.fixes);
}

class PostfixCompletionResult {
  static PostfixCompletionResult parse(Map m) =>
      new PostfixCompletionResult(SourceChange.parse(m['change']));

  /// The change to be applied in order to complete the statement.
  final SourceChange change;

  PostfixCompletionResult(this.change);
}

class RefactoringResult {
  static RefactoringResult? parse(String? kind, Map m) => new RefactoringResult(
      new List.from(
          m['initialProblems'].map((obj) => RefactoringProblem.parse(obj))),
      new List.from(
          m['optionsProblems'].map((obj) => RefactoringProblem.parse(obj))),
      new List.from(
          m['finalProblems'].map((obj) => RefactoringProblem.parse(obj))),
      feedback: RefactoringFeedback.parse(kind, m['feedback']),
      change: m['change'] == null ? null : SourceChange.parse(m['change']),
      potentialEdits: m['potentialEdits'] == null
          ? null
          : new List.from(m['potentialEdits']));

  /// The initial status of the refactoring, i.e. problems related to the
  /// context in which the refactoring is requested. The array will be empty if
  /// there are no known problems.
  final List<RefactoringProblem> initialProblems;

  /// The options validation status, i.e. problems in the given options, such as
  /// light-weight validation of a new name, flags compatibility, etc. The array
  /// will be empty if there are no known problems.
  final List<RefactoringProblem> optionsProblems;

  /// The final status of the refactoring, i.e. problems identified in the
  /// result of a full, potentially expensive validation and / or change
  /// creation. The array will be empty if there are no known problems.
  final List<RefactoringProblem> finalProblems;

  /// Data used to provide feedback to the user. The structure of the data is
  /// dependent on the kind of refactoring being created. The data that is
  /// returned is documented in the section titled
  /// (Refactorings)[#refactorings], labeled as "Feedback".
  final RefactoringFeedback? feedback;

  /// The changes that are to be applied to affect the refactoring. This field
  /// will be omitted if there are problems that prevent a set of changes from
  /// being computed, such as having no options specified for a refactoring that
  /// requires them, or if only validation was requested.
  final SourceChange? change;

  /// The ids of source edits that are not known to be valid. An edit is not
  /// known to be valid if there was insufficient type information for the
  /// server to be able to determine whether or not the code needs to be
  /// modified, such as when a member is being renamed and there is a reference
  /// to a member from an unknown type. This field will be omitted if the change
  /// field is omitted or if there are no potential edits for the refactoring.
  final List<String>? potentialEdits;

  RefactoringResult(
      this.initialProblems, this.optionsProblems, this.finalProblems,
      {this.feedback, this.change, this.potentialEdits});
}

class StatementCompletionResult {
  static StatementCompletionResult parse(Map m) =>
      new StatementCompletionResult(
          SourceChange.parse(m['change']), m['whitespaceOnly']);

  /// The change to be applied in order to complete the statement.
  final SourceChange change;

  /// Will be true if the change contains nothing but whitespace characters, or
  /// is empty.
  final bool whitespaceOnly;

  StatementCompletionResult(this.change, this.whitespaceOnly);
}

class IsPostfixCompletionApplicableResult {
  static IsPostfixCompletionApplicableResult parse(Map m) =>
      new IsPostfixCompletionApplicableResult(m['value']);

  /// True if the template can be expanded at the given location.
  final bool value;

  IsPostfixCompletionApplicableResult(this.value);
}

class ListPostfixCompletionTemplatesResult {
  static ListPostfixCompletionTemplatesResult parse(Map m) =>
      new ListPostfixCompletionTemplatesResult(new List.from(
          m['templates'].map((obj) => PostfixTemplateDescriptor.parse(obj))));

  /// The list of available templates.
  final List<PostfixTemplateDescriptor> templates;

  ListPostfixCompletionTemplatesResult(this.templates);
}

class ImportElementsResult {
  static ImportElementsResult parse(Map m) => new ImportElementsResult(
      edit: m['edit'] == null ? null : SourceFileEdit.parse(m['edit']));

  /// The edits to be applied in order to make the specified elements
  /// accessible. The file to be edited will be the defining compilation unit of
  /// the library containing the file specified in the request, which can be
  /// different than the file specified in the request if the specified file is
  /// a part file. This field will be omitted if there are no edits that need to
  /// be applied.
  final SourceFileEdit? edit;

  ImportElementsResult({this.edit});
}

class SortMembersResult {
  static SortMembersResult parse(Map m) =>
      new SortMembersResult(SourceFileEdit.parse(m['edit']));

  /// The file edit that is to be applied to the given file to effect the
  /// sorting.
  final SourceFileEdit edit;

  SortMembersResult(this.edit);
}

class OrganizeDirectivesResult {
  static OrganizeDirectivesResult parse(Map m) =>
      new OrganizeDirectivesResult(SourceFileEdit.parse(m['edit']));

  /// The file edit that is to be applied to the given file to effect the
  /// organizing.
  final SourceFileEdit edit;

  OrganizeDirectivesResult(this.edit);
}

// execution domain

/// The execution domain contains commands related to providing an execution or
/// debugging experience.
class ExecutionDomain extends Domain {
  ExecutionDomain(AnalysisServer server) : super(server, 'execution');

  /// Reports information needed to allow a single file to be launched.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value "LAUNCH_DATA" in the list of services passed in an
  /// `execution.setSubscriptions` request.
  Stream<ExecutionLaunchData> get onLaunchData {
    return _listen('execution.launchData', ExecutionLaunchData.parse);
  }

  /// Create an execution context for the executable file with the given path.
  /// The context that is created will persist until execution.deleteContext is
  /// used to delete it. Clients, therefore, are responsible for managing the
  /// lifetime of execution contexts.
  Future<CreateContextResult> createContext(String? contextRoot) {
    final Map m = {'contextRoot': contextRoot};
    return _call('execution.createContext', m).then(CreateContextResult.parse);
  }

  /// Delete the execution context with the given identifier. The context id is
  /// no longer valid after this command. The server is allowed to re-use ids
  /// when they are no longer valid.
  Future deleteContext(String id) =>
      _call('execution.deleteContext', {'id': id});

  /// Request completion suggestions for the given runtime context.
  ///
  /// It might take one or two requests of this type to get completion
  /// suggestions. The first request should have only "code", "offset", and
  /// "variables", but not "expressions". If there are sub-expressions that can
  /// have different runtime types, and are considered to be safe to evaluate at
  /// runtime (e.g. getters), so using their actual runtime types can improve
  /// completion results, the server will not include the "suggestions" field in
  /// the response, and instead will return the "expressions" field. The client
  /// will use debug API to get current runtime types for these sub-expressions
  /// and send another request, this time with "expressions". If there are no
  /// interesting sub-expressions to get runtime types for, or when the
  /// "expressions" field is provided by the client, the server will return
  /// "suggestions" in the response.
  Future<RuntimeSuggestionsResult> getSuggestions(
      String? code,
      int? offset,
      String? contextFile,
      int? contextOffset,
      List<RuntimeCompletionVariable>? variables,
      {List<RuntimeCompletionExpression>? expressions}) {
    final Map m = {
      'code': code,
      'offset': offset,
      'contextFile': contextFile,
      'contextOffset': contextOffset,
      'variables': variables
    };
    if (expressions != null) m['expressions'] = expressions;
    return _call('execution.getSuggestions', m)
        .then(RuntimeSuggestionsResult.parse);
  }

  /// Map a URI from the execution context to the file that it corresponds to,
  /// or map a file to the URI that it corresponds to in the execution context.
  ///
  /// Exactly one of the file and uri fields must be provided. If both fields
  /// are provided, then an error of type `INVALID_PARAMETER` will be generated.
  /// Similarly, if neither field is provided, then an error of type
  /// `INVALID_PARAMETER` will be generated.
  ///
  /// If the file field is provided and the value is not the path of a file
  /// (either the file does not exist or the path references something other
  /// than a file), then an error of type `INVALID_PARAMETER` will be generated.
  ///
  /// If the uri field is provided and the value is not a valid URI or if the
  /// URI references something that is not a file (either a file that does not
  /// exist or something other than a file), then an error of type
  /// `INVALID_PARAMETER` will be generated.
  ///
  /// If the contextRoot used to create the execution context does not exist,
  /// then an error of type `INVALID_EXECUTION_CONTEXT` will be generated.
  Future<MapUriResult> mapUri(String? id, {String? file, String? uri}) {
    final Map m = {'id': id};
    if (file != null) m['file'] = file;
    if (uri != null) m['uri'] = uri;
    return _call('execution.mapUri', m).then(MapUriResult.parse);
  }

  @deprecated
  Future setSubscriptions(List<String> subscriptions) =>
      _call('execution.setSubscriptions', {'subscriptions': subscriptions});
}

class ExecutionLaunchData {
  static ExecutionLaunchData parse(Map m) => new ExecutionLaunchData(m['file'],
      kind: m['kind'],
      referencedFiles: m['referencedFiles'] == null
          ? null
          : new List.from(m['referencedFiles']));

  /// The file for which launch data is being provided. This will either be a
  /// Dart library or an HTML file.
  final String file;

  /// The kind of the executable file. This field is omitted if the file is not
  /// a Dart file.
  final String? kind;

  /// A list of the Dart files that are referenced by the file. This field is
  /// omitted if the file is not an HTML file.
  final List<String>? referencedFiles;

  ExecutionLaunchData(this.file, {this.kind, this.referencedFiles});
}

class CreateContextResult {
  static CreateContextResult parse(Map m) => new CreateContextResult(m['id']);

  /// The identifier used to refer to the execution context that was created.
  final String id;

  CreateContextResult(this.id);
}

class RuntimeSuggestionsResult {
  static RuntimeSuggestionsResult parse(Map m) => new RuntimeSuggestionsResult(
      suggestions: m['suggestions'] == null
          ? null
          : new List.from(
              m['suggestions'].map((obj) => CompletionSuggestion.parse(obj))),
      expressions: m['expressions'] == null
          ? null
          : new List.from(m['expressions']
              .map((obj) => RuntimeCompletionExpression.parse(obj))));

  /// The completion suggestions. In contrast to usual completion request,
  /// suggestions for private elements also will be provided.
  ///
  /// If there are sub-expressions that can have different runtime types, and
  /// are considered to be safe to evaluate at runtime (e.g. getters), so using
  /// their actual runtime types can improve completion results, the server
  /// omits this field in the response, and instead will return the
  /// "expressions" field.
  final List<CompletionSuggestion>? suggestions;

  /// The list of sub-expressions in the code for which the server would like to
  /// know runtime types to provide better completion suggestions.
  ///
  /// This field is omitted the field "suggestions" is returned.
  final List<RuntimeCompletionExpression>? expressions;

  RuntimeSuggestionsResult({this.suggestions, this.expressions});
}

class MapUriResult {
  static MapUriResult parse(Map m) =>
      new MapUriResult(file: m['file'], uri: m['uri']);

  /// The file to which the URI was mapped. This field is omitted if the uri
  /// field was not given in the request.
  final String? file;

  /// The URI to which the file path was mapped. This field is omitted if the
  /// file field was not given in the request.
  final String? uri;

  MapUriResult({this.file, this.uri});
}

// diagnostic domain

/// The diagnostic domain contains server diagnostics APIs.
class DiagnosticDomain extends Domain {
  DiagnosticDomain(AnalysisServer server) : super(server, 'diagnostic');

  /// Return server diagnostics.
  Future<DiagnosticsResult> getDiagnostics() =>
      _call('diagnostic.getDiagnostics').then(DiagnosticsResult.parse);

  /// Return the port of the diagnostic web server. If the server is not running
  /// this call will start the server. If unable to start the diagnostic web
  /// server, this call will return an error of
  /// `DEBUG_PORT_COULD_NOT_BE_OPENED`.
  Future<ServerPortResult> getServerPort() =>
      _call('diagnostic.getServerPort').then(ServerPortResult.parse);
}

class DiagnosticsResult {
  static DiagnosticsResult parse(Map m) => new DiagnosticsResult(
      new List.from(m['contexts'].map((obj) => ContextData.parse(obj))));

  /// The list of analysis contexts.
  final List<ContextData> contexts;

  DiagnosticsResult(this.contexts);
}

class ServerPortResult {
  static ServerPortResult parse(Map m) => new ServerPortResult(m['port']);

  /// The diagnostic server port.
  final int port;

  ServerPortResult(this.port);
}

// analytics domain

/// The analytics domain contains APIs related to reporting analytics.
///
/// This API allows clients to expose a UI option to enable and disable the
/// analysis server's reporting of analytics. This value is shared with other
/// tools and can change outside of this API; because of this, clients should
/// use the analysis server's flag as the system of record. Clients can choose
/// to send in additional analytics (see `sendEvent` and `sendTiming`) if they
/// so choose. Dart command-line tools provide a disclaimer similar to: ` Dart
/// SDK tools anonymously report feature usage statistics and basic crash
/// reports to help improve Dart tools over time. See Google's privacy policy:
/// https://www.google.com/intl/en/policies/privacy/. `
///
/// The analysis server will send it's own analytics data (for example,
/// operations performed, operating system type, SDK version). No data (from the
/// analysis server or from clients) will be sent if analytics is disabled.
@experimental
class AnalyticsDomain extends Domain {
  AnalyticsDomain(AnalysisServer server) : super(server, 'analytics');

  /// Query whether analytics is enabled.
  ///
  /// This flag controls whether the analysis server sends any analytics data to
  /// the cloud. If disabled, the analysis server does not send any analytics
  /// data, and any data sent to it by clients (from `sendEvent` and
  /// `sendTiming`) will be ignored.
  ///
  /// The value of this flag can be changed by other tools outside of the
  /// analysis server's process. When you query the flag, you get the value of
  /// the flag at a given moment. Clients should not use the value returned to
  /// decide whether or not to send the `sendEvent` and `sendTiming` requests.
  /// Those requests should be used unconditionally and server will determine
  /// whether or not it is appropriate to forward the information to the cloud
  /// at the time each request is received.
  Future<IsEnabledResult> isEnabled() =>
      _call('analytics.isEnabled').then(IsEnabledResult.parse);

  /// Enable or disable the sending of analytics data. Note that there are other
  /// ways for users to change this setting, so clients cannot assume that they
  /// have complete control over this setting. In particular, there is no
  /// guarantee that the result returned by the `isEnabled` request will match
  /// the last value set via this request.
  Future enable(bool value) => _call('analytics.enable', {'value': value});

  /// Send information about client events.
  ///
  /// Ask the analysis server to include the fact that an action was performed
  /// in the client as part of the analytics data being sent. The data will only
  /// be included if the sending of analytics data is enabled at the time the
  /// request is processed. The action that was performed is indicated by the
  /// value of the `action` field.
  ///
  /// The value of the action field should not include the identity of the
  /// client. The analytics data sent by server will include the client id
  /// passed in using the `--client-id` command-line argument. The request will
  /// be ignored if the client id was not provided when server was started.
  Future sendEvent(String action) =>
      _call('analytics.sendEvent', {'action': action});

  /// Send timing information for client events (e.g. code completions).
  ///
  /// Ask the analysis server to include the fact that a timed event occurred as
  /// part of the analytics data being sent. The data will only be included if
  /// the sending of analytics data is enabled at the time the request is
  /// processed.
  ///
  /// The value of the event field should not include the identity of the
  /// client. The analytics data sent by server will include the client id
  /// passed in using the `--client-id` command-line argument. The request will
  /// be ignored if the client id was not provided when server was started.
  Future sendTiming(String? event, int? millis) {
    final Map m = {'event': event, 'millis': millis};
    return _call('analytics.sendTiming', m);
  }
}

class IsEnabledResult {
  static IsEnabledResult parse(Map m) => new IsEnabledResult(m['enabled']);

  /// Whether sending analytics is enabled or not.
  final bool enabled;

  IsEnabledResult(this.enabled);
}

// kythe domain

/// The kythe domain contains APIs related to generating Dart content in the
/// (Kythe)[http://kythe.io/] format.
@experimental
class KytheDomain extends Domain {
  KytheDomain(AnalysisServer server) : super(server, 'kythe');

  /// Return the list of `KytheEntry` objects for some file, given the current
  /// state of the file system populated by "analysis.updateContent".
  ///
  /// If a request is made for a file that does not exist, or that is not
  /// currently subject to analysis (e.g. because it is not associated with any
  /// analysis root specified to analysis.setAnalysisRoots), an error of type
  /// `GET_KYTHE_ENTRIES_INVALID_FILE` will be generated.
  Future<KytheEntriesResult> getKytheEntries(String? file) {
    final Map m = {'file': file};
    return _call('kythe.getKytheEntries', m).then(KytheEntriesResult.parse);
  }
}

class KytheEntriesResult {
  static KytheEntriesResult parse(Map m) => new KytheEntriesResult(
      new List.from(m['entries'].map((obj) => KytheEntry.parse(obj))),
      new List.from(m['files']));

  /// The list of `KytheEntry` objects for the queried file.
  final List<KytheEntry> entries;

  /// The set of files paths that were required, but not in the file system, to
  /// give a complete and accurate Kythe graph for the file. This could be due
  /// to a referenced file that does not exist or generated files not being
  /// generated or passed before the call to "getKytheEntries".
  final List<String> files;

  KytheEntriesResult(this.entries, this.files);
}

// flutter domain

/// The analysis domain contains API’s related to Flutter support.
class FlutterDomain extends Domain {
  FlutterDomain(AnalysisServer server) : super(server, 'flutter');

  /// Reports the Flutter outline associated with a single file.
  ///
  /// This notification is not subscribed to by default. Clients can subscribe
  /// by including the value `"OUTLINE"` in the list of services passed in an
  /// flutter.setSubscriptions request.
  Stream<FlutterOutlineEvent> get onOutline {
    return _listen('flutter.outline', FlutterOutlineEvent.parse);
  }

  /// Return the description of the widget instance at the given location.
  ///
  /// If the location does not have a support widget, an error of type
  /// `FLUTTER_GET_WIDGET_DESCRIPTION_NO_WIDGET` will be generated.
  ///
  /// If a change to a file happens while widget descriptions are computed, an
  /// error of type `FLUTTER_GET_WIDGET_DESCRIPTION_CONTENT_MODIFIED` will be
  /// generated.
  @experimental
  Future<WidgetDescriptionResult> getWidgetDescription(
      String? file, int? offset) {
    final Map m = {'file': file, 'offset': offset};
    return _call('flutter.getWidgetDescription', m)
        .then(WidgetDescriptionResult.parse);
  }

  /// Set the value of a property, or remove it.
  ///
  /// The server will generate a change that the client should apply to the
  /// project to get the value of the property set to the new value. The
  /// complexity of the change might be from updating a single literal value in
  /// the code, to updating multiple files to get libraries imported, and new
  /// intermediate widgets instantiated.
  @experimental
  Future<SetWidgetPropertyValueResult> setWidgetPropertyValue(int? id,
      {FlutterWidgetPropertyValue? value}) {
    final Map m = {'id': id};
    if (value != null) m['value'] = value;
    return _call('flutter.setWidgetPropertyValue', m)
        .then(SetWidgetPropertyValueResult.parse);
  }

  /// Subscribe for services that are specific to individual files. All previous
  /// subscriptions are replaced by the current set of subscriptions. If a given
  /// service is not included as a key in the map then no files will be
  /// subscribed to the service, exactly as if the service had been included in
  /// the map with an explicit empty list of files.
  ///
  /// Note that this request determines the set of requested subscriptions. The
  /// actual set of subscriptions at any given time is the intersection of this
  /// set with the set of files currently subject to analysis. The files
  /// currently subject to analysis are the set of files contained within an
  /// actual analysis root but not excluded, plus all of the files transitively
  /// reachable from those files via import, export and part directives. (See
  /// analysis.setAnalysisRoots for an explanation of how the actual analysis
  /// roots are determined.) When the actual analysis roots change, the actual
  /// set of subscriptions is automatically updated, but the set of requested
  /// subscriptions is unchanged.
  ///
  /// If a requested subscription is a directory it is ignored, but remains in
  /// the set of requested subscriptions so that if it later becomes a file it
  /// can be included in the set of actual subscriptions.
  ///
  /// It is an error if any of the keys in the map are not valid services. If
  /// there is an error, then the existing subscriptions will remain unchanged.
  Future setSubscriptions(Map<String, List<String>> subscriptions) =>
      _call('flutter.setSubscriptions', {'subscriptions': subscriptions});
}

class FlutterOutlineEvent {
  static FlutterOutlineEvent parse(Map m) =>
      new FlutterOutlineEvent(m['file'], FlutterOutline.parse(m['outline']));

  /// The file with which the outline is associated.
  final String file;

  /// The outline associated with the file.
  final FlutterOutline outline;

  FlutterOutlineEvent(this.file, this.outline);
}

class WidgetDescriptionResult {
  static WidgetDescriptionResult parse(Map m) =>
      new WidgetDescriptionResult(new List.from(
          m['properties'].map((obj) => FlutterWidgetProperty.parse(obj))));

  /// The list of properties of the widget. Some of the properties might be read
  /// only, when their `editor` is not set. This might be because they have type
  /// that we don't know how to edit, or for compound properties that work as
  /// containers for sub-properties.
  final List<FlutterWidgetProperty> properties;

  WidgetDescriptionResult(this.properties);
}

class SetWidgetPropertyValueResult {
  static SetWidgetPropertyValueResult parse(Map m) =>
      new SetWidgetPropertyValueResult(SourceChange.parse(m['change']));

  /// The change that should be applied.
  final SourceChange change;

  SetWidgetPropertyValueResult(this.change);
}

// type definitions

/// A directive to begin overlaying the contents of a file. The supplied content
/// will be used for analysis in place of the file contents in the filesystem.
///
/// If this directive is used on a file that already has a file content overlay,
/// the old overlay is discarded and replaced with the new one.
class AddContentOverlay extends ContentOverlayType implements Jsonable {
  static AddContentOverlay parse(Map m) {
    return new AddContentOverlay(m['content']);
  }

  /// The new content of the file.
  final String content;

  AddContentOverlay(this.content) : super('add');

  Map toMap() => _stripNullValues({'type': type, 'content': content});
}

/// An indication of an error, warning, or hint that was produced by the
/// analysis.
class AnalysisError {
  static AnalysisError parse(Map m) {
    return new AnalysisError(m['severity'], m['type'],
        Location.parse(m['location']), m['message'], m['code'],
        correction: m['correction'],
        url: m['url'],
        contextMessages: m['contextMessages'] == null
            ? null
            : new List.from(m['contextMessages']
                .map((obj) => DiagnosticMessage.parse(obj))),
        hasFix: m['hasFix']);
  }

  /// The severity of the error.
  final String severity;

  /// The type of the error.
  final String type;

  /// The location associated with the error.
  final Location location;

  /// The message to be displayed for this error. The message should indicate
  /// what is wrong with the code and why it is wrong.
  final String message;

  /// The name, as a string, of the error code associated with this error.
  final String code;

  /// The correction message to be displayed for this error. The correction
  /// message should indicate how the user can fix the error. The field is
  /// omitted if there is no correction message associated with the error code.
  final String? correction;

  /// The URL of a page containing documentation associated with this error.
  final String? url;

  /// Additional messages associated with this diagnostic that provide context
  /// to help the user understand the diagnostic.
  final List<DiagnosticMessage>? contextMessages;

  /// A hint to indicate to interested clients that this error has an associated
  /// fix (or fixes). The absence of this field implies there are not known to
  /// be fixes. Note that since the operation to calculate whether fixes apply
  /// needs to be performant it is possible that complicated tests will be
  /// skipped and a false negative returned. For this reason, this attribute
  /// should be treated as a "hint". Despite the possibility of false negatives,
  /// no false positives should be returned. If a client sees this flag set they
  /// can proceed with the confidence that there are in fact associated fixes.
  final bool? hasFix;

  AnalysisError(
      this.severity, this.type, this.location, this.message, this.code,
      {this.correction, this.url, this.contextMessages, this.hasFix});

  bool operator ==(o) =>
      o is AnalysisError &&
      severity == o.severity &&
      type == o.type &&
      location == o.location &&
      message == o.message &&
      code == o.code &&
      correction == o.correction &&
      url == o.url &&
      contextMessages == o.contextMessages &&
      hasFix == o.hasFix;

  int get hashCode =>
      severity.hashCode ^
      type.hashCode ^
      location.hashCode ^
      message.hashCode ^
      code.hashCode;

  String toString() =>
      '[AnalysisError severity: ${severity}, type: ${type}, location: ${location}, message: ${message}, code: ${code}]';
}

/// A list of fixes associated with a specific error.
class AnalysisErrorFixes {
  static AnalysisErrorFixes parse(Map m) {
    return new AnalysisErrorFixes(AnalysisError.parse(m['error']),
        new List.from(m['fixes'].map((obj) => SourceChange.parse(obj))));
  }

  /// The error with which the fixes are associated.
  final AnalysisError error;

  /// The fixes associated with the error.
  final List<SourceChange> fixes;

  AnalysisErrorFixes(this.error, this.fixes);
}

@deprecated
class AnalysisOptions implements Jsonable {
  static AnalysisOptions parse(Map m) {
    return new AnalysisOptions(
        enableAsync: m['enableAsync'],
        enableDeferredLoading: m['enableDeferredLoading'],
        enableEnums: m['enableEnums'],
        enableNullAwareOperators: m['enableNullAwareOperators'],
        enableSuperMixins: m['enableSuperMixins'],
        generateDart2jsHints: m['generateDart2jsHints'],
        generateHints: m['generateHints'],
        generateLints: m['generateLints']);
  }

  /// **Deprecated:** this feature is always enabled.
  ///
  /// True if the client wants to enable support for the proposed async feature.
  @deprecated
  final bool? enableAsync;

  /// **Deprecated:** this feature is always enabled.
  ///
  /// True if the client wants to enable support for the proposed deferred
  /// loading feature.
  @deprecated
  final bool? enableDeferredLoading;

  /// **Deprecated:** this feature is always enabled.
  ///
  /// True if the client wants to enable support for the proposed enum feature.
  @deprecated
  final bool? enableEnums;

  /// **Deprecated:** this feature is always enabled.
  ///
  /// True if the client wants to enable support for the proposed "null aware
  /// operators" feature.
  @deprecated
  final bool? enableNullAwareOperators;

  /// True if the client wants to enable support for the proposed "less
  /// restricted mixins" proposal (DEP 34).
  final bool? enableSuperMixins;

  /// True if hints that are specific to dart2js should be generated. This
  /// option is ignored if generateHints is false.
  final bool? generateDart2jsHints;

  /// True if hints should be generated as part of generating errors and
  /// warnings.
  final bool? generateHints;

  /// True if lints should be generated as part of generating errors and
  /// warnings.
  final bool? generateLints;

  AnalysisOptions(
      {this.enableAsync,
      this.enableDeferredLoading,
      this.enableEnums,
      this.enableNullAwareOperators,
      this.enableSuperMixins,
      this.generateDart2jsHints,
      this.generateHints,
      this.generateLints});

  Map toMap() => _stripNullValues({
        'enableAsync': enableAsync,
        'enableDeferredLoading': enableDeferredLoading,
        'enableEnums': enableEnums,
        'enableNullAwareOperators': enableNullAwareOperators,
        'enableSuperMixins': enableSuperMixins,
        'generateDart2jsHints': generateDart2jsHints,
        'generateHints': generateHints,
        'generateLints': generateLints
      });
}

/// An indication of the current state of analysis.
class AnalysisStatus {
  static AnalysisStatus parse(Map m) {
    return new AnalysisStatus(m['isAnalyzing'],
        analysisTarget: m['analysisTarget']);
  }

  /// True if analysis is currently being performed.
  final bool isAnalyzing;

  /// The name of the current target of analysis. This field is omitted if
  /// analyzing is false.
  final String? analysisTarget;

  AnalysisStatus(this.isAnalyzing, {this.analysisTarget});

  String toString() => '[AnalysisStatus isAnalyzing: ${isAnalyzing}]';
}

/// A partial completion suggestion that can be used in combination with info
/// from `completion.results` to build completion suggestions for not yet
/// imported library tokens.
class AvailableSuggestion {
  static AvailableSuggestion parse(Map m) {
    return new AvailableSuggestion(
        m['label'], m['declaringLibraryUri'], Element.parse(m['element']),
        defaultArgumentListString: m['defaultArgumentListString'],
        defaultArgumentListTextRanges:
            m['defaultArgumentListTextRanges'] == null
                ? null
                : new List.from(m['defaultArgumentListTextRanges']),
        parameterNames: m['parameterNames'] == null
            ? null
            : new List.from(m['parameterNames']),
        parameterTypes: m['parameterTypes'] == null
            ? null
            : new List.from(m['parameterTypes']),
        relevanceTags: m['relevanceTags'] == null
            ? null
            : new List.from(m['relevanceTags']),
        requiredParameterCount: m['requiredParameterCount']);
  }

  /// The identifier to present to the user for code completion.
  final String label;

  /// The URI of the library that declares the element being suggested, not the
  /// URI of the library associated with the enclosing `AvailableSuggestionSet`.
  final String declaringLibraryUri;

  /// Information about the element reference being suggested.
  final Element element;

  /// A default String for use in generating argument list source contents on
  /// the client side.
  final String? defaultArgumentListString;

  /// Pairs of offsets and lengths describing 'defaultArgumentListString' text
  /// ranges suitable for use by clients to set up linked edits of default
  /// argument source contents. For example, given an argument list string 'x,
  /// y', the corresponding text range [0, 1, 3, 1], indicates two text ranges
  /// of length 1, starting at offsets 0 and 3. Clients can use these ranges to
  /// treat the 'x' and 'y' values specially for linked edits.
  final List<int>? defaultArgumentListTextRanges;

  /// If the element is an executable, the names of the formal parameters of all
  /// kinds - required, optional positional, and optional named. The names of
  /// positional parameters are empty strings. Omitted if the element is not an
  /// executable.
  final List<String>? parameterNames;

  /// If the element is an executable, the declared types of the formal
  /// parameters of all kinds - required, optional positional, and optional
  /// named. Omitted if the element is not an executable.
  final List<String>? parameterTypes;

  /// This field is set if the relevance of this suggestion might be changed
  /// depending on where completion is requested.
  final List<String>? relevanceTags;

  final int? requiredParameterCount;

  AvailableSuggestion(this.label, this.declaringLibraryUri, this.element,
      {this.defaultArgumentListString,
      this.defaultArgumentListTextRanges,
      this.parameterNames,
      this.parameterTypes,
      this.relevanceTags,
      this.requiredParameterCount});
}

class AvailableSuggestionSet {
  static AvailableSuggestionSet parse(Map m) {
    return new AvailableSuggestionSet(m['id'], m['uri'],
        new List.from(m['items'].map((obj) => AvailableSuggestion.parse(obj))));
  }

  /// The id associated with the library.
  final int id;

  /// The URI of the library.
  final String uri;

  final List<AvailableSuggestion> items;

  AvailableSuggestionSet(this.id, this.uri, this.items);
}

/// A description of bulk fixes to a library.
class BulkFix {
  static BulkFix parse(Map m) {
    return new BulkFix(m['path'],
        new List.from(m['fixes'].map((obj) => BulkFixDetail.parse(obj))));
  }

  /// The path of the library.
  final String path;

  /// A list of bulk fix details.
  final List<BulkFixDetail> fixes;

  BulkFix(this.path, this.fixes);
}

/// A description of a fix applied to a library.
class BulkFixDetail {
  static BulkFixDetail parse(Map m) {
    return new BulkFixDetail(m['code'], m['occurrences']);
  }

  /// The code of the diagnostic associated with the fix.
  final String code;

  /// The number times the associated diagnostic was fixed in the associated
  /// source edit.
  final int occurrences;

  BulkFixDetail(this.code, this.occurrences);
}

/// A directive to modify an existing file content overlay. One or more ranges
/// of text are deleted from the old file content overlay and replaced with new
/// text.
///
/// The edits are applied in the order in which they occur in the list. This
/// means that the offset of each edit must be correct under the assumption that
/// all previous edits have been applied.
///
/// It is an error to use this overlay on a file that does not yet have a file
/// content overlay or that has had its overlay removed via
/// (RemoveContentOverlay)[#type_RemoveContentOverlay].
///
/// If any of the edits cannot be applied due to its offset or length being out
/// of range, an `INVALID_OVERLAY_CHANGE` error will be reported.
class ChangeContentOverlay extends ContentOverlayType implements Jsonable {
  static ChangeContentOverlay parse(Map m) {
    return new ChangeContentOverlay(
        new List.from(m['edits'].map((obj) => SourceEdit.parse(obj))));
  }

  /// The edits to be applied to the file.
  final List<SourceEdit> edits;

  ChangeContentOverlay(this.edits) : super('change');

  Map toMap() => _stripNullValues({'type': type, 'edits': edits});
}

/// A label that is associated with a range of code that may be useful to render
/// at the end of the range to aid code readability. For example, a constructor
/// call that spans multiple lines may result in a closing label to allow the
/// constructor type/name to be rendered alongside the closing parenthesis.
class ClosingLabel {
  static ClosingLabel parse(Map m) {
    return new ClosingLabel(m['offset'], m['length'], m['label']);
  }

  /// The offset of the construct being labelled.
  final int offset;

  /// The length of the whole construct to be labelled.
  final int length;

  /// The label associated with this range that should be displayed to the user.
  final String label;

  ClosingLabel(this.offset, this.length, this.label);
}

/// A suggestion for how to complete partially entered text. Many of the fields
/// are optional, depending on the kind of element being suggested.
class CompletionSuggestion implements Jsonable {
  static CompletionSuggestion parse(Map m) {
    return new CompletionSuggestion(
        m['kind'],
        m['relevance'],
        m['completion'],
        m['selectionOffset'],
        m['selectionLength'],
        m['isDeprecated'],
        m['isPotential'],
        displayText: m['displayText'],
        docSummary: m['docSummary'],
        docComplete: m['docComplete'],
        declaringType: m['declaringType'],
        defaultArgumentListString: m['defaultArgumentListString'],
        defaultArgumentListTextRanges:
            m['defaultArgumentListTextRanges'] == null
                ? null
                : new List.from(m['defaultArgumentListTextRanges']),
        element: m['element'] == null ? null : Element.parse(m['element']),
        returnType: m['returnType'],
        parameterNames: m['parameterNames'] == null
            ? null
            : new List.from(m['parameterNames']),
        parameterTypes: m['parameterTypes'] == null
            ? null
            : new List.from(m['parameterTypes']),
        requiredParameterCount: m['requiredParameterCount'],
        hasNamedParameters: m['hasNamedParameters'],
        parameterName: m['parameterName'],
        parameterType: m['parameterType']);
  }

  /// The kind of element being suggested.
  final String kind;

  /// The relevance of this completion suggestion where a higher number
  /// indicates a higher relevance.
  final int relevance;

  /// The identifier to be inserted if the suggestion is selected. If the
  /// suggestion is for a method or function, the client might want to
  /// additionally insert a template for the parameters. The information
  /// required in order to do so is contained in other fields.
  final String completion;

  /// The offset, relative to the beginning of the completion, of where the
  /// selection should be placed after insertion.
  final int selectionOffset;

  /// The number of characters that should be selected after insertion.
  final int selectionLength;

  /// True if the suggested element is deprecated.
  final bool isDeprecated;

  /// True if the element is not known to be valid for the target. This happens
  /// if the type of the target is dynamic.
  final bool isPotential;

  /// Text to be displayed in, for example, a completion pop-up. This field is
  /// only defined if the displayed text should be different than the
  /// completion. Otherwise it is omitted.
  final String? displayText;

  /// An abbreviated version of the Dartdoc associated with the element being
  /// suggested. This field is omitted if there is no Dartdoc associated with
  /// the element.
  final String? docSummary;

  /// The Dartdoc associated with the element being suggested. This field is
  /// omitted if there is no Dartdoc associated with the element.
  final String? docComplete;

  /// The class that declares the element being suggested. This field is omitted
  /// if the suggested element is not a member of a class.
  final String? declaringType;

  /// A default String for use in generating argument list source contents on
  /// the client side.
  final String? defaultArgumentListString;

  /// Pairs of offsets and lengths describing 'defaultArgumentListString' text
  /// ranges suitable for use by clients to set up linked edits of default
  /// argument source contents. For example, given an argument list string 'x,
  /// y', the corresponding text range [0, 1, 3, 1], indicates two text ranges
  /// of length 1, starting at offsets 0 and 3. Clients can use these ranges to
  /// treat the 'x' and 'y' values specially for linked edits.
  final List<int>? defaultArgumentListTextRanges;

  /// Information about the element reference being suggested.
  final Element? element;

  /// The return type of the getter, function or method or the type of the field
  /// being suggested. This field is omitted if the suggested element is not a
  /// getter, function or method.
  final String? returnType;

  /// The names of the parameters of the function or method being suggested.
  /// This field is omitted if the suggested element is not a setter, function
  /// or method.
  final List<String>? parameterNames;

  /// The types of the parameters of the function or method being suggested.
  /// This field is omitted if the parameterNames field is omitted.
  final List<String>? parameterTypes;

  /// The number of required parameters for the function or method being
  /// suggested. This field is omitted if the parameterNames field is omitted.
  final int? requiredParameterCount;

  /// True if the function or method being suggested has at least one named
  /// parameter. This field is omitted if the parameterNames field is omitted.
  final bool? hasNamedParameters;

  /// The name of the optional parameter being suggested. This field is omitted
  /// if the suggestion is not the addition of an optional argument within an
  /// argument list.
  final String? parameterName;

  /// The type of the options parameter being suggested. This field is omitted
  /// if the parameterName field is omitted.
  final String? parameterType;

  CompletionSuggestion(
      this.kind,
      this.relevance,
      this.completion,
      this.selectionOffset,
      this.selectionLength,
      this.isDeprecated,
      this.isPotential,
      {this.displayText,
      this.docSummary,
      this.docComplete,
      this.declaringType,
      this.defaultArgumentListString,
      this.defaultArgumentListTextRanges,
      this.element,
      this.returnType,
      this.parameterNames,
      this.parameterTypes,
      this.requiredParameterCount,
      this.hasNamedParameters,
      this.parameterName,
      this.parameterType});

  Map toMap() => _stripNullValues({
        'kind': kind,
        'relevance': relevance,
        'completion': completion,
        'selectionOffset': selectionOffset,
        'selectionLength': selectionLength,
        'isDeprecated': isDeprecated,
        'isPotential': isPotential,
        'displayText': displayText,
        'docSummary': docSummary,
        'docComplete': docComplete,
        'declaringType': declaringType,
        'defaultArgumentListString': defaultArgumentListString,
        'defaultArgumentListTextRanges': defaultArgumentListTextRanges,
        'element': element?.toMap(),
        'returnType': returnType,
        'parameterNames': parameterNames,
        'parameterTypes': parameterTypes,
        'requiredParameterCount': requiredParameterCount,
        'hasNamedParameters': hasNamedParameters,
        'parameterName': parameterName,
        'parameterType': parameterType
      });

  String toString() =>
      '[CompletionSuggestion kind: ${kind}, relevance: ${relevance}, completion: ${completion}, selectionOffset: ${selectionOffset}, selectionLength: ${selectionLength}, isDeprecated: ${isDeprecated}, isPotential: ${isPotential}]';
}

/// Information about an analysis context.
class ContextData {
  static ContextData parse(Map m) {
    return new ContextData(
        m['name'],
        m['explicitFileCount'],
        m['implicitFileCount'],
        m['workItemQueueLength'],
        new List.from(m['cacheEntryExceptions']));
  }

  /// The name of the context.
  final String name;

  /// Explicitly analyzed files.
  final int explicitFileCount;

  /// Implicitly analyzed files.
  final int implicitFileCount;

  /// The number of work items in the queue.
  final int workItemQueueLength;

  /// Exceptions associated with cache entries.
  final List<String> cacheEntryExceptions;

  ContextData(this.name, this.explicitFileCount, this.implicitFileCount,
      this.workItemQueueLength, this.cacheEntryExceptions);
}

/// A "fix" that can be specified in an edit.dartfix request.
@experimental
class DartFix {
  static DartFix parse(Map m) {
    return new DartFix(m['name'], description: m['description']);
  }

  /// The name of the fix.
  final String name;

  /// A human readable description of the fix.
  final String? description;

  DartFix(this.name, {this.description});
}

/// A suggestion from an edit.dartfix request.
@experimental
class DartFixSuggestion {
  static DartFixSuggestion parse(Map m) {
    return new DartFixSuggestion(m['description'],
        location: m['location'] == null ? null : Location.parse(m['location']));
  }

  /// A human readable description of the suggested change.
  final String description;

  /// The location of the suggested change.
  final Location? location;

  DartFixSuggestion(this.description, {this.location});
}

/// A message associated with a diagnostic.
///
/// For example, if the diagnostic is reporting that a variable has been
/// referenced before it was declared, it might have a diagnostic message that
/// indicates where the variable is declared.
class DiagnosticMessage {
  static DiagnosticMessage parse(Map m) {
    return new DiagnosticMessage(m['message'], Location.parse(m['location']));
  }

  /// The message to be displayed to the user.
  final String message;

  /// The location associated with or referenced by the message. Clients should
  /// provide the ability to navigate to the location.
  final Location location;

  DiagnosticMessage(this.message, this.location);
}

/// Information about an element (something that can be declared in code).
class Element implements Jsonable {
  static Element parse(Map m) {
    return new Element(m['kind'], m['name'], m['flags'],
        location: m['location'] == null ? null : Location.parse(m['location']),
        parameters: m['parameters'],
        returnType: m['returnType'],
        typeParameters: m['typeParameters']);
  }

  /// The kind of the element.
  final String kind;

  /// The name of the element. This is typically used as the label in the
  /// outline.
  final String name;

  /// A bit-map containing the following flags:
  final int flags;

  /// The location of the name in the declaration of the element.
  final Location? location;

  /// The parameter list for the element. If the element is not a method or
  /// function this field will not be defined. If the element doesn't have
  /// parameters (e.g. getter), this field will not be defined. If the element
  /// has zero parameters, this field will have a value of "()".
  final String? parameters;

  /// The return type of the element. If the element is not a method or function
  /// this field will not be defined. If the element does not have a declared
  /// return type, this field will contain an empty string.
  final String? returnType;

  /// The type parameter list for the element. If the element doesn't have type
  /// parameters, this field will not be defined.
  final String? typeParameters;

  Element(this.kind, this.name, this.flags,
      {this.location, this.parameters, this.returnType, this.typeParameters});

  Map toMap() => _stripNullValues({
        'kind': kind,
        'name': name,
        'flags': flags,
        'location': location?.toMap(),
        'parameters': parameters,
        'returnType': returnType,
        'typeParameters': typeParameters
      });

  String toString() =>
      '[Element kind: ${kind}, name: ${name}, flags: ${flags}]';
}

/// A declaration - top-level (class, field, etc) or a class member (method,
/// field, etc).
class ElementDeclaration {
  static ElementDeclaration parse(Map m) {
    return new ElementDeclaration(m['name'], m['kind'], m['fileIndex'],
        m['offset'], m['line'], m['column'], m['codeOffset'], m['codeLength'],
        className: m['className'],
        mixinName: m['mixinName'],
        parameters: m['parameters']);
  }

  /// The name of the declaration.
  final String name;

  /// The kind of the element that corresponds to the declaration.
  final String kind;

  /// The index of the file (in the enclosing response).
  final int fileIndex;

  /// The offset of the declaration name in the file.
  final int offset;

  /// The one-based index of the line containing the declaration name.
  final int line;

  /// The one-based index of the column containing the declaration name.
  final int column;

  /// The offset of the first character of the declaration code in the file.
  final int codeOffset;

  /// The length of the declaration code in the file.
  final int codeLength;

  /// The name of the class enclosing this declaration. If the declaration is
  /// not a class member, this field will be absent.
  final String? className;

  /// The name of the mixin enclosing this declaration. If the declaration is
  /// not a mixin member, this field will be absent.
  final String? mixinName;

  /// The parameter list for the element. If the element is not a method or
  /// function this field will not be defined. If the element doesn't have
  /// parameters (e.g. getter), this field will not be defined. If the element
  /// has zero parameters, this field will have a value of "()". The value
  /// should not be treated as exact presentation of parameters, it is just
  /// approximation of parameters to give the user general idea.
  final String? parameters;

  ElementDeclaration(this.name, this.kind, this.fileIndex, this.offset,
      this.line, this.column, this.codeOffset, this.codeLength,
      {this.className, this.mixinName, this.parameters});
}

/// A description of an executable file.
class ExecutableFile {
  static ExecutableFile parse(Map m) {
    return new ExecutableFile(m['file'], m['kind']);
  }

  /// The path of the executable file.
  final String file;

  /// The kind of the executable file.
  final String kind;

  ExecutableFile(this.file, this.kind);
}

/// Information about an existing import, with elements that it provides.
class ExistingImport {
  static ExistingImport parse(Map m) {
    return new ExistingImport(m['uri'], new List.from(m['elements']));
  }

  /// The URI of the imported library. It is an index in the `strings` field, in
  /// the enclosing `ExistingImports` and its `ImportedElementSet` object.
  final int uri;

  /// The list of indexes of elements, in the enclosing `ExistingImports`
  /// object.
  final List<int> elements;

  ExistingImport(this.uri, this.elements);
}

/// Information about all existing imports in a library.
class ExistingImports {
  static ExistingImports parse(Map m) {
    return new ExistingImports(ImportedElementSet.parse(m['elements']),
        new List.from(m['imports'].map((obj) => ExistingImport.parse(obj))));
  }

  /// The set of all unique imported elements for all imports.
  final ImportedElementSet elements;

  /// The list of imports in the library.
  final List<ExistingImport> imports;

  ExistingImports(this.elements, this.imports);
}

/// An node in the Flutter specific outline structure of a file.
class FlutterOutline {
  static FlutterOutline parse(Map m) {
    return new FlutterOutline(
        m['kind'], m['offset'], m['length'], m['codeOffset'], m['codeLength'],
        label: m['label'],
        dartElement:
            m['dartElement'] == null ? null : Element.parse(m['dartElement']),
        attributes: m['attributes'] == null
            ? null
            : new List.from(m['attributes']
                .map((obj) => FlutterOutlineAttribute.parse(obj))),
        className: m['className'],
        parentAssociationLabel: m['parentAssociationLabel'],
        variableName: m['variableName'],
        children: m['children'] == null
            ? null
            : new List.from(
                m['children'].map((obj) => FlutterOutline.parse(obj))));
  }

  /// The kind of the node.
  final String kind;

  /// The offset of the first character of the element. This is different than
  /// the offset in the Element, which is the offset of the name of the element.
  /// It can be used, for example, to map locations in the file back to an
  /// outline.
  final int offset;

  /// The length of the element.
  final int length;

  /// The offset of the first character of the element code, which is neither
  /// documentation, nor annotation.
  final int codeOffset;

  /// The length of the element code.
  final int codeLength;

  /// The text label of the node children of the node. It is provided for any
  /// FlutterOutlineKind.GENERIC node, where better information is not
  /// available.
  final String? label;

  /// If this node is a Dart element, the description of it; omitted otherwise.
  final Element? dartElement;

  /// Additional attributes for this node, which might be interesting to display
  /// on the client. These attributes are usually arguments for the instance
  /// creation or the invocation that created the widget.
  final List<FlutterOutlineAttribute>? attributes;

  /// If the node creates a new class instance, or a reference to an instance,
  /// this field has the name of the class.
  final String? className;

  /// A short text description how this node is associated with the parent node.
  /// For example "appBar" or "body" in Scaffold.
  final String? parentAssociationLabel;

  /// If FlutterOutlineKind.VARIABLE, the name of the variable.
  final String? variableName;

  /// The children of the node. The field will be omitted if the node has no
  /// children.
  final List<FlutterOutline>? children;

  FlutterOutline(
      this.kind, this.offset, this.length, this.codeOffset, this.codeLength,
      {this.label,
      this.dartElement,
      this.attributes,
      this.className,
      this.parentAssociationLabel,
      this.variableName,
      this.children});
}

/// An attribute for a FlutterOutline.
class FlutterOutlineAttribute {
  static FlutterOutlineAttribute parse(Map m) {
    return new FlutterOutlineAttribute(m['name'], m['label'],
        literalValueBoolean: m['literalValueBoolean'],
        literalValueInteger: m['literalValueInteger'],
        literalValueString: m['literalValueString'],
        nameLocation: m['nameLocation'] == null
            ? null
            : Location.parse(m['nameLocation']),
        valueLocation: m['valueLocation'] == null
            ? null
            : Location.parse(m['valueLocation']));
  }

  /// The name of the attribute.
  final String name;

  /// The label of the attribute value, usually the Dart code. It might be quite
  /// long, the client should abbreviate as needed.
  final String label;

  /// The boolean literal value of the attribute. This field is absent if the
  /// value is not a boolean literal.
  final bool? literalValueBoolean;

  /// The integer literal value of the attribute. This field is absent if the
  /// value is not an integer literal.
  final int? literalValueInteger;

  /// The string literal value of the attribute. This field is absent if the
  /// value is not a string literal.
  final String? literalValueString;

  /// If the attribute is a named argument, the location of the name, without
  /// the colon.
  final Location? nameLocation;

  /// The location of the value.
  ///
  /// This field is always available, but marked optional for backward
  /// compatibility between new clients with older servers.
  final Location? valueLocation;

  FlutterOutlineAttribute(this.name, this.label,
      {this.literalValueBoolean,
      this.literalValueInteger,
      this.literalValueString,
      this.nameLocation,
      this.valueLocation});
}

/// A property of a Flutter widget.
class FlutterWidgetProperty {
  static FlutterWidgetProperty parse(Map m) {
    return new FlutterWidgetProperty(
        m['id'], m['isRequired'], m['isSafeToUpdate'], m['name'],
        documentation: m['documentation'],
        expression: m['expression'],
        children: m['children'] == null
            ? null
            : new List.from(
                m['children'].map((obj) => FlutterWidgetProperty.parse(obj))),
        editor: m['editor'] == null
            ? null
            : FlutterWidgetPropertyEditor.parse(m['editor']),
        value: m['value'] == null
            ? null
            : FlutterWidgetPropertyValue.parse(m['value']));
  }

  /// The unique identifier of the property, must be passed back to the server
  /// when updating the property value. Identifiers become invalid on any source
  /// code change.
  final int id;

  /// True if the property is required, e.g. because it corresponds to a
  /// required parameter of a constructor.
  final bool isRequired;

  /// If the property expression is a concrete value (e.g. a literal, or an enum
  /// constant), then it is safe to replace the expression with another concrete
  /// value. In this case this field is true. Otherwise, for example when the
  /// expression is a reference to a field, so that its value is provided from
  /// outside, this field is false.
  final bool isSafeToUpdate;

  /// The name of the property to display to the user.
  final String name;

  /// The documentation of the property to show to the user. Omitted if the
  /// server does not know the documentation, e.g. because the corresponding
  /// field is not documented.
  final String? documentation;

  /// If the value of this property is set, the Dart code of the expression of
  /// this property.
  final String? expression;

  /// The list of children properties, if any. For example any property of type
  /// `EdgeInsets` will have four children properties of type `double` - left /
  /// top / right / bottom.
  final List<FlutterWidgetProperty>? children;

  /// The editor that should be used by the client. This field is omitted if the
  /// server does not know the editor for this property, for example because it
  /// does not have one of the supported types.
  final FlutterWidgetPropertyEditor? editor;

  /// If the expression is set, and the server knows the value of the
  /// expression, this field is set.
  final FlutterWidgetPropertyValue? value;

  FlutterWidgetProperty(
      this.id, this.isRequired, this.isSafeToUpdate, this.name,
      {this.documentation,
      this.expression,
      this.children,
      this.editor,
      this.value});
}

/// An editor for a property of a Flutter widget.
class FlutterWidgetPropertyEditor {
  static FlutterWidgetPropertyEditor parse(Map m) {
    return new FlutterWidgetPropertyEditor(m['kind'],
        enumItems: m['enumItems'] == null
            ? null
            : new List.from(m['enumItems']
                .map((obj) => FlutterWidgetPropertyValueEnumItem.parse(obj))));
  }

  final String kind;

  final List<FlutterWidgetPropertyValueEnumItem>? enumItems;

  FlutterWidgetPropertyEditor(this.kind, {this.enumItems});
}

/// A value of a property of a Flutter widget.
class FlutterWidgetPropertyValue implements Jsonable {
  static FlutterWidgetPropertyValue parse(Map m) {
    return new FlutterWidgetPropertyValue(
        boolValue: m['boolValue'],
        doubleValue: m['doubleValue'],
        intValue: m['intValue'],
        stringValue: m['stringValue'],
        enumValue: m['enumValue'] == null
            ? null
            : FlutterWidgetPropertyValueEnumItem.parse(m['enumValue']),
        expression: m['expression']);
  }

  final bool? boolValue;

  final double? doubleValue;

  final int? intValue;

  final String? stringValue;

  final FlutterWidgetPropertyValueEnumItem? enumValue;

  /// A free-form expression, which will be used as the value as is.
  final String? expression;

  FlutterWidgetPropertyValue(
      {this.boolValue,
      this.doubleValue,
      this.intValue,
      this.stringValue,
      this.enumValue,
      this.expression});

  Map toMap() => _stripNullValues({
        'boolValue': boolValue,
        'doubleValue': doubleValue,
        'intValue': intValue,
        'stringValue': stringValue,
        'enumValue': enumValue,
        'expression': expression
      });
}

/// An item of an enumeration in a general sense - actual `enum` value, or a
/// static field in a class.
class FlutterWidgetPropertyValueEnumItem {
  static FlutterWidgetPropertyValueEnumItem parse(Map m) {
    return new FlutterWidgetPropertyValueEnumItem(
        m['libraryUri'], m['className'], m['name'],
        documentation: m['documentation']);
  }

  /// The URI of the library containing the `className`. When the enum item is
  /// passed back, this will allow the server to import the corresponding
  /// library if necessary.
  final String libraryUri;

  /// The name of the class or enum.
  final String className;

  /// The name of the field in the enumeration, or the static field in the
  /// class.
  final String name;

  /// The documentation to show to the user. Omitted if the server does not know
  /// the documentation, e.g. because the corresponding field is not documented.
  final String? documentation;

  FlutterWidgetPropertyValueEnumItem(this.libraryUri, this.className, this.name,
      {this.documentation});
}

/// A description of a region that can be folded.
class FoldingRegion {
  static FoldingRegion parse(Map m) {
    return new FoldingRegion(m['kind'], m['offset'], m['length']);
  }

  /// The kind of the region.
  final String kind;

  /// The offset of the region to be folded.
  final int offset;

  /// The length of the region to be folded.
  final int length;

  FoldingRegion(this.kind, this.offset, this.length);
}

/// A description of a region that could have special highlighting associated
/// with it.
class HighlightRegion {
  static HighlightRegion parse(Map m) {
    return new HighlightRegion(m['type'], m['offset'], m['length']);
  }

  /// The type of highlight associated with the region.
  final String type;

  /// The offset of the region to be highlighted.
  final int offset;

  /// The length of the region to be highlighted.
  final int length;

  HighlightRegion(this.type, this.offset, this.length);
}

/// The hover information associated with a specific location.
class HoverInformation {
  static HoverInformation parse(Map m) {
    return new HoverInformation(m['offset'], m['length'],
        containingLibraryPath: m['containingLibraryPath'],
        containingLibraryName: m['containingLibraryName'],
        containingClassDescription: m['containingClassDescription'],
        dartdoc: m['dartdoc'],
        elementDescription: m['elementDescription'],
        elementKind: m['elementKind'],
        isDeprecated: m['isDeprecated'],
        parameter: m['parameter'],
        propagatedType: m['propagatedType'],
        staticType: m['staticType']);
  }

  /// The offset of the range of characters that encompasses the cursor position
  /// and has the same hover information as the cursor position.
  final int offset;

  /// The length of the range of characters that encompasses the cursor position
  /// and has the same hover information as the cursor position.
  final int length;

  /// The path to the defining compilation unit of the library in which the
  /// referenced element is declared. This data is omitted if there is no
  /// referenced element, or if the element is declared inside an HTML file.
  final String? containingLibraryPath;

  /// The URI of the containing library, examples here include "dart:core",
  /// "package:.." and file uris represented by the path on disk, "/..". The
  /// data is omitted if the element is declared inside an HTML file.
  final String? containingLibraryName;

  /// A human-readable description of the class declaring the element being
  /// referenced. This data is omitted if there is no referenced element, or if
  /// the element is not a class member.
  final String? containingClassDescription;

  /// The dartdoc associated with the referenced element. Other than the removal
  /// of the comment delimiters, including leading asterisks in the case of a
  /// block comment, the dartdoc is unprocessed markdown. This data is omitted
  /// if there is no referenced element, or if the element has no dartdoc.
  final String? dartdoc;

  /// A human-readable description of the element being referenced. This data is
  /// omitted if there is no referenced element.
  final String? elementDescription;

  /// A human-readable description of the kind of element being referenced (such
  /// as "class" or "function type alias"). This data is omitted if there is no
  /// referenced element.
  final String? elementKind;

  /// True if the referenced element is deprecated.
  final bool? isDeprecated;

  /// A human-readable description of the parameter corresponding to the
  /// expression being hovered over. This data is omitted if the location is not
  /// in an argument to a function.
  final String? parameter;

  /// The name of the propagated type of the expression. This data is omitted if
  /// the location does not correspond to an expression or if there is no
  /// propagated type information.
  final String? propagatedType;

  /// The name of the static type of the expression. This data is omitted if the
  /// location does not correspond to an expression.
  final String? staticType;

  HoverInformation(this.offset, this.length,
      {this.containingLibraryPath,
      this.containingLibraryName,
      this.containingClassDescription,
      this.dartdoc,
      this.elementDescription,
      this.elementKind,
      this.isDeprecated,
      this.parameter,
      this.propagatedType,
      this.staticType});
}

/// A description of a class that is implemented or extended.
class ImplementedClass {
  static ImplementedClass parse(Map m) {
    return new ImplementedClass(m['offset'], m['length']);
  }

  /// The offset of the name of the implemented class.
  final int offset;

  /// The length of the name of the implemented class.
  final int length;

  ImplementedClass(this.offset, this.length);
}

/// A description of a class member that is implemented or overridden.
class ImplementedMember {
  static ImplementedMember parse(Map m) {
    return new ImplementedMember(m['offset'], m['length']);
  }

  /// The offset of the name of the implemented member.
  final int offset;

  /// The length of the name of the implemented member.
  final int length;

  ImplementedMember(this.offset, this.length);
}

/// The set of top-level elements encoded as pairs of the defining library URI
/// and the name, and stored in the parallel lists `elementUris` and
/// `elementNames`.
class ImportedElementSet {
  static ImportedElementSet parse(Map m) {
    return new ImportedElementSet(new List.from(m['strings']),
        new List.from(m['uris']), new List.from(m['names']));
  }

  /// The list of unique strings in this object.
  final List<String> strings;

  /// The library URI part of the element. It is an index in the `strings`
  /// field.
  final List<int> uris;

  /// The name part of a the element. It is an index in the `strings` field.
  final List<int> names;

  ImportedElementSet(this.strings, this.uris, this.names);
}

/// A description of the elements that are referenced in a region of a file that
/// come from a single imported library.
class ImportedElements implements Jsonable {
  static ImportedElements parse(Map m) {
    return new ImportedElements(
        m['path'], m['prefix'], new List.from(m['elements']));
  }

  /// The absolute and normalized path of the file containing the library.
  final String path;

  /// The prefix that was used when importing the library into the original
  /// source.
  final String prefix;

  /// The names of the elements imported from the library.
  final List<String> elements;

  ImportedElements(this.path, this.prefix, this.elements);

  Map toMap() =>
      _stripNullValues({'path': path, 'prefix': prefix, 'elements': elements});
}

/// Each `AvailableSuggestion` can specify zero or more tags in the field
/// `relevanceTags`, so that when the included tag is equal to one of the
/// `relevanceTags`, the suggestion is given higher relevance than the whole
/// `IncludedSuggestionSet`.
class IncludedSuggestionRelevanceTag {
  static IncludedSuggestionRelevanceTag parse(Map m) {
    return new IncludedSuggestionRelevanceTag(m['tag'], m['relevanceBoost']);
  }

  /// The opaque value of the tag.
  final String tag;

  /// The boost to the relevance of the completion suggestions that match this
  /// tag, which is added to the relevance of the containing
  /// `IncludedSuggestionSet`.
  final int relevanceBoost;

  IncludedSuggestionRelevanceTag(this.tag, this.relevanceBoost);
}

/// A reference to an `AvailableSuggestionSet` noting that the library's members
/// which match the kind of this ref should be presented to the user.
class IncludedSuggestionSet {
  static IncludedSuggestionSet parse(Map m) {
    return new IncludedSuggestionSet(m['id'], m['relevance'],
        displayUri: m['displayUri']);
  }

  /// Clients should use it to access the set of precomputed completions to be
  /// displayed to the user.
  final int id;

  /// The relevance of completion suggestions from this library where a higher
  /// number indicates a higher relevance.
  final int relevance;

  /// The optional string that should be displayed instead of the `uri` of the
  /// referenced `AvailableSuggestionSet`.
  ///
  /// For example libraries in the "test" directory of a package have only
  /// "file://" URIs, so are usually long, and don't look nice, but actual
  /// import directives will use relative URIs, which are short, so we probably
  /// want to display such relative URIs to the user.
  final String? displayUri;

  IncludedSuggestionSet(this.id, this.relevance, {this.displayUri});
}

/// This object matches the format and documentation of the Entry object
/// documented in the (Kythe Storage
/// Model)[https://kythe.io/docs/kythe-storage.html#_entry].
class KytheEntry {
  static KytheEntry parse(Map m) {
    return new KytheEntry(KytheVName.parse(m['source']), m['fact'],
        kind: m['kind'],
        target: m['target'] == null ? null : KytheVName.parse(m['target']),
        value: m['value'] == null ? null : new List.from(m['value']));
  }

  /// The ticket of the source node.
  final KytheVName source;

  /// A fact label. The schema defines which fact labels are meaningful.
  final String fact;

  /// An edge label. The schema defines which labels are meaningful.
  final String? kind;

  /// The ticket of the target node.
  final KytheVName? target;

  /// The `String` value of the fact.
  final List<int>? value;

  KytheEntry(this.source, this.fact, {this.kind, this.target, this.value});
}

/// This object matches the format and documentation of the Vector-Name object
/// documented in the (Kythe Storage
/// Model)[https://kythe.io/docs/kythe-storage.html#_a_id_termvname_a_vector_name_strong_vname_strong].
class KytheVName {
  static KytheVName parse(Map m) {
    return new KytheVName(
        m['signature'], m['corpus'], m['root'], m['path'], m['language']);
  }

  /// An opaque signature generated by the analyzer.
  final String signature;

  /// The corpus of source code this `KytheVName` belongs to. Loosely, a corpus
  /// is a collection of related files, such as the contents of a given source
  /// repository.
  final String corpus;

  /// A corpus-specific root label, typically a directory path or project
  /// identifier, denoting a distinct subset of the corpus. This may also be
  /// used to designate virtual collections like generated files.
  final String root;

  /// A path-structured label describing the “location” of the named object
  /// relative to the corpus and the root.
  final String path;

  /// The language this name belongs to.
  final String language;

  KytheVName(this.signature, this.corpus, this.root, this.path, this.language);
}

/// A list of associations between paths and the libraries that should be
/// included for code completion when editing a file beneath that path.
class LibraryPathSet implements Jsonable {
  static LibraryPathSet parse(Map m) {
    return new LibraryPathSet(m['scope'], new List.from(m['libraryPaths']));
  }

  /// The filepath for which this request's libraries should be active in
  /// completion suggestions. This object associates filesystem regions to
  /// libraries and library directories of interest to the client.
  final String scope;

  /// The paths of the libraries of interest to the client for completion
  /// suggestions.
  final List<String> libraryPaths;

  LibraryPathSet(this.scope, this.libraryPaths);

  Map toMap() =>
      _stripNullValues({'scope': scope, 'libraryPaths': libraryPaths});
}

/// A collection of positions that should be linked (edited simultaneously) for
/// the purposes of updating code after a source change. For example, if a set
/// of edits introduced a new variable name, the group would contain all of the
/// positions of the variable name so that if the client wanted to let the user
/// edit the variable name after the operation, all occurrences of the name
/// could be edited simultaneously.
class LinkedEditGroup {
  static LinkedEditGroup parse(Map m) {
    return new LinkedEditGroup(
        new List.from(m['positions'].map((obj) => Position.parse(obj))),
        m['length'],
        new List.from(
            m['suggestions'].map((obj) => LinkedEditSuggestion.parse(obj))));
  }

  /// The positions of the regions that should be edited simultaneously.
  final List<Position> positions;

  /// The length of the regions that should be edited simultaneously.
  final int length;

  /// Pre-computed suggestions for what every region might want to be changed
  /// to.
  final List<LinkedEditSuggestion> suggestions;

  LinkedEditGroup(this.positions, this.length, this.suggestions);

  String toString() =>
      '[LinkedEditGroup positions: ${positions}, length: ${length}, suggestions: ${suggestions}]';
}

/// A suggestion of a value that could be used to replace all of the linked edit
/// regions in a (LinkedEditGroup)[#type_LinkedEditGroup].
class LinkedEditSuggestion {
  static LinkedEditSuggestion parse(Map m) {
    return new LinkedEditSuggestion(m['value'], m['kind']);
  }

  /// The value that could be used to replace all of the linked edit regions.
  final String value;

  /// The kind of value being proposed.
  final String kind;

  LinkedEditSuggestion(this.value, this.kind);
}

/// A location (character range) within a file.
class Location implements Jsonable {
  static Location parse(Map m) {
    return new Location(
        m['file'], m['offset'], m['length'], m['startLine'], m['startColumn']);
  }

  /// The file containing the range.
  final String file;

  /// The offset of the range.
  final int offset;

  /// The length of the range.
  final int length;

  /// The one-based index of the line containing the first character of the
  /// range.
  final int startLine;

  /// The one-based index of the column containing the first character of the
  /// range.
  final int startColumn;

  Location(
      this.file, this.offset, this.length, this.startLine, this.startColumn);

  Map toMap() => _stripNullValues({
        'file': file,
        'offset': offset,
        'length': length,
        'startLine': startLine,
        'startColumn': startColumn
      });

  bool operator ==(o) =>
      o is Location &&
      file == o.file &&
      offset == o.offset &&
      length == o.length &&
      startLine == o.startLine &&
      startColumn == o.startColumn;

  int get hashCode =>
      file.hashCode ^
      offset.hashCode ^
      length.hashCode ^
      startLine.hashCode ^
      startColumn.hashCode;

  String toString() =>
      '[Location file: ${file}, offset: ${offset}, length: ${length}, startLine: ${startLine}, startColumn: ${startColumn}]';
}

/// A description of a region from which the user can navigate to the
/// declaration of an element.
class NavigationRegion {
  static NavigationRegion parse(Map m) {
    return new NavigationRegion(
        m['offset'], m['length'], new List.from(m['targets']));
  }

  /// The offset of the region from which the user can navigate.
  final int offset;

  /// The length of the region from which the user can navigate.
  final int length;

  /// The indexes of the targets (in the enclosing navigation response) to which
  /// the given region is bound. By opening the target, clients can implement
  /// one form of navigation. This list cannot be empty.
  final List<int> targets;

  NavigationRegion(this.offset, this.length, this.targets);

  String toString() =>
      '[NavigationRegion offset: ${offset}, length: ${length}, targets: ${targets}]';
}

/// A description of a target to which the user can navigate.
class NavigationTarget {
  static NavigationTarget parse(Map m) {
    return new NavigationTarget(m['kind'], m['fileIndex'], m['offset'],
        m['length'], m['startLine'], m['startColumn'],
        codeOffset: m['codeOffset'], codeLength: m['codeLength']);
  }

  /// The kind of the element.
  final String kind;

  /// The index of the file (in the enclosing navigation response) to navigate
  /// to.
  final int fileIndex;

  /// The offset of the name of the target to which the user can navigate.
  final int offset;

  /// The length of the name of the target to which the user can navigate.
  final int length;

  /// The one-based index of the line containing the first character of the name
  /// of the target.
  final int startLine;

  /// The one-based index of the column containing the first character of the
  /// name of the target.
  final int startColumn;

  /// The offset of the target code to which the user can navigate.
  final int? codeOffset;

  /// The length of the target code to which the user can navigate.
  final int? codeLength;

  NavigationTarget(this.kind, this.fileIndex, this.offset, this.length,
      this.startLine, this.startColumn,
      {this.codeOffset, this.codeLength});

  String toString() =>
      '[NavigationTarget kind: ${kind}, fileIndex: ${fileIndex}, offset: ${offset}, length: ${length}, startLine: ${startLine}, startColumn: ${startColumn}]';
}

/// A description of the references to a single element within a single file.
class Occurrences {
  static Occurrences parse(Map m) {
    return new Occurrences(
        Element.parse(m['element']), new List.from(m['offsets']), m['length']);
  }

  /// The element that was referenced.
  final Element element;

  /// The offsets of the name of the referenced element within the file.
  final List<int> offsets;

  /// The length of the name of the referenced element.
  final int length;

  Occurrences(this.element, this.offsets, this.length);
}

/// An node in the outline structure of a file.
class Outline {
  static Outline parse(Map m) {
    return new Outline(Element.parse(m['element']), m['offset'], m['length'],
        m['codeOffset'], m['codeLength'],
        children: m['children'] == null
            ? null
            : new List.from(m['children'].map((obj) => Outline.parse(obj))));
  }

  /// A description of the element represented by this node.
  final Element element;

  /// The offset of the first character of the element. This is different than
  /// the offset in the Element, which is the offset of the name of the element.
  /// It can be used, for example, to map locations in the file back to an
  /// outline.
  final int offset;

  /// The length of the element.
  final int length;

  /// The offset of the first character of the element code, which is neither
  /// documentation, nor annotation.
  final int codeOffset;

  /// The length of the element code.
  final int codeLength;

  /// The children of the node. The field will be omitted if the node has no
  /// children. Children are sorted by offset.
  final List<Outline>? children;

  Outline(
      this.element, this.offset, this.length, this.codeOffset, this.codeLength,
      {this.children});
}

/// A description of a member that is being overridden.
class OverriddenMember {
  static OverriddenMember parse(Map m) {
    return new OverriddenMember(Element.parse(m['element']), m['className']);
  }

  /// The element that is being overridden.
  final Element element;

  /// The name of the class in which the member is defined.
  final String className;

  OverriddenMember(this.element, this.className);
}

/// A description of a member that overrides an inherited member.
class Override {
  static Override parse(Map m) {
    return new Override(m['offset'], m['length'],
        superclassMember: m['superclassMember'] == null
            ? null
            : OverriddenMember.parse(m['superclassMember']),
        interfaceMembers: m['interfaceMembers'] == null
            ? null
            : new List.from(m['interfaceMembers']
                .map((obj) => OverriddenMember.parse(obj))));
  }

  /// The offset of the name of the overriding member.
  final int offset;

  /// The length of the name of the overriding member.
  final int length;

  /// The member inherited from a superclass that is overridden by the
  /// overriding member. The field is omitted if there is no superclass member,
  /// in which case there must be at least one interface member.
  final OverriddenMember? superclassMember;

  /// The members inherited from interfaces that are overridden by the
  /// overriding member. The field is omitted if there are no interface members,
  /// in which case there must be a superclass member.
  final List<OverriddenMember>? interfaceMembers;

  Override(this.offset, this.length,
      {this.superclassMember, this.interfaceMembers});
}

/// A description of a member that is being overridden.
@experimental
class ParameterInfo {
  static ParameterInfo parse(Map m) {
    return new ParameterInfo(m['kind'], m['name'], m['type'],
        defaultValue: m['defaultValue']);
  }

  /// The kind of the parameter.
  final String kind;

  /// The name of the parameter.
  final String name;

  /// The type of the parameter.
  final String type;

  /// The default value for this parameter. This value will be omitted if the
  /// parameter does not have a default value.
  final String? defaultValue;

  ParameterInfo(this.kind, this.name, this.type, {this.defaultValue});
}

/// A position within a file.
class Position {
  static Position parse(Map m) {
    return new Position(m['file'], m['offset']);
  }

  /// The file containing the position.
  final String file;

  /// The offset of the position.
  final int offset;

  Position(this.file, this.offset);

  String toString() => '[Position file: ${file}, offset: ${offset}]';
}

/// The description of a postfix completion template.
class PostfixTemplateDescriptor {
  static PostfixTemplateDescriptor parse(Map m) {
    return new PostfixTemplateDescriptor(m['name'], m['key'], m['example']);
  }

  /// The template name, shown in the UI.
  final String name;

  /// The unique template key, not shown in the UI.
  final String key;

  /// A short example of the transformation performed when the template is
  /// applied.
  final String example;

  PostfixTemplateDescriptor(this.name, this.key, this.example);
}

/// An indication of the current state of pub execution.
class PubStatus {
  static PubStatus parse(Map m) {
    return new PubStatus(m['isListingPackageDirs']);
  }

  /// True if the server is currently running pub to produce a list of package
  /// directories.
  final bool isListingPackageDirs;

  PubStatus(this.isListingPackageDirs);

  String toString() =>
      '[PubStatus isListingPackageDirs: ${isListingPackageDirs}]';
}

/// A description of a parameter in a method refactoring.
class RefactoringMethodParameter {
  static RefactoringMethodParameter parse(Map m) {
    return new RefactoringMethodParameter(m['kind'], m['type'], m['name'],
        id: m['id'], parameters: m['parameters']);
  }

  /// The kind of the parameter.
  final String kind;

  /// The type that should be given to the parameter, or the return type of the
  /// parameter's function type.
  final String type;

  /// The name that should be given to the parameter.
  final String name;

  /// The unique identifier of the parameter. Clients may omit this field for
  /// the parameters they want to add.
  final String? id;

  /// The parameter list of the parameter's function type. If the parameter is
  /// not of a function type, this field will not be defined. If the function
  /// type has zero parameters, this field will have a value of '()'.
  final String? parameters;

  RefactoringMethodParameter(this.kind, this.type, this.name,
      {this.id, this.parameters});
}

/// A description of a problem related to a refactoring.
class RefactoringProblem {
  static RefactoringProblem parse(Map m) {
    return new RefactoringProblem(m['severity'], m['message'],
        location: m['location'] == null ? null : Location.parse(m['location']));
  }

  /// The severity of the problem being represented.
  final String severity;

  /// A human-readable description of the problem being represented.
  final String message;

  /// The location of the problem being represented. This field is omitted
  /// unless there is a specific location associated with the problem (such as a
  /// location where an element being renamed will be shadowed).
  final Location? location;

  RefactoringProblem(this.severity, this.message, {this.location});
}

/// A directive to remove an existing file content overlay. After processing
/// this directive, the file contents will once again be read from the file
/// system.
///
/// If this directive is used on a file that doesn't currently have a content
/// overlay, it has no effect.
class RemoveContentOverlay extends ContentOverlayType implements Jsonable {
  static RemoveContentOverlay parse(Map m) {
    return new RemoveContentOverlay();
  }

  RemoveContentOverlay() : super('remove');

  Map toMap() => _stripNullValues({'type': type});
}

/// An expression for which we want to know its runtime type. In expressions
/// like 'a.b.c.where((e) => e.^)' we want to know the runtime type of 'a.b.c'
/// to enforce it statically at the time when we compute completion suggestions,
/// and get better type for 'e'.
class RuntimeCompletionExpression implements Jsonable {
  static RuntimeCompletionExpression parse(Map m) {
    return new RuntimeCompletionExpression(m['offset'], m['length'],
        type: m['type'] == null
            ? null
            : RuntimeCompletionExpressionType.parse(m['type']));
  }

  /// The offset of the expression in the code for completion.
  final int offset;

  /// The length of the expression in the code for completion.
  final int length;

  /// When the expression is sent from the server to the client, the type is
  /// omitted. The client should fill the type when it sends the request to the
  /// server again.
  final RuntimeCompletionExpressionType? type;

  RuntimeCompletionExpression(this.offset, this.length, {this.type});

  Map toMap() =>
      _stripNullValues({'offset': offset, 'length': length, 'type': type});
}

/// A type at runtime.
class RuntimeCompletionExpressionType {
  static RuntimeCompletionExpressionType parse(Map m) {
    return new RuntimeCompletionExpressionType(m['kind'],
        libraryPath: m['libraryPath'],
        name: m['name'],
        typeArguments: m['typeArguments'] == null
            ? null
            : new List.from(m['typeArguments']
                .map((obj) => RuntimeCompletionExpressionType.parse(obj))),
        returnType: m['returnType'] == null
            ? null
            : RuntimeCompletionExpressionType.parse(m['returnType']),
        parameterTypes: m['parameterTypes'] == null
            ? null
            : new List.from(m['parameterTypes']
                .map((obj) => RuntimeCompletionExpressionType.parse(obj))),
        parameterNames: m['parameterNames'] == null
            ? null
            : new List.from(m['parameterNames']));
  }

  /// The kind of the type.
  final String kind;

  /// The path of the library that has this type. Omitted if the type is not
  /// declared in any library, e.g. "dynamic", or "void".
  final String? libraryPath;

  /// The name of the type. Omitted if the type does not have a name, e.g. an
  /// inline function type.
  final String? name;

  /// The type arguments of the type. Omitted if the type does not have type
  /// parameters.
  final List<RuntimeCompletionExpressionType>? typeArguments;

  /// If the type is a function type, the return type of the function. Omitted
  /// if the type is not a function type.
  final RuntimeCompletionExpressionType? returnType;

  /// If the type is a function type, the types of the function parameters of
  /// all kinds - required, optional positional, and optional named. Omitted if
  /// the type is not a function type.
  final List<RuntimeCompletionExpressionType>? parameterTypes;

  /// If the type is a function type, the names of the function parameters of
  /// all kinds - required, optional positional, and optional named. The names
  /// of positional parameters are empty strings. Omitted if the type is not a
  /// function type.
  final List<String>? parameterNames;

  RuntimeCompletionExpressionType(this.kind,
      {this.libraryPath,
      this.name,
      this.typeArguments,
      this.returnType,
      this.parameterTypes,
      this.parameterNames});
}

/// A variable in a runtime context.
class RuntimeCompletionVariable implements Jsonable {
  static RuntimeCompletionVariable parse(Map m) {
    return new RuntimeCompletionVariable(
        m['name'], RuntimeCompletionExpressionType.parse(m['type']));
  }

  /// The name of the variable. The name "this" has a special meaning and is
  /// used as an implicit target for runtime completion, and in explicit "this"
  /// references.
  final String name;

  /// The type of the variable.
  final RuntimeCompletionExpressionType type;

  RuntimeCompletionVariable(this.name, this.type);

  Map toMap() => _stripNullValues({'name': name, 'type': type});
}

/// A single result from a search request.
class SearchResult {
  static SearchResult parse(Map m) {
    return new SearchResult(
        Location.parse(m['location']),
        m['kind'],
        m['isPotential'],
        new List.from(m['path'].map((obj) => Element.parse(obj))));
  }

  /// The location of the code that matched the search criteria.
  final Location location;

  /// The kind of element that was found or the kind of reference that was
  /// found.
  final String kind;

  /// True if the result is a potential match but cannot be confirmed to be a
  /// match. For example, if all references to a method m defined in some class
  /// were requested, and a reference to a method m from an unknown class were
  /// found, it would be marked as being a potential match.
  final bool isPotential;

  /// The elements that contain the result, starting with the most immediately
  /// enclosing ancestor and ending with the library.
  final List<Element> path;

  SearchResult(this.location, this.kind, this.isPotential, this.path);

  String toString() =>
      '[SearchResult location: ${location}, kind: ${kind}, isPotential: ${isPotential}, path: ${path}]';
}

/// A log entry from the server.
@experimental
class ServerLogEntry {
  static ServerLogEntry parse(Map m) {
    return new ServerLogEntry(m['time'], m['kind'], m['data']);
  }

  /// The time (milliseconds since epoch) at which the server created this log
  /// entry.
  final int time;

  /// The kind of the entry, used to determine how to interpret the "data"
  /// field.
  final String kind;

  /// The payload of the entry, the actual format is determined by the "kind"
  /// field.
  final String data;

  ServerLogEntry(this.time, this.kind, this.data);
}

/// A description of a set of edits that implement a single conceptual change.
class SourceChange {
  static SourceChange parse(Map m) {
    return new SourceChange(
        m['message'],
        new List.from(m['edits'].map((obj) => SourceFileEdit.parse(obj))),
        new List.from(
            m['linkedEditGroups'].map((obj) => LinkedEditGroup.parse(obj))),
        selection:
            m['selection'] == null ? null : Position.parse(m['selection']),
        id: m['id']);
  }

  /// A human-readable description of the change to be applied.
  final String message;

  /// A list of the edits used to effect the change, grouped by file.
  final List<SourceFileEdit> edits;

  /// A list of the linked editing groups used to customize the changes that
  /// were made.
  final List<LinkedEditGroup> linkedEditGroups;

  /// The position that should be selected after the edits have been applied.
  final Position? selection;

  /// The optional identifier of the change kind. The identifier remains stable
  /// even if the message changes, or is parameterized.
  final String? id;

  SourceChange(this.message, this.edits, this.linkedEditGroups,
      {this.selection, this.id});

  String toString() =>
      '[SourceChange message: ${message}, edits: ${edits}, linkedEditGroups: ${linkedEditGroups}]';
}

/// A description of a single change to a single file.
class SourceEdit implements Jsonable {
  static SourceEdit parse(Map m) {
    return new SourceEdit(m['offset'], m['length'], m['replacement'],
        id: m['id']);
  }

  /// The offset of the region to be modified.
  final int offset;

  /// The length of the region to be modified.
  final int length;

  /// The code that is to replace the specified region in the original code.
  final String replacement;

  /// An identifier that uniquely identifies this source edit from other edits
  /// in the same response. This field is omitted unless a containing structure
  /// needs to be able to identify the edit for some reason.
  ///
  /// For example, some refactoring operations can produce edits that might not
  /// be appropriate (referred to as potential edits). Such edits will have an
  /// id so that they can be referenced. Edits in the same response that do not
  /// need to be referenced will not have an id.
  final String? id;

  SourceEdit(this.offset, this.length, this.replacement, {this.id});

  Map toMap() => _stripNullValues({
        'offset': offset,
        'length': length,
        'replacement': replacement,
        'id': id
      });

  String toString() =>
      '[SourceEdit offset: ${offset}, length: ${length}, replacement: ${replacement}]';
}

/// A description of a set of changes to a single file.
class SourceFileEdit {
  static SourceFileEdit parse(Map m) {
    return new SourceFileEdit(m['file'], m['fileStamp'],
        new List.from(m['edits'].map((obj) => SourceEdit.parse(obj))));
  }

  /// The file containing the code to be modified.
  final String file;

  /// The modification stamp of the file at the moment when the change was
  /// created, in milliseconds since the "Unix epoch". Will be -1 if the file
  /// did not exist and should be created. The client may use this field to make
  /// sure that the file was not changed since then, so it is safe to apply the
  /// change.
  @deprecated
  final int fileStamp;

  /// A list of the edits used to effect the change.
  final List<SourceEdit> edits;

  SourceFileEdit(this.file, this.fileStamp, this.edits);

  String toString() => '[SourceFileEdit file: ${file}, edits: ${edits}]';
}

/// A scanned token along with its inferred type information.
@experimental
class TokenDetails {
  static TokenDetails parse(Map m) {
    return new TokenDetails(m['lexeme'], m['offset'],
        type: m['type'],
        validElementKinds: m['validElementKinds'] == null
            ? null
            : new List.from(m['validElementKinds']));
  }

  /// The token's lexeme.
  final String lexeme;

  /// The offset of the first character of the token in the file which it
  /// originated from.
  final int offset;

  /// A unique id for the type of the identifier. Omitted if the token is not an
  /// identifier in a reference position.
  final String? type;

  /// An indication of whether this token is in a declaration or reference
  /// position. (If no other purpose is found for this field then it should be
  /// renamed and converted to a boolean value.) Omitted if the token is not an
  /// identifier.
  final List<String>? validElementKinds;

  TokenDetails(this.lexeme, this.offset, {this.type, this.validElementKinds});
}

/// A representation of a class in a type hierarchy.
class TypeHierarchyItem {
  static TypeHierarchyItem parse(Map m) {
    return new TypeHierarchyItem(
        Element.parse(m['classElement']),
        new List.from(m['interfaces']),
        new List.from(m['mixins']),
        new List.from(m['subclasses']),
        displayName: m['displayName'],
        memberElement: m['memberElement'] == null
            ? null
            : Element.parse(m['memberElement']),
        superclass: m['superclass']);
  }

  /// The class element represented by this item.
  final Element classElement;

  /// The indexes of the items representing the interfaces implemented by this
  /// class. The list will be empty if there are no implemented interfaces.
  final List<int> interfaces;

  /// The indexes of the items representing the mixins referenced by this class.
  /// The list will be empty if there are no classes mixed in to this class.
  final List<int> mixins;

  /// The indexes of the items representing the subtypes of this class. The list
  /// will be empty if there are no subtypes or if this item represents a
  /// supertype of the pivot type.
  final List<int> subclasses;

  /// The name to be displayed for the class. This field will be omitted if the
  /// display name is the same as the name of the element. The display name is
  /// different if there is additional type information to be displayed, such as
  /// type arguments.
  final String? displayName;

  /// The member in the class corresponding to the member on which the hierarchy
  /// was requested. This field will be omitted if the hierarchy was not
  /// requested for a member or if the class does not have a corresponding
  /// member.
  final Element? memberElement;

  /// The index of the item representing the superclass of this class. This
  /// field will be omitted if this item represents the class Object.
  final int? superclass;

  TypeHierarchyItem(
      this.classElement, this.interfaces, this.mixins, this.subclasses,
      {this.displayName, this.memberElement, this.superclass});
}

// refactorings

class Refactorings {
  static const String CONVERT_GETTER_TO_METHOD = 'CONVERT_GETTER_TO_METHOD';
  static const String CONVERT_METHOD_TO_GETTER = 'CONVERT_METHOD_TO_GETTER';
  static const String EXTRACT_LOCAL_VARIABLE = 'EXTRACT_LOCAL_VARIABLE';
  static const String EXTRACT_METHOD = 'EXTRACT_METHOD';
  static const String EXTRACT_WIDGET = 'EXTRACT_WIDGET';
  static const String INLINE_LOCAL_VARIABLE = 'INLINE_LOCAL_VARIABLE';
  static const String INLINE_METHOD = 'INLINE_METHOD';
  static const String MOVE_FILE = 'MOVE_FILE';
  static const String RENAME = 'RENAME';
}

/// Create a local variable initialized by the expression that covers the
/// specified selection.
///
/// It is an error if the selection range is not covered by a complete
/// expression.
class ExtractLocalVariableRefactoringOptions extends RefactoringOptions {
  /// The name that the local variable should be given.
  final String? name;

  /// True if all occurrences of the expression within the scope in which the
  /// variable will be defined should be replaced by a reference to the local
  /// variable. The expression used to initiate the refactoring will always be
  /// replaced.
  final bool? extractAll;

  ExtractLocalVariableRefactoringOptions({this.name, this.extractAll});

  Map toMap() => _stripNullValues({'name': name, 'extractAll': extractAll});
}

/// Create a method whose body is the specified expression or list of
/// statements, possibly augmented with a return statement.
///
/// It is an error if the range contains anything other than a complete
/// expression (no partial expressions are allowed) or a complete sequence of
/// statements.
class ExtractMethodRefactoringOptions extends RefactoringOptions {
  /// The return type that should be defined for the method.
  final String? returnType;

  /// True if a getter should be created rather than a method. It is an error if
  /// this field is true and the list of parameters is non-empty.
  final bool? createGetter;

  /// The name that the method should be given.
  final String? name;

  /// The parameters that should be defined for the method.
  ///
  /// It is an error if a REQUIRED or NAMED parameter follows a POSITIONAL
  /// parameter. It is an error if a REQUIRED or POSITIONAL parameter follows a
  /// NAMED parameter.
  final List<RefactoringMethodParameter>? parameters;

  /// True if all occurrences of the expression or statements should be replaced
  /// by an invocation of the method. The expression or statements used to
  /// initiate the refactoring will always be replaced.
  final bool? extractAll;

  ExtractMethodRefactoringOptions(
      {this.returnType,
      this.createGetter,
      this.name,
      this.parameters,
      this.extractAll});

  Map toMap() => _stripNullValues({
        'returnType': returnType,
        'createGetter': createGetter,
        'name': name,
        'parameters': parameters,
        'extractAll': extractAll
      });
}

/// Create a new class that extends StatelessWidget, whose build() method is the
/// widget creation expression, or a method returning a Flutter widget, at the
/// specified offset.
class ExtractWidgetRefactoringOptions extends RefactoringOptions {
  /// The name that the widget class should be given.
  final String? name;

  ExtractWidgetRefactoringOptions({this.name});

  Map toMap() => _stripNullValues({'name': name});
}

/// Inline a method in place of one or all references to that method.
///
/// It is an error if the range contains anything other than all or part of the
/// name of a single method.
class InlineMethodRefactoringOptions extends RefactoringOptions {
  /// True if the method being inlined should be removed. It is an error if this
  /// field is true and inlineAll is false.
  final bool? deleteSource;

  /// True if all invocations of the method should be inlined, or false if only
  /// the invocation site used to create this refactoring should be inlined.
  final bool? inlineAll;

  InlineMethodRefactoringOptions({this.deleteSource, this.inlineAll});

  Map toMap() =>
      _stripNullValues({'deleteSource': deleteSource, 'inlineAll': inlineAll});
}

/// Move the given file and update all of the references to that file and from
/// it. The move operation is supported in general case - for renaming a file in
/// the same folder, moving it to a different folder or both.
///
/// The refactoring must be activated before an actual file moving operation is
/// performed.
///
/// The "offset" and "length" fields from the request are ignored, but the file
/// specified in the request specifies the file to be moved.
class MoveFileRefactoringOptions extends RefactoringOptions {
  /// The new file path to which the given file is being moved.
  final String? newFile;

  MoveFileRefactoringOptions({this.newFile});

  Map toMap() => _stripNullValues({'newFile': newFile});
}

/// Rename a given element and all of the references to that element.
///
/// It is an error if the range contains anything other than all or part of the
/// name of a single function (including methods, getters and setters), variable
/// (including fields, parameters and local variables), class or function type.
class RenameRefactoringOptions extends RefactoringOptions {
  /// The name that the element should have after the refactoring.
  final String? newName;

  RenameRefactoringOptions({this.newName});

  Map toMap() => _stripNullValues({'newName': newName});
}

abstract class RefactoringFeedback {
  static RefactoringFeedback? parse(String? kind, Map m) {
    switch (kind) {
      case Refactorings.EXTRACT_LOCAL_VARIABLE:
        return ExtractLocalVariableFeedback.parse(m);
      case Refactorings.EXTRACT_METHOD:
        return ExtractMethodFeedback.parse(m);
      case Refactorings.INLINE_LOCAL_VARIABLE:
        return InlineLocalVariableFeedback.parse(m);
      case Refactorings.INLINE_METHOD:
        return InlineMethodFeedback.parse(m);
      case Refactorings.RENAME:
        return RenameFeedback.parse(m);
    }

    return null;
  }
}

/// Feedback class for the `EXTRACT_LOCAL_VARIABLE` refactoring.
class ExtractLocalVariableFeedback extends RefactoringFeedback {
  static ExtractLocalVariableFeedback parse(Map m) =>
      new ExtractLocalVariableFeedback(new List.from(m['names']),
          new List.from(m['offsets']), new List.from(m['lengths']),
          coveringExpressionOffsets: m['coveringExpressionOffsets'] == null
              ? null
              : new List.from(m['coveringExpressionOffsets']),
          coveringExpressionLengths: m['coveringExpressionLengths'] == null
              ? null
              : new List.from(m['coveringExpressionLengths']));

  /// The proposed names for the local variable.
  final List<String> names;

  /// The offsets of the expressions that would be replaced by a reference to
  /// the variable.
  final List<int> offsets;

  /// The lengths of the expressions that would be replaced by a reference to
  /// the variable. The lengths correspond to the offsets. In other words, for a
  /// given expression, if the offset of that expression is `offsets[i]`, then
  /// the length of that expression is `lengths[i]`.
  final List<int> lengths;

  /// The offsets of the expressions that cover the specified selection, from
  /// the down most to the up most.
  final List<int>? coveringExpressionOffsets;

  /// The lengths of the expressions that cover the specified selection, from
  /// the down most to the up most.
  final List<int>? coveringExpressionLengths;

  ExtractLocalVariableFeedback(this.names, this.offsets, this.lengths,
      {this.coveringExpressionOffsets, this.coveringExpressionLengths});
}

/// Feedback class for the `EXTRACT_METHOD` refactoring.
class ExtractMethodFeedback extends RefactoringFeedback {
  static ExtractMethodFeedback parse(Map m) => new ExtractMethodFeedback(
      m['offset'],
      m['length'],
      m['returnType'],
      new List.from(m['names']),
      m['canCreateGetter'],
      new List.from(
          m['parameters'].map((obj) => RefactoringMethodParameter.parse(obj))),
      new List.from(m['offsets']),
      new List.from(m['lengths']));

  /// The offset to the beginning of the expression or statements that will be
  /// extracted.
  final int offset;

  /// The length of the expression or statements that will be extracted.
  final int length;

  /// The proposed return type for the method. If the returned element does not
  /// have a declared return type, this field will contain an empty string.
  final String returnType;

  /// The proposed names for the method.
  final List<String> names;

  /// True if a getter could be created rather than a method.
  final bool canCreateGetter;

  /// The proposed parameters for the method.
  final List<RefactoringMethodParameter> parameters;

  /// The offsets of the expressions or statements that would be replaced by an
  /// invocation of the method.
  final List<int> offsets;

  /// The lengths of the expressions or statements that would be replaced by an
  /// invocation of the method. The lengths correspond to the offsets. In other
  /// words, for a given expression (or block of statements), if the offset of
  /// that expression is `offsets[i]`, then the length of that expression is
  /// `lengths[i]`.
  final List<int> lengths;

  ExtractMethodFeedback(this.offset, this.length, this.returnType, this.names,
      this.canCreateGetter, this.parameters, this.offsets, this.lengths);
}

/// Feedback class for the `INLINE_LOCAL_VARIABLE` refactoring.
class InlineLocalVariableFeedback extends RefactoringFeedback {
  static InlineLocalVariableFeedback parse(Map m) =>
      new InlineLocalVariableFeedback(m['name'], m['occurrences']);

  /// The name of the variable being inlined.
  final String name;

  /// The number of times the variable occurs.
  final int occurrences;

  InlineLocalVariableFeedback(this.name, this.occurrences);
}

/// Feedback class for the `INLINE_METHOD` refactoring.
class InlineMethodFeedback extends RefactoringFeedback {
  static InlineMethodFeedback parse(Map m) =>
      new InlineMethodFeedback(m['methodName'], m['isDeclaration'],
          className: m['className']);

  /// The name of the method (or function) being inlined.
  final String methodName;

  /// True if the declaration of the method is selected. So all references
  /// should be inlined.
  final bool isDeclaration;

  /// The name of the class enclosing the method being inlined. If not a class
  /// member is being inlined, this field will be absent.
  final String? className;

  InlineMethodFeedback(this.methodName, this.isDeclaration, {this.className});
}

/// Feedback class for the `RENAME` refactoring.
class RenameFeedback extends RefactoringFeedback {
  static RenameFeedback parse(Map m) => new RenameFeedback(
      m['offset'], m['length'], m['elementKindName'], m['oldName']);

  /// The offset to the beginning of the name selected to be renamed, or -1 if
  /// the name does not exist yet.
  final int offset;

  /// The length of the name selected to be renamed.
  final int length;

  /// The human-readable description of the kind of element being renamed (such
  /// as "class" or "function type alias").
  final String elementKindName;

  /// The old name of the element before the refactoring.
  final String oldName;

  RenameFeedback(this.offset, this.length, this.elementKindName, this.oldName);
}
