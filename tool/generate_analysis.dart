// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:collection' show LinkedHashMap;
import 'dart:io';

import 'package:html/dom.dart';
import 'package:html/dom_parsing.dart' show TreeVisitor;
import 'package:html/parser.dart' show parse;

import 'src/src_gen.dart';

late Api api;

void main(List<String> args) {
  // Parse spec_input.html into a model.
  File file = File('tool/spec_input.html');
  Document document = parse(file.readAsStringSync());
  print('Parsed ${file.path}.');
  Element body = document.body!;
  Element ver = body.querySelector('version')!;
  List<Element> domains = body.getElementsByTagName('domain');
  List<Element> typedefs =
      body.getElementsByTagName('types').first.getElementsByTagName('type');
  List<Element> refactorings = body
      .getElementsByTagName('refactorings')
      .first
      .getElementsByTagName('refactoring');

  // Common common_types_spec.html.
  File commonTypesFile = File('tool/common_types_spec.html');
  Document commonTypesDoc = parse(commonTypesFile.readAsStringSync());
  print('Parsed ${commonTypesFile.path}.');
  List<Element> commonTypedefs = commonTypesDoc.body!
      .getElementsByTagName('types')
      .first
      .getElementsByTagName('type');

  List<Element> combinedTypeDefs = [...typedefs, ...commonTypedefs];
  combinedTypeDefs.sort((Element a, Element b) {
    return a.attributes['name']!.compareTo(b.attributes['name']!);
  });

  api = Api(ver.text);
  api.parse(domains, combinedTypeDefs, refactorings);

  // Generate code from the model.
  File outputFile = File('lib/analysis_server_lib.dart');
  DartGenerator generator = DartGenerator();
  api.generate(generator);
  outputFile.writeAsStringSync(generator.toString());
  var dartFmtResult =
      Process.runSync(Platform.executable, ['format', outputFile.path]);
  if (dartFmtResult.exitCode != 0) {
    throw Exception(dartFmtResult.stderr);
  }
  print('Wrote ${outputFile.path}.');
}

class Api {
  final String version;

  late List<Domain> domains;
  late List<TypeDef> typedefs;
  late List<Refactoring> refactorings;

  Api(this.version);

  void parse(List<Element> domainElements, List<Element> typeElements,
      List<Element> refactoringElements) {
    typedefs = List.from(typeElements.map((element) => TypeDef(element)));
    domains = List.from(domainElements.map((element) => Domain(element)));
    refactorings = List.from(refactoringElements.map((e) => Refactoring(e)));

    // Mark some types as jsonable - we can send them back over the wire.
    findRef('SourceEdit').setCallParam();
    findRef('CompletionSuggestion').setCallParam();
    findRef('Element').setCallParam();
    findRef('Location').setCallParam();
    typedefs
        .where((def) => def.name.endsWith('ContentOverlay'))
        .forEach((def) => def.setCallParam());
  }

  TypeDef findRef(String name) =>
      typedefs.firstWhere((TypeDef t) => t.name == name);

  void generate(DartGenerator gen) {
    gen.out(_headerCode);
    gen.writeln("const String generatedProtocolVersion = '${version}';");
    gen.writeln();
    gen.writeln("typedef MethodSend = void Function(String methodName);");
    gen.writeln();
    gen.writeDocs('''
A class to communicate with an analysis server instance.

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
''');
    gen.writeStatement('class AnalysisServer {');
    gen.writeln(_staticFactory);
    gen.writeStatement('final Completer<int> processCompleter;');
    gen.writeStatement('final void Function()? _processKillHandler;');
    gen.writeln();
    gen.writeStatement('StreamSubscription? _streamSub;');
    gen.writeStatement('late void Function(String) _writeMessage;');
    gen.writeStatement('int _id = 0;');
    gen.writeStatement('Map<String, Completer> _completers = {};');
    gen.writeStatement('Map<String, String> _methodNames = {};');
    gen.writeln(
        'JsonCodec _jsonEncoder = JsonCodec(toEncodable: _toEncodable);');
    gen.writeStatement('Map<String, Domain> _domains = {};');
    gen.writeln(
        "StreamController<String> _onSend = StreamController.broadcast();");
    gen.writeln(
        "StreamController<String> _onReceive = StreamController.broadcast();");
    gen.writeln("MethodSend? _willSend;");
    gen.writeln();
    domains.forEach((Domain domain) => gen.writeln(
        'late final ${domain.className} _${domain.name} = ${domain.className}(this);'));
    gen.writeln();
    gen.writeDocs('Connect to an existing analysis server instance.');
    gen.writeStatement(
        'AnalysisServer(Stream<String> inStream, void Function(String) writeMessage, \n'
        'this.processCompleter, [this._processKillHandler]) {');
    gen.writeStatement('configure(inStream, writeMessage);');
    gen.writeln('}');
    gen.writeln();
    domains.forEach((Domain domain) => gen
        .writeln('${domain.className} get ${domain.name} => _${domain.name};'));
    gen.writeln();
    gen.out(_serverCode);
    gen.writeln('}');
    gen.writeln();

    // abstract Domain
    gen.out(_domainCode);

    // individual domains
    domains.forEach((Domain domain) => domain.generate(gen));

    // Object definitions.
    gen.writeln();
    gen.writeln('// type definitions');
    gen.writeln();
    typedefs
        .where((t) => t.isObject)
        .forEach((TypeDef def) => def.generate(gen));

    // Handle the refactorings items.
    gen.writeln();
    gen.writeln('// refactorings');
    gen.writeln();
    gen.writeStatement('class Refactorings {');
    refactorings.forEach((Refactoring refactor) {
      gen.writeStatement(
          "static const String ${refactor.kind} = '${refactor.kind}';");
    });
    gen.writeStatement('}');

    refactorings.forEach((Refactoring refactor) => refactor.generate(gen));

    // Refactoring feedback.
    gen.writeln();

    gen.writeStatement('abstract class RefactoringFeedback {');
    gen.writeStatement(
        'static RefactoringFeedback? parse(String? kind, Map m) {');
    gen.writeln();
    gen.writeStatement('switch (kind) {');
    refactorings.forEach((Refactoring refactor) {
      if (refactor.feedbackFields.isEmpty) return;
      gen.writeStatement("case Refactorings.${refactor.kind}: "
          "return ${refactor.className}Feedback.parse(m);");
    });
    gen.writeStatement('}');
    gen.writeln();
    gen.writeStatement('return null;');
    gen.writeStatement('}');
    gen.writeStatement('}');

    // Refactoring feedback classes.
    for (Refactoring refactor in refactorings) {
      if (refactor.feedbackFields.isEmpty) continue;

      List<Field> fields = refactor.feedbackFields;
      String name = '${refactor.className}Feedback';

      gen.writeln();
      gen.writeDocs('Feedback class for the `${refactor.kind}` refactoring.');
      gen.writeStatement('class ${name} extends RefactoringFeedback {');
      gen.write('static ${name} parse(Map m) => ');
      gen.write('${name}(');
      gen.write(fields.map((Field field) {
        String val = "m['${field.name}']";
        if (field.type.isMap) {
          val = 'Map.from($val)';
        }

        if (field.optional) {
          return "${field.name}: ${field.type.jsonConvert(val, isOptional: true)}";
        } else {
          return field.type.jsonConvert(val);
        }
      }).join(', '));
      gen.writeln(');');
      gen.writeln();
      fields.forEach((field) {
        if (field.deprecated) {
          gen.write('@deprecated ');
        } else {
          gen.writeDocs(field.docs);
        }
        gen.writeln(
            'final ${field.type}${field.optional ? '?' : ''} ${field.name};');
      });
      gen.writeln();
      gen.write('${name}(');
      gen.write(fields.map((field) {
        StringBuffer buf = StringBuffer();
        if (field.optional && fields.firstWhere((a) => a.optional) == field) {
          buf.write('{');
        }
        buf.write('this.${field.name}');
        if (field.optional && fields.lastWhere((a) => a.optional) == field) {
          buf.write('}');
        }
        return buf.toString();
      }).join(', '));
      gen.writeln(');');
      gen.writeln('}');
    }
  }

  String toString() => domains.toString();
}

class Domain {
  bool experimental = false;
  late String name;
  String? docs;

  late List<Request> requests;
  late List<Notification> notifications;
  Map<String, List<Field>> resultClasses = LinkedHashMap();

  Domain(Element element) {
    name = element.attributes['name']!;
    experimental = element.attributes.containsKey('experimental');
    docs = _collectDocs(element);
    requests = element
        .getElementsByTagName('request')
        .map((element) => Request(this, element))
        .toList();
    notifications = element
        .getElementsByTagName('notification')
        .map((element) => Notification(this, element))
        .toList();
  }

  String get className => '${titleCase(name)}Domain';

  void generate(DartGenerator gen) {
    resultClasses.clear();
    gen.writeln();
    gen.writeln('// ${name} domain');
    gen.writeln();
    gen.writeDocs(docs);
    if (experimental) gen.writeln('@experimental');
    gen.writeStatement('class ${className} extends Domain {');
    gen.writeStatement(
        "${className}(AnalysisServer server) : super(server, '${name}');");
    if (notifications.isNotEmpty) {
      gen.writeln();
      notifications
          .forEach((Notification notification) => notification.generate(gen));
    }
    requests.forEach((Request request) => request.generate(gen));
    gen.writeln('}');

    notifications.forEach(
        (Notification notification) => notification.generateClass(gen));

    // Result classes
    for (String name in resultClasses.keys) {
      List<Field> fields = resultClasses[name]!;

      gen.writeln();
      gen.writeStatement('class ${name} {');
      if (name == 'RefactoringResult') {
        gen.write('static ${name}? parse(String? kind, Map m) => ');
      } else {
        gen.write('static ${name} parse(Map m) => ');
      }
      gen.write('${name}(');
      gen.write(fields.map((Field field) {
        String val = "m['${field.name}']";
        if (field.type.isMap) {
          val = 'Map.from($val)';
        }

        if (field.optional) {
          return "${field.name}: ${field.type.jsonConvert(val, isOptional: true)}";
        } else {
          return field.type.jsonConvert(val);
        }
      }).join(', '));
      gen.writeln(');');
      gen.writeln();
      fields.forEach((field) {
        if (field.deprecated) {
          gen.write('@deprecated ');
        } else {
          gen.writeDocs(field.docs);
        }
        gen.writeln(
            'final ${field.type}${field.optional ? '?' : ''} ${field.name};');
      });
      gen.writeln();
      gen.write('${name}(');
      gen.write(fields.map((field) {
        StringBuffer buf = StringBuffer();
        if (field.optional && fields.firstWhere((a) => a.optional) == field) {
          buf.write('{');
        }
        buf.write('this.${field.name}');
        if (field.optional && fields.lastWhere((a) => a.optional) == field) {
          buf.write('}');
        }
        return buf.toString();
      }).join(', '));
      gen.writeln(');');
      gen.writeln('}');
    }
  }

  String toString() => "Domain '${name}': ${requests}";
}

class Request {
  final Domain domain;

  late bool experimental;
  late bool deprecated;
  late String method;
  String? docs;

  List<Field> args = [];
  List<Field> results = [];

  Request(this.domain, Element element) {
    experimental = element.attributes.containsKey('experimental');
    deprecated = element.attributes.containsKey('deprecated');
    method = element.attributes['method']!;
    docs = _collectDocs(element);

    List<Element> paramsList = element.getElementsByTagName('params');
    if (paramsList.isNotEmpty) {
      args = List.from(paramsList.first
          .getElementsByTagName('field')
          .map((field) => Field(field)));
    }

    List<Element> resultsList = element.getElementsByTagName('result');
    if (resultsList.isNotEmpty) {
      results = List.from(resultsList.first
          .getElementsByTagName('field')
          .map((field) => Field(field)));
    }
  }

  void generate(DartGenerator gen) {
    gen.writeln();

    args.forEach((Field field) => field.setCallParam());
    if (results.isNotEmpty) {
      domain.resultClasses[resultName] = results;
    }

    if (deprecated) {
      gen.writeln('@deprecated');
    } else {
      gen.writeDocs(docs);
    }
    if (experimental) gen.writeln('@experimental');

    String qName = '${domain.name}.${method}';

    if (results.isEmpty) {
      if (args.isEmpty) {
        gen.writeln("Future ${method}() => _call('$qName');");
        return;
      }

      if (args.length == 1 && !args.first.optional) {
        Field arg = args.first;
        String type = arg.type.toString();

        if (method == 'updateContent') {
          type = 'Map<String, ContentOverlayType>';
        }
        gen.write("Future ${method}(${type} ${arg.name}) => ");
        gen.writeln("_call('$qName', {'${arg.name}': ${arg.name}});");
        return;
      }
    }

    if (args.isEmpty) {
      gen.writeln("Future<${resultName}> ${method}() => _call('$qName').then("
          "${resultName}.parse);");
      return;
    }

    if (results.isEmpty) {
      gen.write('Future ${method}(');
    } else {
      String resultName = this.resultName;
      if (const ['RefactoringResult'].contains(resultName)) {
        resultName += '?';
      }
      gen.write('Future<${resultName}> ${method}(');
    }
    gen.write(args.map((arg) {
      StringBuffer buf = StringBuffer();
      if (arg.optional && args.firstWhere((a) => a.optional) == arg) {
        buf.write('{');
      }
      buf.write('${arg.type}? ${arg.name}');
      if (arg.optional && args.lastWhere((a) => a.optional) == arg) {
        buf.write('}');
      }
      return buf.toString();
    }).join(', '));
    gen.writeStatement(') {');
    if (args.isEmpty) {
      gen.write("return _call('$qName')");
      if (results.isNotEmpty) {
        gen.write(".then(${resultName}.parse)");
      }
      gen.writeln(';');
    } else {
      String mapStr = args
          .where((arg) => !arg.optional)
          .map((arg) => "'${arg.name}': ${arg.name}")
          .join(', ');
      gen.writeStatement('final Map m = {${mapStr}};');
      for (Field arg in args.where((arg) => arg.optional)) {
        final String statement =
            "if (${arg.name} != null) m['${arg.name}'] = ${arg.name};";
        if (statement.length + gen.indentLength <= gen.colBoundary) {
          gen.writeStatement(statement);
        } else {
          gen.writeln("if (${arg.name} != null) {");
          gen.writeln("m['${arg.name}'] = ${arg.name};");
          gen.writeln('}');
        }
      }
      gen.write("return _call('$qName', m)");
      if (results.isNotEmpty) {
        if (qName == 'edit.getRefactoring') {
          gen.write(".then((m) => ${resultName}.parse(kind, m))");
        } else {
          gen.write(".then(${resultName}.parse)");
        }
      }
      gen.writeln(';');
    }
    gen.writeStatement('}');
  }

  String get resultName {
    if (results.isEmpty) return 'dynamic';
    if (domain.name == 'execution' && method == 'getSuggestions') {
      return 'RuntimeSuggestionsResult';
    }
    if (method.startsWith('get')) return '${method.substring(3)}Result';
    return '${titleCase(method)}Result';
  }

  String toString() => 'Request ${method}()';
}

class Notification {
  static Set<String> disambiguateEvents = Set.from(['FlutterOutline']);

  final Domain domain;
  late String event;
  String? docs;
  late List<Field> fields;

  Notification(this.domain, Element element) {
    event = element.attributes['event']!;
    docs = _collectDocs(element);
    fields = List.from(
        element.getElementsByTagName('field').map((field) => Field(field)));
    fields.sort();
  }

  String get title => '${domain.name}.${event}';

  String get onName => 'on${titleCase(event)}';

  String get className {
    String name = '${titleCase(domain.name)}${titleCase(event)}';
    if (disambiguateEvents.contains(name)) {
      name = name + 'Event';
    }
    return name;
  }

  void generate(DartGenerator gen) {
    gen.writeDocs(docs);
    gen.writeln("Stream<${className}> get ${onName} {");
    gen.writeln("return _listen('${title}', ${className}.parse);");
    gen.writeln("}");
  }

  void generateClass(DartGenerator gen) {
    gen.writeln();
    gen.writeln('class ${className} {');
    gen.write('static ${className} parse(Map m) => ');
    gen.write('${className}(');
    gen.write(fields.map((Field field) {
      String val = "m['${field.name}']";
      if (field.optional) {
        return "${field.name}: ${field.type.jsonConvert(val, isOptional: true)}";
      } else {
        return field.type.jsonConvert(val);
      }
    }).join(', '));
    gen.writeln(');');
    if (fields.isNotEmpty) {
      gen.writeln();
      fields.forEach((field) {
        if (field.deprecated) {
          gen.write('@deprecated ');
        } else {
          gen.writeDocs(field.docs);
        }
        gen.writeln(
            'final ${field.type}${field.optional ? '?' : ''} ${field.name};');
      });
    }
    gen.writeln();
    gen.write('${className}(');
    gen.write(fields.map((field) {
      StringBuffer buf = StringBuffer();
      if (field.optional && fields.firstWhere((a) => a.optional) == field) {
        buf.write('{');
      }
      buf.write('this.${field.name}');
      if (field.optional && fields.lastWhere((a) => a.optional) == field) {
        buf.write('}');
      }
      return buf.toString();
    }).join(', '));
    gen.writeln(');');
    gen.writeln('}');
  }
}

class Field implements Comparable {
  late String name;
  String? docs;
  late bool optional;
  late bool deprecated;
  late Type type;

  Field(Element element) {
    name = element.attributes['name']!;
    docs = _collectDocs(element);
    optional = element.attributes['optional'] == 'true';
    deprecated = element.attributes.containsKey('deprecated');
    type = Type.create(element.children.firstWhere((e) => e.localName != 'p'));
  }

  void setCallParam() => type.setCallParam();

  bool get isJsonable => type.isCallParam();

  String toString() => name;

  int compareTo(other) {
    if (other is! Field) return 0;
    if (!optional && other.optional) return -1;
    if (optional && !other.optional) return 1;
    return 0;
  }

  void generate(DartGenerator gen, {bool forceOptional = false}) {
    if (deprecated) {
      gen.writeln('@deprecated');
    } else {
      gen.writeDocs(docs);
    }
    gen.writeStatement(
        'final ${type}${optional || forceOptional ? '?' : ''} ${name};');
  }
}

class Refactoring {
  late String kind;
  String? docs;
  List<Field> optionsFields = [];
  List<Field> feedbackFields = [];

  Refactoring(Element element) {
    kind = element.attributes['kind']!;
    docs = _collectDocs(element);

    // Parse <options>
    // <field name="deleteSource"><ref>bool</ref></field>
    Element? options = element.querySelector('options');
    if (options != null) {
      optionsFields = List.from(
          options.getElementsByTagName('field').map((field) => Field(field)));
    }

    // Parse <feedback>
    // <field name="className" optional="true"><ref>String</ref></field>
    Element? feedback = element.querySelector('feedback');
    if (feedback != null) {
      feedbackFields = List.from(
          feedback.getElementsByTagName('field').map((field) => Field(field)));
      feedbackFields.sort();
    }
  }

  String get className {
    // MOVE_FILE ==> MoveFile
    return kind.split('_').map((s) => forceTitleCase(s)).join('');
  }

  void generate(DartGenerator gen) {
    // Generate the refactoring options.
    if (optionsFields.isNotEmpty) {
      gen.writeln();
      gen.writeDocs(docs);
      gen.writeStatement(
          'class ${className}RefactoringOptions extends RefactoringOptions {');
      // fields
      for (Field field in optionsFields) {
        field.generate(gen, forceOptional: true);
      }

      gen.writeln();
      gen.writeStatement('${className}RefactoringOptions({'
          '${optionsFields.map((f) => 'this.${f.name}').join(', ')}'
          '});');
      gen.writeln();

      // toMap
      gen.write("Map toMap() => _stripNullValues({");
      gen.write(optionsFields.map((f) => "'${f.name}': ${f.name}").join(', '));
      gen.writeStatement("});");
      gen.writeStatement('}');
    }
  }
}

class TypeDef {
  static final Set<String> _shouldHaveToString = Set.from([
    'SourceEdit',
    'PubStatus',
    'Location',
    'AnalysisStatus',
    'AnalysisError',
    'SourceChange',
    'SourceFileEdit',
    'LinkedEditGroup',
    'Position',
    'NavigationRegion',
    'NavigationTarget',
    'CompletionSuggestion',
    'Element',
    'SearchResult'
  ]);

  static final Set<String> _shouldHaveEquals =
      Set.from(['Location', 'AnalysisError']);

  late String name;
  late bool experimental;
  late bool deprecated;
  String? docs;
  bool isString = false;
  List<Field>? fields;
  bool _callParam = false;

  TypeDef(Element element) {
    name = element.attributes['name']!;
    experimental = element.attributes.containsKey('experimental');
    deprecated = element.attributes.containsKey('deprecated');
    docs = _collectDocs(element);

    // object, enum, ref
    Set<String> tags = Set.from(element.children.map((c) => c.localName));

    if (tags.contains('object')) {
      Element object = element.getElementsByTagName('object').first;
      fields =
          List.from(object.getElementsByTagName('field').map((f) => Field(f)))
            ..sort();
    } else if (tags.contains('enum')) {
      isString = true;
    } else if (tags.contains('ref')) {
      Element tag = element.getElementsByTagName('ref').first;
      String type = tag.text;
      if (type == 'String') {
        isString = true;
      } else {
        throw 'unknown ref type: ${type}';
      }
    } else {
      throw 'unknown tag: ${tags}';
    }
  }

  bool get isObject => fields != null;

  bool get callParam => _callParam;

  void setCallParam() {
    _callParam = true;
  }

  bool isCallParam() => _callParam;

  void generate(DartGenerator gen) {
    if (name == 'RefactoringOptions' ||
        name == 'RefactoringFeedback' ||
        name == 'RequestError') {
      return;
    }

    bool isContentOverlay = name.endsWith('ContentOverlay');
    List<Field> _fields = this.fields!;
    List<Field> fields = _fields;
    if (isContentOverlay) {
      _fields = _fields.toList()..removeAt(0);
    }

    gen.writeln();
    if (deprecated) {
      gen.writeln('@deprecated');
    } else {
      gen.writeDocs(docs);
    }
    if (experimental) gen.writeln('@experimental');
    gen.write('class ${name}');
    if (isContentOverlay) gen.write(' extends ContentOverlayType');
    if (callParam) gen.write(' implements Jsonable');
    gen.writeln(' {');
    gen.writeln('static ${name} parse(Map m) {');
    gen.write('return ${name}(');
    gen.write(_fields.map((Field field) {
      String val = "m['${field.name}']";
      if (field.optional) {
        return "${field.name}: ${field.type.jsonConvert(val, isOptional: true)}";
      } else {
        return field.type.jsonConvert(val);
      }
    }).join(', '));
    gen.writeln(');');
    gen.writeln('}');

    if (_fields.isNotEmpty) {
      gen.writeln();
      _fields.forEach((field) {
        gen.writeln();
        gen.writeDocs(field.docs);
        if (field.deprecated) {
          gen.write('@deprecated ');
        }

        gen.writeln(
            'final ${field.type}${field.optional ? '?' : ''} ${field.name};');
      });
    }

    gen.writeln();
    gen.write('${name}(');
    gen.write(_fields.map((field) {
      StringBuffer buf = StringBuffer();
      if (field.optional && fields.firstWhere((a) => a.optional) == field) {
        buf.write('{');
      }
      buf.write('this.${field.name}');
      if (field.optional && fields.lastWhere((a) => a.optional) == field) {
        buf.write('}');
      }
      return buf.toString();
    }).join(', '));
    if (isContentOverlay) {
      String type = name
          .substring(0, name.length - 'ContentOverlay'.length)
          .toLowerCase();
      gen.writeln(") : super('$type');");
    } else {
      gen.writeln(');');
    }

    if (callParam) {
      gen.writeln();
      String map = fields.map((f) {
        if (f.isJsonable && f.type.typeName != 'String') {
          return "'${f.name}': ${f.name}?.toMap()";
        }
        return "'${f.name}': ${f.name}";
      }).join(', ');
      gen.writeln("Map toMap() => _stripNullValues({${map}});");
    }

    if (hasEquals) {
      gen.writeln();
      String str = fields.map((f) => "${f.name} == o.${f.name}").join(' && ');
      gen.writeln("bool operator==(o) => o is ${name} && ${str};");
      gen.writeln();
      String str2 = fields
          .where((f) => !f.optional)
          .map((f) => "${f.name}.hashCode")
          .join(' ^ ');
      gen.writeln("int get hashCode => ${str2};");
    }

    if (hasToString) {
      gen.writeln();
      String str = fields
          .where((f) => (!f.optional && !f.deprecated))
          .map((f) => "${f.name}: \${${f.name}}")
          .join(', ');
      gen.writeln("String toString() => '[${name} ${str}]';");
    }

    gen.writeln('}');
  }

  bool get hasEquals => _shouldHaveEquals.contains(name);

  bool get hasToString => _shouldHaveToString.contains(name);

  String toString() => 'TypeDef ${name}';
}

abstract class Type {
  String get typeName;

  static Type create(Element element) {
    // <ref>String</ref>, or list, or map
    if (element.localName == 'ref') {
      String text = element.text;
      if (text == 'int' ||
          text == 'bool' ||
          text == 'String' ||
          text == 'double' ||
          text == 'long') {
        return PrimitiveType(text);
      } else {
        return RefType(text);
      }
    } else if (element.localName == 'list') {
      return ListType(element.children.first);
    } else if (element.localName == 'map') {
      return MapType(element.children[0].children.first,
          element.children[1].children.first);
    } else if (element.localName == 'union') {
      return PrimitiveType('dynamic');
    } else {
      throw 'unknown type: ${element}';
    }
  }

  String jsonConvert(String ref, {bool isOptional = false});

  void setCallParam();

  bool isCallParam() => false;

  bool get isMap => typeName == 'Map' || typeName.startsWith('Map<');

  String toString() => typeName;
}

class ListType extends Type {
  Type subType;

  ListType(Element element) : subType = Type.create(element);

  String get typeName => 'List<${subType.typeName}>';

  String jsonConvert(String ref, {bool isOptional = false}) {
    if (subType is PrimitiveType) {
      String code = 'List.from(${ref})';
      return isOptional ? "${ref} == null ? null : $code" : code;
    }

    if (subType is RefType && (subType as RefType).isString) {
      String code = 'List.from(${ref})';
      return isOptional ? "${ref} == null ? null : $code" : code;
    }

    String code =
        'List.from(${ref}.map((obj) => ${subType.jsonConvert('obj', isOptional: false)}))';
    return isOptional ? "${ref} == null ? null : $code" : code;
  }

  void setCallParam() => subType.setCallParam();
}

class MapType extends Type {
  Type key;
  Type value;

  MapType(Element keyElement, Element valueElement)
      : key = Type.create(keyElement),
        value = Type.create(valueElement);

  String get typeName => 'Map<${key.typeName}, ${value.typeName}>';

  String jsonConvert(String ref, {bool isOptional = false}) => ref;

  void setCallParam() {
    key.setCallParam();
    value.setCallParam();
  }
}

class RefType extends Type {
  String text;
  TypeDef? ref;

  RefType(this.text);

  bool get isString {
    if (this.ref == null) _resolve();
    TypeDef ref = this.ref!;
    return ref.isString;
  }

  String get typeName {
    if (this.ref == null) _resolve();
    TypeDef ref = this.ref!;
    return ref.isString ? 'String' : ref.name;
  }

  String jsonConvert(String r, {bool isOptional = false}) {
    if (this.ref == null) _resolve();
    TypeDef ref = this.ref!;
    if (ref.name == 'RefactoringFeedback') {
      if (isOptional) {
        return '$r == null ? null : ${ref.name}.parse(kind, ${r})';
      } else {
        return '${ref.name}.parse(kind, ${r})';
      }
    } else if (ref.isString) {
      return r;
    } else {
      String code = '${ref.name}.parse($r)';
      return isOptional ? '$r == null ? null : $code' : code;
    }
  }

  void setCallParam() {
    if (this.ref == null) _resolve();
    TypeDef ref = this.ref!;
    ref.setCallParam();
  }

  bool isCallParam() => ref!.isCallParam();

  void _resolve() {
    try {
      ref = api.findRef(text);
    } catch (e) {
      print("can't resolve ${text}");
      rethrow;
    }
  }
}

class PrimitiveType extends Type {
  final String type;

  PrimitiveType(this.type);

  String get typeName => type == 'long' ? 'int' : type;

  String jsonConvert(String ref, {bool isOptional = false}) => ref;

  void setCallParam() {}
}

class _ConcatTextVisitor extends TreeVisitor {
  final StringBuffer buffer = StringBuffer();

  String toString() => buffer.toString();

  void visitText(Text node) {
    buffer.write(node.data);
  }

  void visitElement(Element node) {
    if (node.localName == 'b') {
      buffer.write('**${node.text}**');
    } else if (node.localName == 'a') {
      buffer.write('(${node.text})[${node.attributes['href']}]');
    } else if (node.localName == 'tt') {
      buffer.write('`${node.text}`');
    } else {
      visitChildren(node);
    }
  }
}

final RegExp _wsRegexp = RegExp(r'\s+', multiLine: true);

String? _collectDocs(Element element) {
  String str =
      element.children.where((e) => e.localName == 'p').map((Element e) {
    _ConcatTextVisitor visitor = _ConcatTextVisitor();
    visitor.visit(e);
    return visitor.toString().trim().replaceAll(_wsRegexp, ' ');
  }).join('\n\n');
  return str.isEmpty ? null : str;
}

final String _headerCode = r'''
// Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is a generated file.

// ignore_for_file: provide_deprecation_message

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

final Logger _logger = Logger('analysis_server');

''';

final String _staticFactory = r'''
  /// Create and connect to a new analysis server instance.
  ///
  /// - [sdkPath] override the default sdk path
  /// - [scriptPath] override the default entry-point script to use for the
  ///     analysis server
  /// - [onRead] called every time data is read from the server
  /// - [onWrite] called every time data is written to the server
  static Future<AnalysisServer> create(
      {String? sdkPath, String? scriptPath,
       void Function(String str)? onRead, void Function(String str)? onWrite,
       List<String>? vmArgs, List<String>? serverArgs,
       String? clientId, String? clientVersion,
      Map<String, String>? processEnvironment}) async {
    Completer<int> processCompleter = Completer();

    String vmPath;
    if (sdkPath != null) {
      vmPath = path.join(sdkPath, 'bin', Platform.isWindows ? 'dart.exe' : 'dart');
    } else {
      sdkPath = path.dirname(path.dirname(Platform.resolvedExecutable));
      vmPath = Platform.resolvedExecutable;
    }
    scriptPath ??= '$sdkPath/bin/snapshots/analysis_server.dart.snapshot';
    if (!File(scriptPath).existsSync()) {
      throw "The analysis_server snapshot doesn't exist at '$scriptPath', "
          "consider passing `sdkPath` to `AnalysisServer.create`.";
    }

    List<String> args = [scriptPath, '--sdk', sdkPath];
    if (vmArgs != null) args.insertAll(0, vmArgs);
    if (serverArgs != null) args.addAll(serverArgs);
    if (clientId != null) args.add('--client-id=$clientId');
    if (clientVersion != null) args.add('--client-version=$clientVersion');

    Process process = await Process.start(vmPath, args, environment: processEnvironment);
    unawaited(process.exitCode.then((code) => processCompleter.complete(code)));

    Stream<String> inStream = process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .map((String message) {
      if (onRead != null) onRead(message);
      return message;
    });

    AnalysisServer server = AnalysisServer(inStream, (String message) {
      if (onWrite != null) onWrite(message);
      process.stdin.writeln(message);
    }, processCompleter, process.kill);

    return server;
  }

''';

final String _serverCode = r'''
  Stream<String> get onSend => _onSend.stream;
  Stream<String> get onReceive => _onReceive.stream;

  set willSend(MethodSend fn) {
    _willSend = fn;
  }

  void configure(Stream<String> inStream, void Function(String) writeMessage) {
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
          completer.completeError(RequestError.parse(methodName!, json['error']));
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
    Completer<Map> completer = _completers[id] = Completer<Map>();
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
''';

final String _domainCode = r'''
abstract class Domain {
  final AnalysisServer server;
  final String name;

  Map<String, StreamController<Map>> _controllers = {};
  Map<String, Stream> _streams = {};

  Domain(this.server, this.name) {
    server._domains[name] = this;
  }

  Future<Map> _call(String method, [Map? args]) => server._call(method, args);

  Stream<E> _listen<E>(String name, E Function(Map) cvt) {
    if (_streams[name] == null) {
      StreamController<Map> controller = _controllers[name] = StreamController<Map>.broadcast();
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

abstract class RefactoringOptions implements Jsonable {
}

abstract class ContentOverlayType {
  final String type;

  ContentOverlayType(this.type);
}

class RequestError {
  static RequestError parse(String method, Map m) {
    return RequestError(method, m['code'], m['message'], stackTrace: m['stackTrace']);
  }

  final String method;
  final String code;
  final String message;
  final String? stackTrace;

  RequestError(this.method, this.code, this.message, {this.stackTrace});

  String toString() => '[Analyzer RequestError method: ${method}, code: ${code}, message: ${message}]';
}

Map _stripNullValues(Map m) {
  Map copy = {};

  for (var key in m.keys) {
    var value = m[key];
    if (value != null) copy[key] = value;
  }

  return copy;
}
''';
