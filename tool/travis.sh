#!/bin/bash

# Copyright (c) 2017, Devon Carew. Please see the AUTHORS file for details.
# All rights reserved. Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Fast fail the script on failures.
set -e

# Verify the library re-generates.
dart -c tool/generate_analysis.dart

# Verify that the libraries are error free.
dartanalyzer --fatal-warnings \
  tool/generate_analysis.dart \
  tool/src/analysis_tester.dart \
  lib/analysis_server.dart \
  test/analysis_server_test.dart

# Run the tests.
pub run test
