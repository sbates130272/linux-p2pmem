#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
#
# A thin wrapper on top of the KUnit Kernel
#
# Copyright (C) 2019, Google LLC.
# Author: Felix Guo <felixguoxiuping@gmail.com>
# Author: Brendan Higgins <brendanhiggins@google.com>

import argparse
import sys
import os
import time

import kunit_config
import kunit_kernel
import kunit_parser

parser = argparse.ArgumentParser(description='Runs KUnit tests.')

parser.add_argument('--raw_output', help='don\'t format output from kernel',
		    action='store_true')

parser.add_argument('--timeout', help='maximum number of seconds to allow for '
		    'all tests to run. This does not include time taken to '
		    'build the tests.', type=int, default=300,
		    metavar='timeout')

parser.add_argument('--jobs',
		    help='As in the make command, "Specifies  the number of '
		    'jobs (commands) to run simultaneously."',
		    type=int, default=8, metavar='jobs')

parser.add_argument('--build_dir',
		    help='As in the make command, it specifies the build '
		    'directory.',
		    type=str, default=None, metavar='build_dir')

cli_args = parser.parse_args()

linux = kunit_kernel.LinuxSourceTree()

build_dir = None
if cli_args.build_dir:
	build_dir = cli_args.build_dir

config_start = time.time()
success = linux.build_reconfig(build_dir)
config_end = time.time()
if not success:
	quit()

kunit_parser.print_with_timestamp('Building KUnit Kernel ...')

build_start = time.time()

success = linux.build_um_kernel(jobs=cli_args.jobs, build_dir=build_dir)
build_end = time.time()
if not success:
	quit()

kunit_parser.print_with_timestamp('Starting KUnit Kernel ...')
test_start = time.time()

if cli_args.raw_output:
	kunit_parser.raw_output(linux.run_kernel(timeout=cli_args.timeout,
						 build_dir=build_dir))
else:
	kunit_parser.parse_run_tests(linux.run_kernel(timeout=cli_args.timeout,
						      build_dir=build_dir))

test_end = time.time()

kunit_parser.print_with_timestamp((
	"Elapsed time: %.3fs total, %.3fs configuring, %.3fs " +
	"building, %.3fs running.\n") % (test_end - config_start,
	config_end - config_start, build_end - build_start,
	test_end - test_start))
