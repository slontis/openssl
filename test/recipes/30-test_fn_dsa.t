#! /usr/bin/env perl
use strict;
use warnings;
use OpenSSL::Test::Simple;
simple_test("test_fn_dsa", "fn_dsa_test", "fn-dsa");
