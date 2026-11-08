#! /usr/bin/env perl
use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT srctop_dir/;
use OpenSSL::Test::Utils;
setup("test_internal_fn_dsa");
plan skip_all => "FN-DSA disabled" if disabled("fn-dsa");
plan tests => 1;
my $data = srctop_dir("test", "recipes", "30-test_fn_dsa_data");
ok(run(test(["fn_dsa_internal_test", $data])), "FN-DSA internal tests");
