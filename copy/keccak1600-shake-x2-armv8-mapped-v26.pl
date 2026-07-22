#!/usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# AArch64 SHA3-extension, two-way interleaved Keccak-f[1600].
# Stream A occupies d[0] and stream B occupies d[1] of each vector lane.

use strict;
use warnings;

my $output  = (@ARGV && $ARGV[-1] =~ /\.[A-Za-z0-9]+$/) ? pop @ARGV : undef;
my $flavour = (@ARGV && $ARGV[0] !~ /\./) ? shift @ARGV : "linux64";

$0 =~ m{(.*[\\/])[^\\/]+$};
my $dir = $1 // "";
my $xlate = -f "${dir}arm-xlate.pl" ? "${dir}arm-xlate.pl"
          : -f "${dir}../../perlasm/arm-xlate.pl" ? "${dir}../../perlasm/arm-xlate.pl"
          : die "can't locate arm-xlate.pl\n";

open STDOUT, "|\"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't invoke arm-xlate.pl: $!\n";

my $state           = "x0";
my $interleaved_msg = "x1";
my $state_hi        = "x5";
my $round_constants = "x9";
my $round_count     = "x10";
my $round_constant  = "x11";

my (@Av, @Aq);
for my $row (0 .. 4) {
    for my $col (0 .. 4) {
        my $lane = 5 * $row + $col;
        $Av[$col][$row] = "v$lane";
        $Aq[$col][$row] = "q$lane";
    }
}

my @theta_chi_tmp_v = map { "v$_" } (25 .. 29);
my @theta_chi_tmp_q = map { "q$_" } (25 .. 29);
my $temp1_v = "v30";
my $temp2_v = "v31";
my $temp1_q = "q30";
my $temp2_q = "q31";

# Rho constants are ordered as five rows for x=0 through x=4.
my @rho_list = (0, 36, 3, 41, 18,
                 1, 44, 10, 45, 2,
                 62, 6, 43, 15, 61,
                 28, 55, 25, 21, 56,
                 27, 20, 39, 8, 14);
my @rhotates;
for my $col (0 .. 4) {
    for my $row (0 .. 4) {
        $rhotates[$col][$row] = $rho_list[5 * $col + $row];
    }
}

my $code = <<'___';
#include "arch/arm_arch.h"

#if defined(__AARCH64EB__) || defined(__ARMEB__)
# error "This implementation requires little-endian AArch64"
#endif

.section .rodata
.align 6
.Lkeccak_iotas:
.quad 0x0000000000000001
.quad 0x0000000000008082
.quad 0x800000000000808a
.quad 0x8000000080008000
.quad 0x000000000000808b
.quad 0x0000000080000001
.quad 0x8000000080008081
.quad 0x8000000000008009
.quad 0x000000000000008a
.quad 0x0000000000000088
.quad 0x0000000080008009
.quad 0x000000008000000a
.quad 0x000000008000808b
.quad 0x800000000000008b
.quad 0x8000000000008089
.quad 0x8000000000008003
.quad 0x8000000000008002
.quad 0x8000000000000080
.quad 0x000000000000800a
.quad 0x800000008000000a
.quad 0x8000000080008081
.quad 0x8000000000008080
.quad 0x0000000080000001
.quad 0x8000000080008008
.size .Lkeccak_iotas,.-.Lkeccak_iotas

.text
___

# Save the ABI-preserved halves of v8-v15.
sub save_nonvolatile_vectors {
    $code .= <<___;
    stp d8, d9, [sp, #-64]!
    stp d10, d11, [sp, #16]
    stp d12, d13, [sp, #32]
    stp d14, d15, [sp, #48]
___
}

# Restore the ABI-preserved halves of v8-v15.
sub restore_nonvolatile_vectors {
    $code .= <<___;
    ldp d10, d11, [sp, #16]
    ldp d12, d13, [sp, #32]
    ldp d14, d15, [sp, #48]
    ldp d8, d9, [sp], #64
___
}

# Load the complete interleaved state.
sub load_state {
    $code .= <<___;
    add $state_hi, $state, #240
    ldp $Aq[0][0], $Aq[1][0], [$state, #0]
    ldp $Aq[2][0], $Aq[3][0], [$state, #32]
    ldp $Aq[4][0], $Aq[0][1], [$state, #64]
    ldp $Aq[1][1], $Aq[2][1], [$state, #96]
    ldp $Aq[3][1], $Aq[4][1], [$state, #128]
    ldp $Aq[0][2], $Aq[1][2], [$state, #160]
    ldp $Aq[2][2], $Aq[3][2], [$state, #192]
    ldr $Aq[4][2], [$state, #224]
    ldr $Aq[0][3], [$state_hi, #0]
    ldp $Aq[1][3], $Aq[2][3], [$state_hi, #16]
    ldp $Aq[3][3], $Aq[4][3], [$state_hi, #48]
    ldp $Aq[0][4], $Aq[1][4], [$state_hi, #80]
    ldp $Aq[2][4], $Aq[3][4], [$state_hi, #112]
    ldr $Aq[4][4], [$state_hi, #144]
___
}

# Store the complete interleaved state.
sub save_state {
    $code .= <<___;
    stp $Aq[0][0], $Aq[1][0], [$state, #0]
    stp $Aq[2][0], $Aq[3][0], [$state, #32]
    stp $Aq[4][0], $Aq[0][1], [$state, #64]
    stp $Aq[1][1], $Aq[2][1], [$state, #96]
    stp $Aq[3][1], $Aq[4][1], [$state, #128]
    stp $Aq[0][2], $Aq[1][2], [$state, #160]
    stp $Aq[2][2], $Aq[3][2], [$state, #192]
    str $Aq[4][2], [$state, #224]
    str $Aq[0][3], [$state_hi, #0]
    stp $Aq[1][3], $Aq[2][3], [$state_hi, #16]
    stp $Aq[3][3], $Aq[4][3], [$state_hi, #48]
    stp $Aq[0][4], $Aq[1][4], [$state_hi, #80]
    stp $Aq[2][4], $Aq[3][4], [$state_hi, #112]
    str $Aq[4][4], [$state_hi, #144]
___
}

# Load an initial rate block directly into the state registers.
sub load_initial_rate {
    my ($rate_lanes) = @_;

    die "unsupported rate: $rate_lanes lanes\n"
        unless $rate_lanes == 17 || $rate_lanes == 21;

    $code .= <<___;
    add $state_hi, $state, #240
    ldp $Aq[0][0], $Aq[1][0], [$interleaved_msg, #0]
    ldp $Aq[2][0], $Aq[3][0], [$interleaved_msg, #32]
    ldp $Aq[4][0], $Aq[0][1], [$interleaved_msg, #64]
    ldp $Aq[1][1], $Aq[2][1], [$interleaved_msg, #96]
    ldp $Aq[3][1], $Aq[4][1], [$interleaved_msg, #128]
    ldp $Aq[0][2], $Aq[1][2], [$interleaved_msg, #160]
    ldp $Aq[2][2], $Aq[3][2], [$interleaved_msg, #192]
    ldp $Aq[4][2], $Aq[0][3], [$interleaved_msg, #224]
    ldr $Aq[1][3], [$interleaved_msg, #256]
___

    if ($rate_lanes == 21) {
        $code .= <<___;
    ldp $Aq[2][3], $Aq[3][3], [$interleaved_msg, #272]
    ldp $Aq[4][3], $Aq[0][4], [$interleaved_msg, #304]
    eor $Av[1][4].16b, $Av[1][4].16b, $Av[1][4].16b
    eor $Av[2][4].16b, $Av[2][4].16b, $Av[2][4].16b
    eor $Av[3][4].16b, $Av[3][4].16b, $Av[3][4].16b
    eor $Av[4][4].16b, $Av[4][4].16b, $Av[4][4].16b
___
    } else {
        $code .= <<___;
    eor $Av[2][3].16b, $Av[2][3].16b, $Av[2][3].16b
    eor $Av[3][3].16b, $Av[3][3].16b, $Av[3][3].16b
    eor $Av[4][3].16b, $Av[4][3].16b, $Av[4][3].16b
    eor $Av[0][4].16b, $Av[0][4].16b, $Av[0][4].16b
    eor $Av[1][4].16b, $Av[1][4].16b, $Av[1][4].16b
    eor $Av[2][4].16b, $Av[2][4].16b, $Av[2][4].16b
    eor $Av[3][4].16b, $Av[3][4].16b, $Av[3][4].16b
    eor $Av[4][4].16b, $Av[4][4].16b, $Av[4][4].16b
___
    }
}

# XOR a rate block using three interleaved load buffers.
sub xor_rate {
    my ($rate_lanes) = @_;

    die "unsupported rate: $rate_lanes lanes\n"
        unless $rate_lanes == 17 || $rate_lanes == 21;

    $code .= <<___;
    ldp $theta_chi_tmp_q[0], $theta_chi_tmp_q[1], [$interleaved_msg, #0]
    ldp $theta_chi_tmp_q[2], $theta_chi_tmp_q[3], [$interleaved_msg, #32]
    ldp $theta_chi_tmp_q[4], $temp1_q, [$interleaved_msg, #64]
    eor $Av[0][0].16b, $Av[0][0].16b, $theta_chi_tmp_v[0].16b
    eor $Av[1][0].16b, $Av[1][0].16b, $theta_chi_tmp_v[1].16b
    ldp $theta_chi_tmp_q[0], $theta_chi_tmp_q[1], [$interleaved_msg, #96]
    eor $Av[2][0].16b, $Av[2][0].16b, $theta_chi_tmp_v[2].16b
    eor $Av[3][0].16b, $Av[3][0].16b, $theta_chi_tmp_v[3].16b
    ldp $theta_chi_tmp_q[2], $theta_chi_tmp_q[3], [$interleaved_msg, #128]
    eor $Av[4][0].16b, $Av[4][0].16b, $theta_chi_tmp_v[4].16b
    eor $Av[0][1].16b, $Av[0][1].16b, $temp1_v.16b
    ldp $theta_chi_tmp_q[4], $temp1_q, [$interleaved_msg, #160]
    eor $Av[1][1].16b, $Av[1][1].16b, $theta_chi_tmp_v[0].16b
    eor $Av[2][1].16b, $Av[2][1].16b, $theta_chi_tmp_v[1].16b
    ldp $theta_chi_tmp_q[0], $theta_chi_tmp_q[1], [$interleaved_msg, #192]
    eor $Av[3][1].16b, $Av[3][1].16b, $theta_chi_tmp_v[2].16b
    eor $Av[4][1].16b, $Av[4][1].16b, $theta_chi_tmp_v[3].16b
    ldp $theta_chi_tmp_q[2], $theta_chi_tmp_q[3], [$interleaved_msg, #224]
    eor $Av[0][2].16b, $Av[0][2].16b, $theta_chi_tmp_v[4].16b
    eor $Av[1][2].16b, $Av[1][2].16b, $temp1_v.16b
    ldr $temp2_q, [$interleaved_msg, #256]
    eor $Av[2][2].16b, $Av[2][2].16b, $theta_chi_tmp_v[0].16b
    eor $Av[3][2].16b, $Av[3][2].16b, $theta_chi_tmp_v[1].16b
___

    if ($rate_lanes == 21) {
        $code .= <<___;
    ldp $theta_chi_tmp_q[0], $theta_chi_tmp_q[1], [$interleaved_msg, #272]
___
    }

    $code .= <<___;
    eor $Av[4][2].16b, $Av[4][2].16b, $theta_chi_tmp_v[2].16b
    eor $Av[0][3].16b, $Av[0][3].16b, $theta_chi_tmp_v[3].16b
___

    if ($rate_lanes == 21) {
        $code .= <<___;
    ldp $theta_chi_tmp_q[2], $theta_chi_tmp_q[3], [$interleaved_msg, #304]
___
    }

    $code .= <<___;
    eor $Av[1][3].16b, $Av[1][3].16b, $temp2_v.16b
___

    if ($rate_lanes == 21) {
        $code .= <<___;
    eor $Av[2][3].16b, $Av[2][3].16b, $theta_chi_tmp_v[0].16b
    eor $Av[3][3].16b, $Av[3][3].16b, $theta_chi_tmp_v[1].16b
    eor $Av[4][3].16b, $Av[4][3].16b, $theta_chi_tmp_v[2].16b
    eor $Av[0][4].16b, $Av[0][4].16b, $theta_chi_tmp_v[3].16b
___
    }
}

# Apply the Theta step and prepare the XAR zero operand.
sub theta {
    for my $col (0 .. 4) {
        $code .= <<___;
    eor3 $theta_chi_tmp_v[$col].16b, $Av[$col][0].16b, $Av[$col][1].16b, $Av[$col][2].16b
    eor3 $theta_chi_tmp_v[$col].16b, $theta_chi_tmp_v[$col].16b, $Av[$col][3].16b, $Av[$col][4].16b
___
    }

    $code .= <<___;
    eor $temp2_v.16b, $temp2_v.16b, $temp2_v.16b
___

    for my $col (0 .. 4) {
        $code .= <<___;
    rax1 $temp1_v.2d, $theta_chi_tmp_v[($col + 4) % 5].2d, $theta_chi_tmp_v[($col + 1) % 5].2d
    eor $Av[$col][0].16b, $Av[$col][0].16b, $temp1_v.16b
    eor $Av[$col][1].16b, $Av[$col][1].16b, $temp1_v.16b
    eor $Av[$col][2].16b, $Av[$col][2].16b, $temp1_v.16b
    eor $Av[$col][3].16b, $Av[$col][3].16b, $temp1_v.16b
    eor $Av[$col][4].16b, $Av[$col][4].16b, $temp1_v.16b
___
    }
}

# Perform Rho and Pi in place without clobbering live lanes.
sub rho_pi {
    my @cycle;
    my ($col, $row) = (1, 0);

    while (!grep { $_->[0] == $col && $_->[1] == $row } @cycle) {
        push @cycle, [$col, $row];
        ($col, $row) = ($row, (2 * $col + 3 * $row) % 5);
    }
    die "invalid Pi cycle\n"
        unless @cycle == 24 && $col == 1 && $row == 0;

    $code .= <<___;
    mov $temp1_v.16b, $Av[$cycle[0][0]][$cycle[0][1]].16b
___

    for (my $i = $#cycle; $i >= 1; --$i) {
        my ($src_col, $src_row) = @{$cycle[$i]};
        my ($dst_col, $dst_row) = ($src_row,
                                   (2 * $src_col + 3 * $src_row) % 5);
        my $immediate = (64 - $rhotates[$src_col][$src_row]) & 63;
        $code .= <<___;
    xar $Av[$dst_col][$dst_row].2d, $Av[$src_col][$src_row].2d, $temp2_v.2d, #$immediate
___
    }

    my ($src_col, $src_row) = @{$cycle[0]};
    my ($dst_col, $dst_row) = ($src_row,
                               (2 * $src_col + 3 * $src_row) % 5);
    my $immediate = (64 - $rhotates[$src_col][$src_row]) & 63;
    $code .= <<___;
    xar $Av[$dst_col][$dst_row].2d, $temp1_v.2d, $temp2_v.2d, #$immediate
___
}

# Apply Chi to the physically permuted rows.
sub chi {
    for my $row (0 .. 4) {
        for my $col (0 .. 4) {
            $code .= <<___;
    bcax $theta_chi_tmp_v[$col].16b, $Av[$col][$row].16b, $Av[($col + 2) % 5][$row].16b, $Av[($col + 1) % 5][$row].16b
___
        }
        for my $col (0 .. 4) {
            $code .= <<___;
    mov $Av[$col][$row].16b, $theta_chi_tmp_v[$col].16b
___
        }
    }
}

# Generate all 24 Keccak-f[1600] rounds.
sub permutation {
    my ($tag) = @_;
    my $round_label = ".Lkeccak_x2_round_${tag}";

    $code .= <<___;
    adrp $round_constants, .Lkeccak_iotas
    add $round_constants, $round_constants, :lo12:.Lkeccak_iotas
    mov $round_count, #24
.align 4
$round_label:
    ldr $round_constant, [$round_constants], #8
___
    theta();
    rho_pi();
    $code .= <<___;
    dup $temp1_v.2d, $round_constant
___
    chi();
    $code .= <<___;
    eor $Av[0][0].16b, $Av[0][0].16b, $temp1_v.16b
    subs $round_count, $round_count, #1
    b.ne $round_label
___
}

# Generate one exported assembly entry point.
sub generate_function {
    my (%args) = @_;

    $code .= <<___;
.globl $args{name}
.type $args{name},%function
.align 5
$args{name}:
    AARCH64_VALID_CALL_TARGET
___
    save_nonvolatile_vectors();

    if ($args{mode} eq 'permute') {
        load_state();
    } elsif ($args{mode} eq 'init') {
        load_initial_rate($args{rate});
    } elsif ($args{mode} eq 'update') {
        load_state();
        xor_rate($args{rate});
    } else {
        die "bad mode\n";
    }

    permutation($args{name});
    save_state();
    restore_nonvolatile_vectors();
    $code .= <<___;
    ret
.size $args{name},.-$args{name}
___
}

generate_function(name => 'ossl_shake128_x2_absorb_init_armv8',   mode => 'init',   rate => 21);
generate_function(name => 'ossl_shake128_x2_absorb_update_armv8', mode => 'update', rate => 21);
generate_function(name => 'ossl_shake256_x2_absorb_init_armv8',   mode => 'init',   rate => 17);
generate_function(name => 'ossl_shake256_x2_absorb_update_armv8', mode => 'update', rate => 17);
generate_function(name => 'keccak1600_2x_permute_armv8',          mode => 'permute');

# Encode SHA3-extension mnemonics for older assemblers.
sub sha3_opcode {
    my ($mnemonic, $operands) = @_;
    my ($opcode, $vd, $vn, $vm, $va_or_imm);

    if ($mnemonic eq "eor3" || $mnemonic eq "bcax") {
        $operands =~ /^v(\d+)\.16b,\s*v(\d+)\.16b,\s*v(\d+)\.16b,\s*v(\d+)\.16b$/
            or die "unable to encode $mnemonic $operands\n";
        ($vd, $vn, $vm, $va_or_imm) = ($1, $2, $3, $4);
        $opcode = ($mnemonic eq "eor3" ? 0xce000000 : 0xce200000)
                | $vd | ($vn << 5) | ($va_or_imm << 10) | ($vm << 16);
    } elsif ($mnemonic eq "rax1") {
        $operands =~ /^v(\d+)\.2d,\s*v(\d+)\.2d,\s*v(\d+)\.2d$/
            or die "unable to encode $mnemonic $operands\n";
        ($vd, $vn, $vm) = ($1, $2, $3);
        $opcode = 0xce608c00 | $vd | ($vn << 5) | ($vm << 16);
    } elsif ($mnemonic eq "xar") {
        $operands =~ /^v(\d+)\.2d,\s*v(\d+)\.2d,\s*v(\d+)\.2d,\s*#(\d+)$/
            or die "unable to encode $mnemonic $operands\n";
        ($vd, $vn, $vm, $va_or_imm) = ($1, $2, $3, $4);
        die "XAR immediate out of range: $va_or_imm\n" if $va_or_imm > 63;
        $opcode = 0xce800000 | $vd | ($vn << 5) | ($va_or_imm << 10) | ($vm << 16);
    } else {
        die "unsupported SHA3 mnemonic: $mnemonic\n";
    }

    return sprintf("    .inst 0x%08x    // %s %s", $opcode, $mnemonic, $operands);
}

for my $line (split /\n/, $code) {
    $line =~ s/^\s*(eor3|rax1|bcax|xar)\s+(.+)$/sha3_opcode($1, $2)/e;
    print "$line\n";
}
close STDOUT or die "error closing translator pipe: $!\n";
