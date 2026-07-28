
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
my $msg             = "x1";
my $msg2            = "x2"; # Temp register when using uninterleaved absorb input
my $state_hi        = "x5";
my $round_constants = "x9";
my $round_count     = "x10";
my $round_constant  = "x11";

my (@Av, @Aq, @statev);
for my $row (0 .. 4) {
    for my $col (0 .. 4) {
        my $lane = 5 * $row + $col;
        $Av[$col][$row] = "v$lane";
        $Aq[$col][$row] = "q$lane";
        push(@statev, "v$lane");
    }
}

my @theta_chi_tmp_v = map { "v$_" } (25 .. 29);
my @theta_chi_tmp_q = map { "q$_" } (25 .. 29);
my @queue_v = map { "v$_" } (25 .. 31);
my @queue_q = map { "q$_" } (25 .. 31);
my $temp1_v = "v30";
my $temp1_q = "q30";
my $temp1_d = "d30";
my $temp2_v = "v31";
my $temp2_q = "q31";
my $temp2_d = "d31";
my $temp3_v = "v29";

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
    .align 4        // Force 16-byte alignment for LDR Q-register safety
round_constants_table:
    .quad 0x0000000000000001, 0x0000000000000001    // Round 0 Constant (Block A, Block B)
    .quad 0x0000000000008082, 0x0000000000008082    // Round 1 Constant (Block A, Block B)
    .quad 0x800000000000808a, 0x800000000000808a    // Round 2 Constant (Block A, Block B)
    .quad 0x8000000080008000, 0x8000000080008000    // Round 3 Constant (Block A, Block B)
    .quad 0x000000000000808b, 0x000000000000808b    // Round 4 Constant (Block A, Block B)
    .quad 0x0000000080000001, 0x0000000080000001    // Round 5 Constant (Block A, Block B)
    .quad 0x8000000080008081, 0x8000000080008081    // Round 6 Constant (Block A, Block B)
    .quad 0x8000000000008009, 0x8000000000008009    // Round 7 Constant (Block A, Block B)
    .quad 0x000000000000008a, 0x000000000000008a    // Round 8 Constant (Block A, Block B)
    .quad 0x0000000000000088, 0x0000000000000088    // Round 9 Constant (Block A, Block B)
    .quad 0x0000000080008009, 0x0000000080008009    // Round 10 Constant (Block A, Block B)
    .quad 0x000000008000000a, 0x000000008000000a    // Round 11 Constant (Block A, Block B)
    .quad 0x000000008000808b, 0x000000008000808b    // Round 12 Constant (Block A, Block B)
    .quad 0x800000000000008b, 0x800000000000008b    // Round 13 Constant (Block A, Block B)
    .quad 0x8000000000008089, 0x8000000000008089    // Round 14 Constant (Block A, Block B)
    .quad 0x8000000000008003, 0x8000000000008003    // Round 15 Constant (Block A, Block B)
    .quad 0x8000000000008002, 0x8000000000008002    // Round 16 Constant (Block A, Block B)
    .quad 0x8000000000000080, 0x8000000000000080    // Round 17 Constant (Block A, Block B)
    .quad 0x000000000000800a, 0x000000000000800a    // Round 18 Constant (Block A, Block B)
    .quad 0x800000008000000a, 0x800000008000000a    // Round 19 Constant (Block A, Block B)
    .quad 0x8000000080008081, 0x8000000080008081    // Round 20 Constant (Block A, Block B)
    .quad 0x8000000000008080, 0x8000000000008080    // Round 21 Constant (Block A, Block B)
    .quad 0x0000000080000001, 0x0000000080000001    // Round 22 Constant (Block A, Block B)
    .quad 0x8000000080008008, 0x8000000080008008    // Round 23 Constant (Block A, Block B)

.size .Lround_constants_table,.-.Lround_constants_table
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

# This code assumes that $msg is 16 byte aligned
# ($msg + $rate) is also 16 byte aligned.
sub generate_uninterleaved_absorb_pipeline {
    my ($rate_bytes, $is_initial) = @_;
    my $num_lanes = $rate_bytes / 8;

    $code .= "    add $msg2, $msg, #$rate_bytes\n";

    # Fetch 4 64-bit lanes (2 128-bit registers) at once!
    my $i = 0;
    while ($i < ($num_lanes - 7)) {
        my $off = $i * 8; # Byte offset

    # 1. Fetch 32 Bytes from Block A and 32 Bytes from Block B simultaneously
    # This completely saturates the CPU's memory read pipelines.
$code .= <<___;
    ldp q24, q25, [\$msg,  #$off]           // Lanes i, i+1, i+2, i+3 (Block A)
    ldp q26, q27, [\$msg,  #@{[$off + 32]}] // Lanes i+4, i+5, i+6, i+7 (Block A)
    ldp q28, q29, [\$msg2, #$off]           // Lanes i, i+1, i+2, i+3 (Block B)
    ldp q30, q31, [\$msg2, #@{[$off + 32]}] // Lanes i+4, i+5, i+6, i+7 (Block B)
___

    # 2. Interleave and Process Out-of-Order
    # We extract lower/upper halves of the 128-bit registers using zip1/zip2
        if ($is_initial) {
$code .= <<___;
    zip1 $statev[$i].2d,   q24.2d, q28.2d   // Lane i (Block A + B)
    zip2 $statev[$i+1].2d, q24.2d, q28.2d   // Lane i+1 (Block A + B)
    zip1 $statev[$i+2].2d, q25.2d, q29.2d   // Lane i+2 (Block A + B)
    zip2 $statev[$i+3].2d, q25.2d, q29.2d   // Lane i+3 (Block A + B)
    zip1 $statev[$i+4].2d, q26.2d, q30.2d   // Lane i+4 (Block A + B)
    zip2 $statev[$i+5].2d, q26.2d, q30.2d   // Lane i+5 (Block A + B)
    zip1 $statev[$i+6].2d, q27.2d, q31.2d   // Lane i+6 (Block A + B)
    zip2 $statev[$i+7].2d, q27.2d, q31.2d   // Lane i+7 (Block A + B)
___
        } else {
            # Uses scratch temporary vectors to hold the interleaved layout pairs before XORing
$code .= <<___;
    zip1 v16.2d, q24.2d, q28.2d
    zip2 v17.2d, q24.2d, q28.2d
    zip1 v18.2d, q25.2d, q29.2d
    zip2 v19.2d, q25.2d, q29.2d
    eor  $statev[$i].16b,   $statev[$i].16b,   v16.16b
    eor  $statev[$i+1].16b, $statev[$i+1].16b, v17.16b
    eor  $statev[$i+2].16b, $statev[$i+2].16b, v18.16b
    eor  $statev[$i+3].16b, $statev[$i+3].16b, v19.16b

    zip1 v16.2d, q26.2d, q30.2d
    zip2 v17.2d, q26.2d, q30.2d
    zip1 v18.2d, q27.2d, q31.2d
    zip2 v19.2d, q27.2d, q31.2d
    eor  $statev[$i+4].16b, $statev[$i+4].16b, v16.16b
    eor  $statev[$i+5].16b, $statev[$i+5].16b, v17.16b
    eor  $statev[$i+6].16b, $statev[$i+6].16b, v18.16b
    eor  $statev[$i+7].16b, $statev[$i+7].16b, v19.16b
___
        }
        $i += 8;
    }

    # Handle remaining single lanes
    # (since SHAKE128/21 lanes and SHAKE256/17 lanes aren't clean multiples of 8)
    while ($i < $num_lanes) {
        my $off = $i * 8;
$code .= <<___;
    ldr d24, [\$msg, #$off]
    ldr d25, [\$msg2, #$off]
___
        if ($is_initial) {
            $code .= "    zip1 $statev[$i].2d, v24.2d, v25.2d\n";
        } else {
$code .= <<___;
    zip1 v16.2d, v24.2d, v25.2d
    eor  $statev[$i].16b, $statev[$i].16b, v16.16b
___
        }
        $i++;
    }

    # Step 4: For initial blocks, zero out the remaining capacity matrix registers
    if ($is_initial) {
        for (my $j = $num_lanes; $j < 25; $j++) {
            $code .= "    eor $statev[$j].16b, $statev[$j].16b, $statev[$j].16b\n";
        }
    }
}

#
# Using 2 interleaved blocks of input data, load the data into a state matrix
# of size 5*5, where each element holds 2 64 bit values. The state is stored into
# q0..24
#
# $rate: 17 (SHAKE256) or 21 (SHAKE128)
# $is_initial: 1 if its the initial absorb, or 0 for subsequent absorbs.
#              On the first call it does not need to XOR into the state
# $msg: input 2 * $rate of data for 2 blocks. The data is interleaved, so that
#   laneN is 64bits of data for block1, laneN+1 is 64bits of data for block2.
#
# Since the state uses q0..q24, that only leaves 7 registers q25..q31.
# The registers used in a ldp instruction can take 3-4 cycles before they can
# be accessed. Reduce stalls by pre loading before values are needed.
# Use a 7 register ring buffer in q25..q31, and preload 6 lanes to prevent stalls.

sub generate_interleaved_absorb_pipeline {
    my ($rate, $is_initial) = @_;

    # Validation against SHAKE specifications
    die "Unsupported rate: $rate (Expected 17 for SHAKE256 or 21 for SHAKE128)\n"
        unless $rate == 17 || $rate == 21;

    # Explicitly map the 7 available scratch registers to our software ring buffer
    my @ring_buf = map { "q$_" } (25 .. 31);
    my $rb_sz    = scalar @ring_buf; # Exactly 7

    my $gen_op = sub {
        my ($state_idx, $reg_name) = @_;
        # $state_idx represents q0..q24 state matrix
        return $is_initial ? "orr q$state_idx.16b, $reg_name.16b, $reg_name.16b"
                           : "eor q$state_idx.16b, q$state_idx.16b, $reg_name.16b";
    };

    # Step 1: Pre-prime the ring buffer with the first 6 lanes (3 pairs = 96 bytes)
    # This maximizes execution depth without overflowing our 7-register ceiling.
$code .= <<___;
    ldp $ring_buf[0], $ring_buf[1], [\$msg, #0]   // Prefetch Lanes 0 & 1
    ldp $ring_buf[2], $ring_buf[3], [\$msg, #32]  // Prefetch Lanes 2 & 3
    ldp $ring_buf[4], $ring_buf[5], [\$msg, #64]  // Prefetch Lanes 4 & 5
___

    # Step 2: Main Pipeline Loop (Process pair-by-pair)
    my $lane = 0;
    while ($lane < ($rate - 2)) {
        my $fetch_lane = $lane + 6;
        # Fetch offset tracks 6 lanes ahead of current execution lane
        my $fetch_off = $fetch_lane * 16;

        my $curr1 = $ring_buf[$lane % $rb_sz];
        my $curr2 = $ring_buf[($lane + 1) % $rb_sz];
        my $next1 = $ring_buf[$fetch_lane % $rb_sz];
        my $next2 = $ring_buf[($fetch_lane + 1) % $rb_sz];

        # Emit Vector ALU processing steps
        $code .= "    " . $gen_op->($lane,     $curr1) . "\n";

        # Interleaved speculative load execution to hide latency
        if (($lane + 7) < $rate) {
            $code .= "    ldp ${next1}, ${next2}, [\$msg, #$fetch_off]\n";
        }
        elsif (($lane + 6) < $rate) {
            # Single-register fallback if only 1 lane remains to fetch
            $code .= "    ldr ${next1}, [\$msg, #$fetch_off]\n";
        }
        $code .= "    " . $gen_op->($lane + 1, $curr2) . "\n";

        $lane += 2;
    }

    # Step 3: Drain the remaining lanes in the pipeline tail
    while ($lane < $rate) {
        my $curr = $ring_buf[$lane % $rb_sz];
        $code .= "    " . $gen_op->($lane, $curr) . "\n";
        $lane++;
    }

    # Step 4: Clear the capacity/padding space for Keccak permutation compatibility
    if ($is_initial) {
        for (my $j = $rate; $j < 25; $j++) {
            $code .= "    eor q$j.16b, q$j.16b, q$j.16b\n";
        }
    }
}


Theta:

C[0] = A[0,0] ^ A[0,1] ^ A[0,2]
C[1] = A[1,0] ^ A[1,1] ^ A[1,2]
C[2] = A[2,0] ^ A[2,1] ^ A[2,2]
C[3] = A[3,0] ^ A[3,1] ^ A[2,2]
C[4] = A[4,0] ^ A[4,1] ^ A[2,2]
C[0] ^= A[0,3] ^ A[0,4]
C[1] ^= A[1,3] ^ A[1,4]
C[2] ^= A[2,3] ^ A[2,4]
C[3] ^= A[3,3] ^ A[3,4]
C[4] ^= A[4,3] ^ A[4,4]

D[0] = C[4] ^ ROL1(C[1])
D[1] = C[0] ^ ROL1(C[2])
D[2] = C[1] ^ ROL1(C[1])
D[3] = C[2] ^ ROL1(C[1])
D[4] = C[3] ^ ROL1(C[1])
D[5] = C[4] ^ ROL1(C[1])
D[6] = C[5] ^ ROL1(C[1])
D[7] = C[4] ^ ROL1(C[1])




# Theta:
#   C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
#   D[x] = C[(x-1) % 5] ^ ROL1((C[x+1) % 5))
#   For each row y: A[x,y] ^= D[x]
#   NOTE: RAX1  dst, src1, src2 => dst = src1 ^ (src2 <<<1) (used for D[x])
#         EOR3 dst, src1, src2, src3 => dst = src1 ^ src2 ^ src3 (used for C[x])
#         XAR dst, src1, src2, #imm => dst = ROR(src1 ^ src2, imm) (A[x,y] ^= D[x])
# Rho:
#   A[x,y] = ROTATE([A[x,y], fixed_rotate[x,y])
# Pi:
#   A[y, (2x+ 3y) % 5] = A[x,y]
# So if we are doing rho + pi in place then it becomes
#   A[y, (2x+ 3y) % 5] = ROTATE([A[x,y], fixed_rotate[x,y])
# Note that A[0,0] is not modified.
# If you start at A[x=1,y=0] the mapping A[y, (2x+ 3y) % 5]
# will visit each element in the state, and you can do the
# substitutions without trashing any states.
# Just using the previous state however will result in stalls
# so we need to run 2 cycles at once to interleave them.
#
# Chi:
#   A[x,y] = A[x,y] ^ (~A[(x+1) % 5,y] & A[(x+2) % 5,y])
# iota:
#   A[0][0] = A[0][0] ^ RoundConst[round]
# To combine Chi & iota:
#   A[0][0] = A[0][0] ^ (~A[1][0] & A[2,0])) ^ RoundConst[round]
# Note: BCAX dst, src1, src2, src3 => dst = src1 ^ (src2 & ~src3) (Used for CHI)
#
# SHA3 supports RAX1, EOR3, XAR and BCAX, which all work on 128 bit values
# consisting of 2*64 bit parallel lanes. This means we can perform 2
# permute operations in parallel.

sub keccak1600x2_round {
    my ($round_const) = @_;

    # -------------------------------------------------------------------------
    # 1. PI TRANSFORMATION PIPELINE SETUP
    # -------------------------------------------------------------------------
    my $col = 1;
    my $row = 0;
    my @rho_pi_steps;

    # Track the exact coordinate chain sequence for the combined Rho-Pi step
    for (my $step = 0; $step < 24; $step++) {
        my $next_col = $row;
        my $next_row = (2 * $col + 3 * $row) % 5;
        my $shift_amt = $rhotates[$col][$row];
        my $xar_imm   = (64 - $shift_amt) & 63;

        push @rho_pi_steps, {
            src_reg => $Av[$col][$row],
            dst_reg => $Av[$next_col][$next_row],
            imm     => $xar_imm,
        };
        ($col, $row) = ($next_col, $next_row);
    }

    # Split the 24 permutations into two balanced execution streams to hide latency
    my @grp1 = @rho_pi_steps[0 .. 11];
    my @grp2 = @rho_pi_steps[12 .. 23];

    # -------------------------------------------------------------------------
    # 2. THETA PHASE 1: STALL-FREE VERTICAL PARITY SUMMATION
    # -------------------------------------------------------------------------
    # We unroll column computations into separate scratch spaces to prevent
    # Read-After-Write hazards. All lookups are strictly concatenated outside strings.
    $code .= "    // --- Phase 1: Column Parity Accumulation ---\n";
    for my $c (0 .. 4) {
        $code .= "    eor3  " . $theta_chi_tmp_v[$c] . ".16b, "
                       . $Av[$c][0] . ".16b, "
                       . $Av[$c][1] . ".16b, "
                       . $Av[$c][2] . ".16b\n";
    }

    # We separate the final accumulation pass to allow the execution pipelines
    # to absorb the preceding write latency.
    for my $c (0 .. 4) {
        $code .= "    eor3  " . $theta_chi_tmp_v[$c] . ".16b, "
                       . $theta_chi_tmp_v[$c] . ".16b, "
                       . $Av[$c][3] . ".16b, "
                       . $Av[$c][4] . ".16b\n";
    }

    # -------------------------------------------------------------------------
    # 3. THETA PHASE 2: PRE-COMPUTE COLUMN MIXING FACTORS (D[x])
    # -------------------------------------------------------------------------
    # Compute the neighborhood parities via RAX1. We stagger targets
    # using dedicated scratchpad allocations to eliminate pipeline bubbles.
    $code .= "\n    // --- Phase 2: Compute Mixing Words ---\n";
    for my $c (0 .. 4) {
        my $prev = ($c + 4) % 5;
        my $next = ($c + 1) % 5;
        $code .= "    rax1  " . $theta_d_v[$c] . ".2d, "
                       . $theta_chi_tmp_v[$prev] . ".2d, "
                       . $theta_chi_tmp_v[$next] . ".2d\n";
    }

    # -------------------------------------------------------------------------
    # 4. STEP 3: HIGH-PERFORMANCE INTERLEAVED THETA-RHO-PI RECONCILIATION
    # -------------------------------------------------------------------------
    # To hide the 2-3 cycle latency of EOR and XAR instructions, we mix the
    # state row-by-row. While column N applies its parity adjustments, the ALU
    # executes independent XAR operations from the Rho-Pi chain.
    $code .= "\n    // --- Phase 3: Interleaved Execution Engine ---\n";

    # Pre-cache the initial step references outside the loop boundaries
    $code .= "    mov   v30.16b, " . $grp1[0]->{src_reg} . ".16b\n";
    $code .= "    mov   v31.16b, " . $grp2[0]->{src_reg} . ".16b\n";

    for my $y (0 .. 4) {
        my $g1_a = $grp1[$y];      my $g2_a = $grp2[$y];
        my $g1_b = $grp1[$y + 5];  my $g2_b = $grp2[$y + 5];

        # Stream Column 0 updates interleaved with Stream A transformations
        $code .= "    eor   " . $Av[0][$y] . ".16b, " . $Av[0][$y] . ".16b, " . $theta_d_v[0] . ".16b\n";
        $code .= "    xar   " . $g1_a->{dst_reg} . ".2d, " . $g1_a->{dst_reg} . ".2d, " . $g1_a->{src_reg} . ".2d, #" . $g1_a->{imm} . "\n";

        # Stream Column 1 updates interleaved with Stream B transformations
        $code .= "    eor   " . $Av[1][$y] . ".16b, " . $Av[1][$y] . ".16b, " . $theta_d_v[1] . ".16b\n";
        $code .= "    xar   " . $g2_a->{dst_reg} . ".2d, " . $g2_a->{dst_reg} . ".2d, " . $g2_a->{src_reg} . ".2d, #" . $g2_a->{imm} . "\n";

        # Stream Column 2 updates interleaved with advanced pipe tracking
        $code .= "    eor   " . $Av[2][$y] . ".16b, " . $Av[2][$y] . ".16b, " . $theta_d_v[2] . ".16b\n";
        $code .= "    xar   " . $g1_b->{dst_reg} . ".2d, " . $g1_b->{dst_reg} . ".2d, " . $g1_b->{src_reg} . ".2d, #" . $g1_b->{imm} . "\n";

        # Stream Column 3 and Column 4 safely distributed
        $code .= "    eor   " . $Av[3][$y] . ".16b, " . $Av[3][$y] . ".16b, " . $theta_d_v[3] . ".16b\n";
        $code .= "    xar   " . $g2_b->{dst_reg} . ".2d, " . $g2_b->{dst_reg} . ".2d, " . $g2_b->{src_reg} . ".2d, #" . $g2_b->{imm} . "\n";

        $code .= "    eor   " . $Av[4][$y] . ".16b, " . $Av[4][$y] . ".16b, " . $theta_d_v[4] . ".16b\n\n";
    }

    # Process remaining tail steps (Indices 10 and 11) to balance pipeline depletion
    for my $i (10 .. 10) {
        my $g1 = $grp1[$i]; my $g2 = $grp2[$i];
        $code .= "    xar   " . $g1->{dst_reg} . ".2d, " . $g1->{dst_reg} . ".2d, " . $g1->{src_reg} . ".2d, #" . $g1->{imm} . "\n";
        $code .= "    xar   " . $g2->{dst_reg} . ".2d, " . $g2->{dst_reg} . ".2d, " . $g2->{src_reg} . ".2d, #" . $g2->{imm} . "\n";
    }

    # Resolve boundary terminations via the initial setup caches (v30 / v31)
    my $g1_last = $grp1[-1];
    my $g2_last = $grp2[-1];
    $code .= "    xar   " . $g1_last->{dst_reg} . ".2d, " . $g1_last->{dst_reg} . ".2d, v31.2d, #" . $g1_last->{imm} . "\n";
    $code .= "    xar   " . $g2_last->{dst_reg} . ".2d, " . $g2_last->{dst_reg} . ".2d, v30.2d, #" . $g2_last->{imm} . "\n\n";

    # -------------------------------------------------------------------------
    # 5. CHI & IOTA NON-LINEAR INTERLEAVING
    # -------------------------------------------------------------------------
    # To bypass RAW stalls on back-to-back BCAX instructions, we load and
    # map row modifications using an alternating double-buffer register layout.
    $code .= "    // --- Phase 4: Non-Linear Confusion Pipeline ---\n";

    for my $r (0 .. 4) {
        my $c0 = $Av[0][$r]; my $c1 = $Av[1][$r]; my $c2 = $Av[2][$r]; my $c3 = $Av[3][$r]; my $c4 = $Av[4][$r];

        # Duplicate the row boundary states to prevent cyclic pipeline bubbles
        $code .= "    mov   v30.16b, " . $c0 . ".16b\n";
        $code .= "    mov   v31.16b, " . $c1 . ".16b\n";

        # Order the BCAX transformations so they execute without instruction dependencies
        $code .= "    bcax  " . $c0 . ".16b, " . $c0 . ".16b, " . $c2 . ".16b, " . $c1 . ".16b\n";
        $code .= "    bcax  " . $c1 . ".16b, " . $c1 . ".16b, " . $c3 . ".16b, " . $c2 . ".16b\n";
        $code .= "    bcax  " . $c2 . ".16b, " . $c2 . ".16b, " . $c4 . ".16b, " . $c3 . ".16b\n";
        $code .= "    bcax  " . $c3 . ".16b, " . $c3 . ".16b, v30.16b, " . $c4 . ".16b\n";
        $code .= "    bcax  " . $c4 . ".16b, " . $c4 . ".16b, v31.16b, " . $c0 . ".16b\n";

        # Inject the Iota Round Constant to Row 0 exclusively
        if ($r == 0) {
            $code .= "    eor   " . $c0 . ".16b, " . $c0 . ".16b, " . $round_const . ".16b\n";
        }
        $code .= "\n";
    }
}

}

# Perform 24 Keccak-f[1600] rounds performing 2 permutations in parallel
sub permutation {
    my ($tag) = @_;
$code .= <<___;
    adrp $round_constants_ptr, .Lround_constants_table
    add $round_constants_ptr, $round_constants_ptr, :lo12:.Lround_constants_table
    mov $round_count, #24
.align 4
$round_label:
    ldr $round_constant, [$round_constants_ptr], #16
____
    keccak1600x2_round($round_constant);
$code .= <<___;
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
        if ($args{layout} eq 'interleaved') {
            generate_interleaved_absorb_pipeline($args{rate}, 1);
        } else {
            generate_uninterleaved_absorb_pipeline($args{rate}, 1);
        }
    } elsif ($args{mode} eq 'update') {
        load_state();
        if (($args{interleaved} // 0) == 1) {
            generate_interleaved_absorb_pipeline($args{rate}, 0);
        } else {
            generate_uninterleaved_absorb_pipeline($args{rate}, 0);
        }
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

# The API supports passing input into the absorb in either interleaved format
# or non interleaved format.
# In interleaved format the input is repeats of 64 bits for lane0 followed by
# 64 bits for lane1 (This is the internal format required by the hardware).
# For non interleaved format, it needs to do a bit more processing in order to
# reorder into interleaved format.
# All inputs are assumed to be 16 byte aligned, and are full blocks of size
# 2 * X bytes (where X is 136 for SHAKE128 and 168 for SHAKE256).
generate_function(name => 'ossl_shake128x2_absorb_init_armv8',   mode => 'init',   rate => 21, interleaved => 1);
generate_function(name => 'ossl_shake128x2_absorb_update_armv8', mode => 'update', rate => 21, interleaved => 1);
generate_function(name => 'ossl_shake256x2_absorb_init_armv8',   mode => 'init',   rate => 17, interleaved => 1);
generate_function(name => 'ossl_shake256x2_absorb_update_armv8', mode => 'update', rate => 17, interleaved => 1);
generate_function(name => 'ossl_shake128x2_ni_absorb_init_armv8',   mode => 'init',   rate => 21);
generate_function(name => 'ossl_shake128x2_ni_absorb_update_armv8', mode => 'update', rate => 21);
generate_function(name => 'ossl_shake256x2_ni_absorb_init_armv8',   mode => 'init',   rate => 17);
generate_function(name => 'ossl_shake256x2_ni_absorb_update_armv8', mode => 'update', rate => 17);
# Used for shake and only operates on the state matrix which must be 16 byte aligned.
generate_function(name => 'ossl_shakex2_permute_armv8', mode => 'permute');


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





.type   KeccakF16002x_cext,%function
.align  5
KeccakF16002x_cext:
    AARCH64_SIGN_LINK_REGISTER
    stp x29,x30,[sp,#-80]!
    add x29,sp,#0
    stp d8,d9,[sp,#16]      // per ABI requirement
    stp d10,d11,[sp,#32]
    stp d12,d13,[sp,#48]
    stp d14,d15,[sp,#64]
___
for($i=0; $i<24; $i+=2) {       # load A[5][5]
my $j=$i+1;
$code.=<<___;
    ldp q$i,q$j,[x0,#16*$i]
___
}
$code.=<<___;
    ldr q24,[x0,#16*$i]
    bl  KeccakF16002x_ce
    ldr x30,[sp,#8]
___
for($i=0; $i<24; $i+=2) {       # store A[5][5]
my $j=$i+1;
$code.=<<___;
    stp q$i,q$j,[x0,#16*$i]
___
}
$code.=<<___;
    str q24,[x0,#16*$i]

    ldp d8,d9,[sp,#16]
    ldp d10,d11,[sp,#32]
    ldp d12,d13,[sp,#48]
    ldp d14,d15,[sp,#64]
    ldr x29,[sp],#80
    AARCH64_VALIDATE_LINK_REGISTER
    ret
.size   KeccakF16002x_cext,.-KeccakF1600_cext
___

{
my ($ctx,$inp,$bsz) = map("x$_",(0..3));

# Absorb 4 parallel lanes of state into vectors in A[i/5][i%5].
# This is used to absorb input into the state 'rate' data (Basically an XOR)
# It passes in 4 'i' indexes.
# It assumes $ctx holds the state. This value is incremented by 64.
# It assumes $inp holds 2 interleaved lanes of 64 bit data. This value is incremented by 64.
# It attempts to interleave instructions to reduce stalls
sub absorb_4_lanes {
    my ($i, $j, $k, $l) = @_;
$code.=<<___;
    ldp q28, q29, [$inp], #32
    ldp $Aq[$i/5][$i%5],$Aq[$j/5][$j%5],[$ctx], #32
    ldp q30, q31, [$inp], #32
    ldp $Aq[$k/5][$k%5],$Aq[$l/5][$l%5],[$ctx]
#ifdef __AARCH64EB__
    rev64 v28.16b,v28.16b
    rev64 v29.16b,v29.16b
    rev64 v30.16b,v30.16b
    rev64 v31.16b,v31.16b
#endif
    sub $ctx, $ctx, #32
    eor_16b($A[$i/5][$i%5], $A[$i/5][$i%5], "v28.2d");
    eor_16b($A[$j/5][$j%5], $A[$j/5][$j%5], "v29.2d");
    eor_16b($A[$k/5][$k%5], $A[$k/5][$k%5], "v30.2d");
    eor_16b($A[$l/5][$l%5], $A[$l/5][$l%5], "v31.2d");

    stp $Aq[$i/5][$i%5],$Aq[$j/5][$j%5],[$ctx],#32
    stp $Aq[$k/5][$k%5],$Aq[$l/5][$l%5],[$ctx],#32
___
}

# Load 4*2 parallel lanes of state into vectors in A[i/5][i%5].
# This is used to load the state 'capacity' data.
# It passes in 4 'i' indexes.
# It assumes $ctx holds the state. This value is incremented by 64.
sub load_capacity_4_lanes {
    my ($i, $j, $k, $l) = @_;
$code.=<<___;
    ldp     $Aq[$i/5][$i%5], $Aq[$j/5][$j%5], [$ctx], #32
    ldp     $Aq[$k/5][$k%5], $Aq[$l/5][$l%5], [$ctx], #32
___
}

# Absorb 1*2 parallel lanes of state into vectors in A[i/5][i%5].
# This is used to absorb input into the tail of the state 'rate' data (Basically an XOR)
# It passes in 1 'i' index.
# It assumes $ctx holds the state. This value is incremented by 16.
# It assumes $inp holds 1*2 interleaved lanes of 64 bit data. This value is incremented by 16.
sub absorb_tail_lane {
    my ($i) = @_;
$code.=<<___;
    ldr     q31, [$inp]                 // Fetch input for tail lane
    ldr     $Aq[$i/5][$i%5],[$ctx]      // Fetch matrix state for tail 16
#ifdef __AARCH64EB__
    rev64   v31.16b, v31.16b
#endif
    eor_16b($A[$i/5][$i%5], $A[$i/5][$i%5], "v31.2d");
    eor v31.16b,v31.16b,v30.16b
    str q31,[$ctx],#16
___
}

# Assumptions:
# - code is specifically written for SHAKE128 and SHAKE256
# - The input is interleaved in 2 lanes of 64 bits.
#   For shake128 bsz=168, and the input buffer has a size of 2*21*64bits
#   For shake256 bsz=136, and the input buffer has a size of 2*17*64bits.
# - len is not used, so only single blocks are supported.
$code.=<<___;
.globl  ossl_shake_absorb2x_interleaved_block
.type   ossl_shake_absorb2x_interleaved_block,%function
.align  5
ossl_shake_absorb2x_interleaved_block:
    AARCH64_SIGN_LINK_REGISTER
    stp x29,x30,[sp,#-80]!
    add x29,sp,#0
    stp d8,d9,[sp,#16]      // per ABI requirement
    stp d10,d11,[sp,#32]
    stp d12,d13,[sp,#48]
    stp d14,d15,[sp,#64]
___
    absorb_4_lanes(0,1,2,3);
    absorb_4_lanes(4,5,6,7);
    absorb_4_lanes(8,9,10,11);
    absorb_4_lanes(12,13,14,15);
$code.=<<___;
    cmp $bsz, #136
    b.eq    .Lpath_shake256_a2xib
#tail_shake128
___
    absorb_4_lanes(16,17,18,19);
    absorb_tail_lane(20);
$code.=<<___;
    b .Lfinish_a2xib
.Lpath_shake256_a2xib:
___
    absorb_tail_lane(16);
    load_capacity_4_lanes(17,18,19,20);
$code.=<<___;
.Lfinish_a2xib:
___
    load_capacity_4_lanes(21,22,23,24);
$code.=<<___;
    bl  KeccakF16002x_ce
    ldp d8,d9,[sp,#16]
    ldp d10,d11,[sp,#32]
    ldp d12,d13,[sp,#48]
    ldp d14,d15,[sp,#64]
    ldp x29,x30,[sp],#80
    AARCH64_VALIDATE_LINK_REGISTER
    ret
.size   ossl_shake_absorb2x_interleaved_block,.-ossl_shake_absorb2x_interleaved_block
___
}
