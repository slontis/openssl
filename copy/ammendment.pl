sub load_initial_rate_uninterleaved {

    my ($rate_bytes) = @_;

    # x1 -> msg 0

    # x2 -> msg 1, located rate_bytes after msg 0

    $code .= "    add x2, x1, #$rate_bytes\n";

    # Use the same destination order as the existing interleaved path.

    my @rate_q = (

        $Aq[0][0], $Aq[1][0], $Aq[2][0], $Aq[3][0], $Aq[4][0],

        $Aq[0][1], $Aq[1][1], $Aq[2][1], $Aq[3][1], $Aq[4][1],

        $Aq[0][2], $Aq[1][2], $Aq[2][2], $Aq[3][2], $Aq[4][2],

        $Aq[0][3], $Aq[1][3], $Aq[2][3], $Aq[3][3], $Aq[4][3],

        $Aq[0][4],

    );

    for (my $i = 0; $i < @rate_q; $i++) {

        my $off = $i * 8;

        $code .= <<___;

    ldr d20, [x1, #$off]

    ldr d21, [x2, #$off]

    zip1 $rate_q[$i].2d, v20.2d, v21.2d

___

    }

    # Same zeroing/padding tail handling you already had.

    if ($rate_bytes == 136) {

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

    } else {

        $code .= <<___;

    eor $Av[1][4].16b, $Av[1][4].16b, $Av[1][4].16b

    eor $Av[2][4].16b, $Av[2][4].16b, $Av[2][4].16b

    eor $Av[3][4].16b, $Av[3][4].16b, $Av[3][4].16b

    eor $Av[4][4].16b, $Av[4][4].16b, $Av[4][4].16b

___

    }

}

sub xor_rate_uninterleaved {

    my ($rate_bytes) = @_;

    $code .= "    add x2, x1, #$rate_bytes\n";

    my @rate_q = (

        $Av[0][0], $Av[1][0], $Av[2][0], $Av[3][0], $Av[4][0],

        $Av[0][1], $Av[1][1], $Av[2][1], $Av[3][1], $Av[4][1],

        $Av[0][2], $Av[1][2], $Av[2][2], $Av[3][2], $Av[4][2],

        $Av[0][3], $Av[1][3], $Av[2][3], $Av[3][3], $Av[4][3],

        $Av[0][4],

    );

    for (my $i = 0; $i < @rate_q; $i++) {

        my $off = $i * 8;

        $code .= <<___;

    ldr d20, [x1, #$off]

    ldr d21, [x2, #$off]

    zip1 v22.2d, v20.2d, v21.2d

    eor $rate_q[$i].16b, $rate_q[$i].16b, v22.16b

___

    }

}
