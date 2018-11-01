#include <stdio.h>
#include <string.h>
#include "self_test_lcl.h"

int self_test_is_corrupt_cb(const char *type, const char *desc)
{
    //fprintf(stdout, "Corrupt ");
    return 0;
}

void self_test_cb(const char *type, const char *desc, const char *state)
{
    if (strncmp(state, "start", 5) == 0)
        fprintf(stdout, "%s %s ", type, desc);
    else
        fprintf(stdout, "%s\n", state);
}
