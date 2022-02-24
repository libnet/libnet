#include <stdio.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>

/* A test case that does nothing and succeeds. */
static void bool_always_success(void **state) {
    (void) state; /* unused */

    bool this_is_true = true;

    assert_true(this_is_true);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(bool_always_success),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
