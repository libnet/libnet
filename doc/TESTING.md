TESTING
===

Unit Testing
------------
For Unit Testing the [cmocka](https://cmocka.org/) is used. Unit Tests resides in `tests\unit_tests.c`.

Lets see the example of how to add the test for `libnet_build_ethernet` function.

1. In `tests\unit_tests.c` add `test_libnet_build_ethernet` function. In this function implement all neccessary logic.
```c
static void
test_libnet_build_ethernet(void **state)
{
    (void)state;    /* unused */

    ...
}
```

2. Let to the `cmocka` to run this function. Add the test to the `tests[]`
```c
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_libnet_build_ethernet),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

3. Compile and Run. See `Running Unit Tests with CMocka` in README
