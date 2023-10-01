TESTING
=======

Unit Testing
------------

For Unit Testing [CMocka](https://cmocka.org/) is used.  Unit Tests
resides in the `test/` subdirectory.

Example of how to add a test for the `libnet_build_ethernet()` function:

  1. In `test/unit_tests.c` add `test_libnet_build_ethernet`
     function.  In this function implement all logic.

```c
static void
test_libnet_build_ethernet(void **state)
{
    (void)state;    /* unused */

    ...
}
```

  2. Add the test to `tests[]` to let `cmocka` run this function.

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

  3. Compile and Run.  For details, see section [Running Unit Tests with
     CMocka](../README.md#running-unit-tests-with-cmocka) in the README.
