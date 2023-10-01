Unit Testing
============

For Unit Testing [CMocka](https://cmocka.org/) is used.  Unit Tests
resides in the `test/` subdirectory.

Example
------

This is an example of how to add a test for the completely made up
libnet function `libnet_build_foo()`.

First, we create a new file `test/foo.c` where we add a test function
`test_libnet_build_foo()`, which is where all the test logic goes:


```c
static void test_libnet_build_foo(void **state)
{
    (void)state;    /* unused */

    ...
    assert_..._(...);
    ...
}
```

> **Tip:** For help on the various checks you can do, see the [CMocka
> Assert Macros](https://api.cmocka.org/group__cmocka__asserts.html).

Add the test function to `tests[]` to let CMocka run it.  You can have
multiple test functions testing various aspects/APIs of a given module.

```c
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_libnet_build_foo),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

Second, add the new test file to `test/Makefile.am`, in the TESTS
variables, alphabetically:

```Makefile
...
AM_LDFLAGS        = -lcmocka $(top_builddir)/src/libnet.la
TESTS             = ethernet
TESTS            += foo
TESTS            += udld
...
```

Finally, compile and run.  For details, see section [Running Unit Tests
with CMocka](../README.md#running-unit-tests-with-cmocka) in the README.

```bash
~/src/libnet(ethernet-test)$ make check
```
