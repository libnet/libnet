// clang-format off
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <libnet.h>
// clang-format on

/******************************************************************************
 *
 * LOCAL HELPERS
 *
 *****************************************************************************/

static void
print_err_buf(const char *err_buf)
{
    fprintf(stdout, "[ERROR]: %s\n", err_buf);
    exit(EXIT_FAILURE);
}

/******************************************************************************
 *
 * END OF LOCAL HELPERS
 *
 *****************************************************************************/

static void
test_libnet_build_ethernet(void **state)
{
    (void)state;                                    /* unused */

    libnet_ptag_t eth_ptag = (-1);
    struct libnet_ethernet_hdr *eth_hdr = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    uint8_t *header = NULL;
    uint32_t header_size = 0;
    uint8_t mac_dst[ETHER_ADDR_LEN] = { 0x11, 0x11, 0x11, 0x22, 0x22, 0x22 };
    uint8_t mac_src[ETHER_ADDR_LEN] = { 0x44, 0x44, 0x44, 0x55, 0x55, 0x55 };
    int rv = (-1);

    libnet_t *l = libnet_init(LIBNET_LINK_ADV,  /* enable advanced mode */
                              NULL,                 /* interface */
                              errbuf);              /* error buffer */

    if (NULL == l)
    {
        print_err_buf(errbuf);
    }
    assert_non_null(l);

    eth_ptag = libnet_build_ethernet(mac_dst,       /* destination ethernet address */
                                     mac_src,       /* source ethernet address */
                                     ETHERTYPE_IP,  /* upper layer protocol type */
                                     NULL,          /* payload */
                                     0,             /* payload length */
                                     l,             /* libnet context */
                                     0);            /* protocol tag */
    if ((-1) == eth_ptag)
    {
        print_err_buf(errbuf);
    }
    assert_int_not_equal(eth_ptag, (-1));

    rv = libnet_adv_cull_header(l,                  /* libnet context */
                                eth_ptag,           /* protocol tag */
                                &header,            /* header */
                                &header_size);      /* header size */
    if ((-1) == rv)
    {
        print_err_buf(errbuf);
    }
    assert_int_not_equal(eth_ptag, (-1));
    assert_int_not_equal(header_size, 0);

    eth_hdr = (struct libnet_ethernet_hdr *)header;
    assert_int_equal(eth_hdr->ether_type, htons(ETHERTYPE_IP));

    // Compare source macs
    for (uint8_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        assert_int_equal(eth_hdr->ether_shost[i], mac_src[i]);
    }

    // Compare destination macs
    for (uint8_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        assert_int_equal(eth_hdr->ether_dhost[i], mac_dst[i]);
    }

    libnet_destroy(l);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_libnet_build_ethernet),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
