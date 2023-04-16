#include <stdint.h>
#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include "./libnet_test.h"

#include <assert.h>

#define DEVICE_NAME "lo"

int
main(int argc, char *argv[])
{
    (void)argc;                                     /* unused */

    int c;
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    size_t udld_payload_size = 0;

    l = libnet_init(LIBNET_LINK, DEVICE_NAME, errbuf);
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        return (EXIT_FAILURE);
    }

    /* [TLV SEQUENCE NUMBER ]*/
    const uint32_t sequence_number = 1;
    t = libnet_build_udld_sequence_number((const uint8_t *)&sequence_number, l, 0);
    if (t == (-1))
    {
        fprintf(stderr, "Cannot build UDLD Sequence Number TLV: %s\n", libnet_geterror(l));
        goto bad;
    }
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint32_t));

    /* [TLV DEVICE NAME ]*/
    const char *device_name_str = "S1";
    t = libnet_build_udld_device_name((const uint8_t *)device_name_str, strlen(device_name_str), l, 0);
    if (t == (-1))
    {
        fprintf(stderr, "Cannot build UDLD Device Name TLV: %s\n", libnet_geterror(l));
        goto bad;
    }
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + strlen(device_name_str));

    /* [TLV TIMEOUT INTERVAL ]*/
    const uint8_t timeout_interval = 5;
    t = libnet_build_udld_timeout_interval(&timeout_interval, l, 0);
    if (t == (-1))
    {
        fprintf(stderr, "Cannot build UDLD Timeout Interval TLV: %s\n", libnet_geterror(l));
        goto bad;
    }
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint8_t));

    /* [TLV MESSAGE INTERVAL ]*/
    const uint8_t message_interval = 7;
    t = libnet_build_udld_message_interval(&message_interval, l, 0);
    if (t == (-1))
    {
        fprintf(stderr, "Cannot build UDLD Message Interval TLV: %s\n", libnet_geterror(l));
        goto bad;
    }
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint8_t));

    /* [ TLV ECHO ] */
    const uint8_t echo_id_pairs[] = {0x0, 0x0, 0x0, 0x0};
    t = libnet_build_udld_echo(echo_id_pairs, (sizeof(echo_id_pairs)/sizeof(echo_id_pairs[0])), l, 0);
    if (t == (-1))
    {
        fprintf(stderr, "Cannot build UDLD Echo TLV: %s\n", libnet_geterror(l));
        goto bad;
    }
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + (sizeof(echo_id_pairs)/sizeof(echo_id_pairs[0])));

    /* [ TLV PORT ID ] */
    const char *port_id_str = "Gi0/1";
    t = libnet_build_udld_port_id((const uint8_t *)port_id_str, strlen(port_id_str), l, 0);
    if (t == (-1))
    {
        fprintf(stderr, "Cannot build UDLD Port ID TLV: %s\n", libnet_geterror(l));
        goto bad;
    }
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + strlen(port_id_str));

    /* [ TLV DEVICE ID ] */
    const char *device_id_str = "FOC1031Z7JG";
    t = libnet_build_udld_device_id((const uint8_t *)device_id_str, strlen(device_id_str), l, 0);
    if (t == (-1))
    {
        fprintf(stderr, "Cannot build UDLD Device ID TLV: %s\n", libnet_geterror(l));
        goto bad;
    }
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + strlen(device_id_str));

    assert((udld_payload_size == 56) && "Incorrect UDLD payload size\n");

    int flags = (LIBNET_UDLD_FLAG_RT | LIBNET_UDLD_FLAG_RSY);
    t = libnet_build_udld_hdr(LIBNET_UDLD_PDU_VERSION,      /* version */
                              LIBNET_UDLD_PDU_OPCODE_PROBE, /* opcode */
                              flags,                        /* flags */
                              0,                            /* checksum */
                              NULL,                         /* payload */
                              0,                            /* payload_s */
                              l, 0);
    if (t == -1)
    {
        fprintf(stderr, "Can't build UDLD: %s\n", libnet_geterror(l));
        goto bad;
    }

    uint8_t OUI[3] = LIBNET_UDLD_OID;
    t = libnet_build_802_2snap(0xAA,                            /* DSAP      */
                               0xAA,                            /* SSAP      */
                               0x03,                            /* Control   */
                               OUI,                             /* OUI       */
                               LIBNET_UDLD_HDLC_PROTO_TYPE,     /* Type      */
                               NULL,                            /* Payload   */
                               0,                               /* Payload_s */
                               l,
                               0);

    uint8_t udld_dst_mac[6] = LIBNET_UDLD_DEST_MAC;
    uint8_t udld_src_mac_dummy[6] = { 0x00, 0x19, 0x06, 0xEA, 0xB8, 0x81 };
    t = libnet_build_802_3(udld_dst_mac,                                            /* ethernet destination */
                           udld_src_mac_dummy,                                      /* ethernet source */
                           LIBNET_802_2SNAP_H +                                     /* */
                           LIBNET_UDLD_H + udld_payload_size,                       /* */
                           NULL,                                                    /* payload */
                           0,                                                       /* payload size */
                           l,                                                       /* libnet context */
                           0);                                                      /* libnet ptag */
    if (t == -1)
    {
        fprintf(stderr, "Can't build 802.3 header: %s\n", libnet_geterror(l));
        goto bad;
    }

    /* write the packet out */
    c = libnet_write(l);
    if (c == -1)
    {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
        goto bad;
    }
    else
    {
        fprintf(stderr, "Wrote %d byte LLDP frame \"%s\"\n", c, argv[2]);
    }

    libnet_destroy(l);
    return (EXIT_SUCCESS);
  bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
}
