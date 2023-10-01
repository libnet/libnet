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

/* Helpers */
#define LIBNET_TEST_ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

static uint8_t tlv_length_offset = 2;
static uint8_t tlv_value_offset  = 4;

static void
libnet_build_udld__pdu_header_only(void **state)
{
    (void)state;                                    /* unused */

    int rv = (-1);
    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);

    assert_non_null(l);

    const uint8_t flags = (LIBNET_UDLD_FLAG_RT | LIBNET_UDLD_FLAG_RSY);

    libnet_ptag_t udld_ptag = libnet_build_udld_hdr(LIBNET_UDLD_PDU_VERSION,        /* version */
                                                    LIBNET_UDLD_PDU_OPCODE_PROBE,   /* opcode */
                                                    flags,                          /* flags */
                                                    0,                              /* do checksum */
                                                    NULL,                           /* payload */
                                                    0,                              /* payload length */
                                                    l,                              /* libnet context */
                                                    0);                             /* protocol tag */

    assert_int_not_equal(udld_ptag, (-1));

    uint8_t *header = NULL;
    uint32_t header_size = 0;

    rv = libnet_adv_cull_header(l, udld_ptag, &header, &header_size);
    assert_int_not_equal(rv, (-1));


    struct libnet_udld_hdr *udld_hdr = NULL;

    udld_hdr = (struct libnet_udld_hdr *)header;

    assert_int_equal((udld_hdr->version_opcode >> LIBNET_UDLD_PDU_VERSION_OFFSET), LIBNET_UDLD_PDU_VERSION);
    assert_int_equal((udld_hdr->version_opcode & LIBNET_UDLD_PDU_OPCODE_MASK), LIBNET_UDLD_PDU_OPCODE_PROBE);
    assert_int_equal(udld_hdr->flags, (LIBNET_UDLD_FLAG_RT | LIBNET_UDLD_FLAG_RSY));

    libnet_destroy(l);
}

/* Refs: test/data/packet_captures/UDLD.cap, Packet #1, UDLD Device ID */
static void
libnet_build_udld__tlv_device_id(void **state)
{
    (void)state;                                    /* unused */

    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);
    assert_non_null(l);

    const char *device_id_str = "FOC1031Z7JG";
    libnet_ptag_t udld_tlv_device_id_ptag = libnet_build_udld_device_id((const uint8_t *)device_id_str,
                                                                        strlen(device_id_str),
                                                                        l,
                                                                        0);
    assert_int_not_equal(udld_tlv_device_id_ptag, (-1));

    libnet_pblock_t *p = libnet_pblock_find(l, udld_tlv_device_id_ptag);
    assert_non_null(p);
    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_DEVICE_ID_H);

    const uint16_t *type   = (const uint16_t *)(p->buf);
    const uint16_t *length = (const uint16_t *)(p->buf + tlv_length_offset);
    const uint8_t  *value  = (const uint8_t  *)(p->buf + tlv_value_offset);

    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_DEVICE_ID_H);
    assert_int_equal(ntohs(*type), LIBNET_UDLD_DEVICE_ID);
    assert_int_equal(ntohs(*length), LIBNET_UDLD_TLV_HDR_SIZE + strlen(device_id_str));
    assert_memory_equal(value, (const char []){ "FOC1031Z7JG" }, strlen(device_id_str));

    libnet_destroy(l);
}

/* Refs: test/data/packet_captures/UDLD.cap, Packet #1, UDLD Port ID */
static void
libnet_build_udld__tlv_port_id(void **state)
{
    (void)state; /* unused */
    
    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);
    assert_non_null(l);

    const char *origin_port_id_str = "Gi0/1";
    libnet_ptag_t udld_tlv_port_id_ptag = libnet_build_udld_port_id((const uint8_t *)origin_port_id_str,
                                                                    strlen(origin_port_id_str),
                                                                    l,
                                                                    0);
    assert_int_not_equal(udld_tlv_port_id_ptag, (-1));

    libnet_pblock_t *p = libnet_pblock_find(l, udld_tlv_port_id_ptag);
    assert_non_null(p);
    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_PORT_ID_H);

    const uint16_t *type   = (const uint16_t *)(p->buf);
    const uint16_t *length = (const uint16_t *)(p->buf + tlv_length_offset);
    const uint8_t  *value  = (const uint8_t  *)(p->buf + tlv_value_offset);

    assert_int_equal(ntohs(*type), LIBNET_UDLD_PORT_ID);
    assert_int_equal(ntohs(*length), LIBNET_UDLD_TLV_HDR_SIZE + strlen(origin_port_id_str));
    assert_memory_equal(value, (const char []){ "Gi0/1" }, strlen(origin_port_id_str));

    libnet_destroy(l);
}

/* Refs: test/data/packet_captures/UDLD.cap, Packet #1, UDLD Echo */
static void
libnet_build_udld__tlv_echo(void **state)
{
    (void)state; /* unused */

    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);
    assert_non_null(l);

    const uint8_t original_echo_id_pairs[] = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t expected_echo_id_pairs[] = { 0x01, 0x02, 0x03, 0x04 };
    libnet_ptag_t udld_tlv_echo_ptag = libnet_build_udld_echo(original_echo_id_pairs,
                                                              LIBNET_TEST_ARRAY_LENGTH(original_echo_id_pairs),
                                                              l,
                                                              0);
    assert_int_not_equal(udld_tlv_echo_ptag, (-1));

    libnet_pblock_t *p = libnet_pblock_find(l, udld_tlv_echo_ptag);
    assert_non_null(p);
    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_ECHO_H);

    const uint16_t *type   = (const uint16_t *)(p->buf);
    const uint16_t *length = (const uint16_t *)(p->buf + tlv_length_offset);
    const uint8_t  *value  = (const uint8_t  *)(p->buf + tlv_value_offset);

    assert_int_equal(ntohs(*type), LIBNET_UDLD_ECHO);
    assert_int_equal(ntohs(*length), LIBNET_UDLD_TLV_HDR_SIZE + LIBNET_TEST_ARRAY_LENGTH(original_echo_id_pairs));
    assert_int_equal(ntohs(*length) - 4/* sizeof type and length */, LIBNET_TEST_ARRAY_LENGTH(expected_echo_id_pairs));
    assert_memory_equal(value, expected_echo_id_pairs, LIBNET_TEST_ARRAY_LENGTH(original_echo_id_pairs));

    libnet_destroy(l);
}

/* Refs: test/data/packet_captures/UDLD.cap, Packet #1, UDLD Message Interval */
static void
libnet_build_udld__tlv_message_interval(void **state)
{
    (void)state; /* unused */

    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);
    assert_non_null(l);

    const uint8_t message_interval = 7;
    libnet_ptag_t udld_tlv_message_interval_ptag = libnet_build_udld_message_interval(&message_interval,
                                                                          l,
                                                                          0);
    assert_int_not_equal(udld_tlv_message_interval_ptag, (-1));

    libnet_pblock_t *p = libnet_pblock_find(l, udld_tlv_message_interval_ptag);
    assert_non_null(p);
    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_MSG_INTERVAL_H);

    const uint16_t *type   = (const uint16_t *)(p->buf);
    const uint16_t *length = (const uint16_t *)(p->buf + tlv_length_offset);
    const uint8_t  *value  = (const uint8_t  *)(p->buf + tlv_value_offset);

    assert_int_equal(ntohs(*type), LIBNET_UDLD_MESSAGE_INTERVAL);
    assert_int_equal(ntohs(*length), LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint8_t));
    assert_int_equal(*value, 7);

    libnet_destroy(l);
}

/* Refs: test/data/packet_captures/UDLD.cap, Packet #1, UDLD Timeout Interval */
static void
libnet_build_udld__tlv_timeout_interval(void **state)
{
    (void)state; /* unused */

    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);
    assert_non_null(l);

    const uint8_t timeout_interval = 5;
    libnet_ptag_t udld_tlv_timeout_interval_ptag = libnet_build_udld_timeout_interval(&timeout_interval,
                                                                          l,
                                                                          0);
    assert_int_not_equal(udld_tlv_timeout_interval_ptag, (-1));

    libnet_pblock_t *p = libnet_pblock_find(l, udld_tlv_timeout_interval_ptag);
    assert_non_null(p);
    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_TMT_INTERVAL_H);

    const uint16_t *type   = (const uint16_t *)(p->buf);
    const uint16_t *length = (const uint16_t *)(p->buf + tlv_length_offset);
    const uint8_t  *value  = (const uint8_t  *)(p->buf + tlv_value_offset);

    assert_int_equal(ntohs(*type), LIBNET_UDLD_TIMEOUT_INTERVAL);
    assert_int_equal(ntohs(*length), LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint8_t));
    assert_int_equal(*value, 5);

    libnet_destroy(l);
}

/* Refs: test/data/packet_captures/UDLD.cap, Packet #1, UDLD Device Name */
static void
libnet_build_udld__tlv_device_name(void **state)
{
    (void)state; /* unused */

    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);
    assert_non_null(l);

    const char *device_name_str = "S1";
    libnet_ptag_t udld_tlv_device_name_ptag = libnet_build_udld_device_name((const uint8_t *)device_name_str,
                                                                            strlen(device_name_str),
                                                                            l,
                                                                            0);
    assert_int_not_equal(udld_tlv_device_name_ptag, (-1));

    libnet_pblock_t *p = libnet_pblock_find(l, udld_tlv_device_name_ptag);
    assert_non_null(p);
    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_DEVICE_NAME_H);

    const uint16_t *type   = (const uint16_t *)(p->buf);
    const uint16_t *length = (const uint16_t *)(p->buf + tlv_length_offset);
    const uint8_t  *value  = (const uint8_t  *)(p->buf + tlv_value_offset);

    assert_int_equal(ntohs(*type), LIBNET_UDLD_DEVICE_NAME);
    assert_int_equal(ntohs(*length), LIBNET_UDLD_TLV_HDR_SIZE + strlen(device_name_str));
    assert_memory_equal(value, (const uint8_t []){ "S1" }, strlen(device_name_str));

    libnet_destroy(l);
}

/* Refs: test/data/packet_captures/UDLD.cap, Packet #1, UDLD Sequence Number */
static void
libnet_build_udld__tlv_sequence_number(void **state)
{
    (void)state; /* unused */

    char errbuf[LIBNET_ERRBUF_SIZE];

    libnet_t *l = libnet_init(LIBNET_NONE, NULL, errbuf);
    assert_non_null(l);

    const uint32_t sequence_number = 1;
    libnet_ptag_t udld_tlv_sequence_number_ptag = libnet_build_udld_sequence_number((const uint8_t *)&sequence_number,
                                                                                    l,
                                                                                    0);
    assert_int_not_equal(udld_tlv_sequence_number_ptag, (-1));

    libnet_pblock_t *p = libnet_pblock_find(l, udld_tlv_sequence_number_ptag);
    assert_non_null(p);
    assert_int_equal(p->type, LIBNET_PBLOCK_UDLD_SEQ_NUMBER_H);

    const uint16_t *type   = (const uint16_t *)(p->buf);
    const uint16_t *length = (const uint16_t *)(p->buf + tlv_length_offset);
    const uint32_t *value  = (const uint32_t *)(p->buf + tlv_value_offset);

    assert_int_equal(ntohs(*type), LIBNET_UDLD_SEQUENCE_NUMBER);
    assert_int_equal(ntohs(*length), LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint32_t));
    assert_int_equal(ntohl(*value), 1);

    libnet_destroy(l);
}


static void
libnet_udld__checksum_calculation(void **state)
{
    (void)state; /* unused */

    const uint8_t original_packet_hex[] = {
        0x01,0x00,0x0c,0xcc,0xcc,0xcc,0x00,0x19,0x06,0xea,0xb8,0x81,0x00,0x44,       /* 14 bytes: IEEE 802.3 Ethernet      */
        0xaa,0xaa,0x03,0x00,0x00,0x0c,0x01,0x11,                                     /* 8  bytes: LLC                      */
        0x21,                                                                        /* 1  bytes: UDLD: version and opcode */ 
        0x03,                                                                        /* 1  bytes: UDLD: flags              */
        0x00,0x00,                                                                   /* 2  bytes: UDLD: checksum           */
        0x00,0x01,0x00,0x0f,0x46,0x4f,0x43,0x31,0x30,0x33,0x31,0x5a,0x37,0x4a,0x47,  /* 15 bytes: UDLD: Device ID          */
        0x00,0x02,0x00,0x09,0x47,0x69,0x30,0x2f,0x31,                                /* 9  bytes: UDLD: Port ID            */
        0x00,0x03,0x00,0x08,0x00,0x00,0x00,0x00,                                     /* 8  bytes: UDLD: Echo               */
        0x00,0x04,0x00,0x05,0x07,                                                    /* 5  bytes: UDLD: Message Interval   */
        0x00,0x05,0x00,0x05,0x05,                                                    /* 5  bytes: UDLD: Timeout Interval   */
        0x00,0x06,0x00,0x06,0x53,0x31,                                               /* 6  bytes: UDLD: Device Name        */
        0x00,0x07,0x00,0x08,0x00,0x00,0x00,0x01                                      /* 8  bytes: UDLD: Sequence Number    */
    };

    const uint16_t expected_checksum = 0x6d85;
    const uint16_t checksum = libnet_ip_check((uint16_t *)original_packet_hex + 11, /* UDLD packet offset*/
                                                                                60  /* remaining bytes   */
                                             );
    assert_int_equal(expected_checksum, htons(checksum));
}

/**
 * Build the whole UDLD packet, including the payload and IEEE802.3 Ethernet + LLC headers.
 *
 * Refs: test/data/packet_captures/UDLD.cap, Packet #2
*/
static void
libnet_build_udld__build_whole_packet_with_checksum(void **state)
{
    (void)state; /* unused */

    libnet_t *l                              = NULL;
    libnet_ptag_t udld_ptag                  = 0;
    libnet_ptag_t udld_device_id_tlv_ptag    = 0;
    libnet_ptag_t udld_port_id_tlv_ptag      = 0;
    libnet_ptag_t udld_echo_id_tlv_ptag      = 0;
    libnet_ptag_t udld_message_interval_ptag = 0;
    libnet_ptag_t udld_timeout_interval_ptag = 0;
    libnet_ptag_t udld_device_name_ptag      = 0;
    libnet_ptag_t udld_sequence_number_ptag  = 0;
    libnet_ptag_t ieee_802_2_llc_ptag        = 0;
    libnet_ptag_t ieee_802_3_ptag            = 0;
    uint32_t udld_payload_size               = 0;
    char error_buffer[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_NONE, NULL, error_buffer);
    assert_non_null(l);

    /* Build UDLD */

    /* Build UDLD Sequence Number TLV */
    const uint32_t sequence_number = 1;
    udld_sequence_number_ptag = libnet_build_udld_sequence_number((const uint8_t *)&sequence_number,
                                                                  l,
                                                                  0
    );
    assert_int_not_equal(udld_sequence_number_ptag, (-1));
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint32_t));

    /* Build UDLD Device Name TLV */
    const char *device_name_str = "S2";
    udld_device_name_ptag = libnet_build_udld_device_name((const uint8_t *)device_name_str,
                                                          strlen(device_name_str),
                                                          l,
                                                          0
    );
    assert_int_not_equal(udld_device_name_ptag, (-1));
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + strlen(device_name_str));

    /* Build UDLD Timeout Interval TLV */
    const uint8_t timeout_interval = 5;
    udld_timeout_interval_ptag = libnet_build_udld_timeout_interval(&timeout_interval,
                                                                    l,
                                                                    0
    );
    assert_int_not_equal(udld_timeout_interval_ptag, (-1));
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint8_t));

    /* Build UDLD Message Interval TLV */
    const uint8_t message_interval = 7;
    udld_message_interval_ptag = libnet_build_udld_message_interval(&message_interval,
                                                                    l,
                                                                    0
    );
    assert_int_not_equal(udld_message_interval_ptag, (-1));
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + sizeof(uint8_t));

    /* Build UDLD Echo TLV */
    const uint8_t echo_id_pairs[] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x0b,
                                     0x46, 0x4f, 0x43, 0x31, 0x30, 0x33,
                                     0x31, 0x5a, 0x37, 0x4a, 0x47, 0x00,
                                     0x05, 0x47, 0x69, 0x30, 0x2f, 0x31};
    udld_echo_id_tlv_ptag = libnet_build_udld_echo(echo_id_pairs,
                                                   LIBNET_TEST_ARRAY_LENGTH(echo_id_pairs),
                                                   l,
                                                   0
    );
    assert_int_not_equal(udld_echo_id_tlv_ptag, (-1));
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + sizeof(echo_id_pairs));

    /* Build UDLD Port ID TLV */
    const char *port_id_str = "Fa0/1";
    udld_port_id_tlv_ptag = libnet_build_udld_port_id((const uint8_t *)port_id_str,
                                                       strlen(port_id_str),
                                                       l,
                                                       0
    );
    assert_int_not_equal(udld_port_id_tlv_ptag, (-1));
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + strlen(port_id_str));

    /* Build UDLD Device ID TLV */
    const char *device_id_str = "FOC1025X4W3";
    udld_device_id_tlv_ptag = libnet_build_udld_device_id((const uint8_t *)device_id_str,
                                                          strlen(device_id_str),
                                                          l,
                                                          0
    );
    assert_int_not_equal(udld_device_id_tlv_ptag, (-1));
    udld_payload_size += (LIBNET_UDLD_TLV_HDR_SIZE + strlen(device_id_str));

    assert_int_equal(udld_payload_size, 76);

    int flags = 0;
    udld_ptag = libnet_build_udld_hdr(
                                    LIBNET_UDLD_PDU_VERSION,       /* version */
                                    LIBNET_UDLD_PDU_OPCODE_ECHO,   /* opcode */
                                    flags,                         /* flags */
                                    0,                             /* checksum */
                                    NULL,                          /* payload*/
                                    0,                             /* payload_s */
                                    l,                             /* libnet context */
                                    0                              /* libnet ptag */
    );
    assert_int_not_equal(udld_ptag, (-1));

    /* Build IEEE 802.2 snap LLC */
    uint8_t OUI[3] = LIBNET_UDLD_OID;
    ieee_802_2_llc_ptag = libnet_build_802_2snap(0xAA,                            /* DSAP      */
                                                 0xAA,                            /* SSAP      */
                                                 0x03,                            /* Control   */
                                                 OUI,                             /* OUI       */
                                                 LIBNET_UDLD_HDLC_PROTO_TYPE,     /* Type      */
                                                 NULL,                            /* Payload   */
                                                 0,                               /* Payload_s */
                                                 l,
                                                 0
    );
    assert_int_not_equal(ieee_802_2_llc_ptag, (-1));

    /* Build IEEE 802.3 */
    uint8_t udld_dst_mac[6]       = LIBNET_UDLD_DEST_MAC;
    uint8_t udld_src_mac_dummy[6] = { 0x00, 0x19, 0x06, 0xEA, 0xB8, 0x81 };
    ieee_802_3_ptag = libnet_build_802_3(udld_dst_mac,                                            /* ethernet destination */
                                         udld_src_mac_dummy,                                      /* ethernet source */
                                         LIBNET_802_2SNAP_H +                                     /* */
                                         LIBNET_UDLD_H + udld_payload_size,                       /* */
                                         NULL,                                                    /* payload */
                                         0,                                                       /* payload size */
                                         l,                                                       /* libnet context */
                                         0
    );
    assert_int_not_equal(ieee_802_3_ptag, (-1));

    /**
     * Assembly packet.
     * Verify checksum correctness.
     * */
    {
        uint8_t *packet        = NULL;
        uint32_t packet_length = 0;
        int rv                 = (-1);

        /* like libnet_write but only assembly packet, NOT sending it to the network */
        rv = libnet_pblock_coalesce(l, &packet, &packet_length);
        assert_int_not_equal(rv, UINT32_MAX);

        struct libnet_udld_hdr *udld_hdr = (struct libnet_udld_hdr *)(packet + (LIBNET_802_3_H + LIBNET_802_2SNAP_H));

        const uint32_t expected_checksum = 0x805d;
        assert_int_equal(htons(udld_hdr->checksum), expected_checksum);
    }

    libnet_destroy(l);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(libnet_udld__checksum_calculation),

        cmocka_unit_test(libnet_build_udld__pdu_header_only),
        cmocka_unit_test(libnet_build_udld__tlv_device_id),
        cmocka_unit_test(libnet_build_udld__tlv_port_id),
        cmocka_unit_test(libnet_build_udld__tlv_echo),
        cmocka_unit_test(libnet_build_udld__tlv_message_interval),
        cmocka_unit_test(libnet_build_udld__tlv_timeout_interval),
        cmocka_unit_test(libnet_build_udld__tlv_device_name),
        cmocka_unit_test(libnet_build_udld__tlv_sequence_number),
        cmocka_unit_test(libnet_build_udld__build_whole_packet_with_checksum),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
