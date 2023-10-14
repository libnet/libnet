#include "common.h"

#include <assert.h>

static libnet_ptag_t
internal_build_udld_tlv(uint16_t tlv_type, const uint8_t *value,
uint8_t value_s, libnet_t * l, libnet_ptag_t ptag)
{
    struct libnet_udld_hdr hdr;
    libnet_pblock_t *p;

    hdr.tlv__type   = tlv_type;
    hdr.tlv__length = LIBNET_UDLD_TLV_HDR_SIZE + value_s;

    const uint32_t host_type_and_len = 0
        | (hdr.tlv__type << 16)
        | (hdr.tlv__length);
    const uint32_t network_type_and_len = htonl(host_type_and_len);

    const uint32_t n = LIBNET_UDLD_TLV_HDR_SIZE + value_s;
    const uint32_t h = n;

    uint8_t pblock_type = 0;
    uint8_t value_type  = 0;
    switch(tlv_type)
    {
        case LIBNET_UDLD_DEVICE_ID:
            pblock_type = LIBNET_PBLOCK_UDLD_DEVICE_ID_H;
            value_type  = LIBNET_UDLD_VALUE_TYPE_ASCII;
            break;
        case LIBNET_UDLD_PORT_ID:
            pblock_type = LIBNET_PBLOCK_UDLD_PORT_ID_H;
            value_type  = LIBNET_UDLD_VALUE_TYPE_ASCII;
            break;
        case LIBNET_UDLD_ECHO:
            pblock_type = LIBNET_PBLOCK_UDLD_ECHO_H;
            value_type  = LIBNET_UDLD_VALUE_TYPE_ID_PAIRS;
            break;
        case LIBNET_UDLD_MESSAGE_INTERVAL:
            pblock_type = LIBNET_PBLOCK_UDLD_MSG_INTERVAL_H;
            value_type  = LIBNET_UDLD_VALUE_TYPE_8_BIT_UINT;
            break;
        case LIBNET_UDLD_TIMEOUT_INTERVAL:
            pblock_type = LIBNET_PBLOCK_UDLD_TMT_INTERVAL_H;
            value_type  = LIBNET_UDLD_VALUE_TYPE_8_BIT_UINT;
            break;
        case LIBNET_UDLD_DEVICE_NAME:
            pblock_type = LIBNET_PBLOCK_UDLD_DEVICE_NAME_H;
            value_type  = LIBNET_UDLD_VALUE_TYPE_ASCII;
            break;
        case LIBNET_UDLD_SEQUENCE_NUMBER:
            pblock_type = LIBNET_PBLOCK_UDLD_SEQ_NUMBER_H;
            value_type  = LIBNET_UDLD_VALUE_TYPE_32_BIT_UINT;
            break;
        default:
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "%s(): incorrect TLV type", __func__);
            p = NULL;
            goto bad;
    }

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, pblock_type);
    if (p == NULL)
    {
        return (-1);
    }

    if (libnet_pblock_append(l, p, &network_type_and_len, sizeof(network_type_and_len)) == -1)
    {
        goto bad;
    }

    switch(value_type)
    {
        case LIBNET_UDLD_VALUE_TYPE_ASCII:
        case LIBNET_UDLD_VALUE_TYPE_ID_PAIRS:
        {
            if (libnet_pblock_append(l, p, value, value_s) == -1)
            {
                goto bad;
            }
            break;
        }
        case LIBNET_UDLD_VALUE_TYPE_8_BIT_UINT:
        {
            if (libnet_pblock_append(l, p, value, sizeof(uint8_t)) == -1)
            {
                goto bad;
            }
            break;
        }
        case LIBNET_UDLD_VALUE_TYPE_32_BIT_UINT:
        {
            const uint32_t sequence_number = htonl(*(const uint32_t *)value);
            if (libnet_pblock_append(l, p, &sequence_number, sizeof(uint32_t)) == -1)
            {
                goto bad;
            }
            break;
        }
        default:
        {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "%s(): incorrect value type", __func__);
            goto bad;
        }
    }

    if (ptag)
    {
        return ptag;
    }

    return libnet_pblock_update(l, p, h, pblock_type);
  bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_hdr(uint8_t version, uint8_t opcode, uint8_t flags, uint8_t checksum,
const uint8_t *payload, uint32_t payload_s, libnet_t * l, libnet_ptag_t ptag)
{

    struct libnet_udld_hdr udld_hdr;
    uint32_t n = 0;
    const uint32_t h = 0;

    if (l == NULL)
    {
        return (-1);
    }

    n = LIBNET_UDLD_H + payload_s;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    libnet_pblock_t * const p = libnet_pblock_probe(
        l,
        ptag,
        n,
        LIBNET_PBLOCK_UDLD_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&udld_hdr, 0, sizeof(udld_hdr));
    udld_hdr.version_opcode |= (version << LIBNET_UDLD_PDU_VERSION_OFFSET);
    udld_hdr.version_opcode |= (opcode);
    udld_hdr.flags = flags;
    udld_hdr.checksum = checksum;

    /*
     *  Appened the protocol unit to the list.
     */
    n = libnet_pblock_append(l, p, (u_char *) & udld_hdr, LIBNET_UDLD_H);
    if (n == -1)
    {
        goto bad;
    }

    LIBNET_DO_PAYLOAD(l, p);

    if (checksum == 0 && l->injection_type != LIBNET_RAW4)
    {
        /*
         *  If checksum is zero, by default libnet will compute a checksum
         *  for the user.  The programmer can override this by calling
         *  libnet_toggle_checksum(l, ptag, 1);
         */
        libnet_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
    }

    return (ptag ? ptag : libnet_pblock_update(l, p, h, LIBNET_PBLOCK_UDLD_H));
  bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_device_id(const uint8_t *value, uint8_t value_s, libnet_t * l, libnet_ptag_t ptag)
{
    if (l == NULL)
    {
        return (-1);
    }

    if ((value && !value_s) || (!value && value_s))
    {
        sprintf(l->err_buf, "%s(): value inconsistency\n", __FUNCTION__);
        return (-1);
    }

    return internal_build_udld_tlv(LIBNET_UDLD_DEVICE_ID, value, value_s, l, ptag);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_port_id(const uint8_t *value, uint8_t value_s, libnet_t * l, libnet_ptag_t ptag)
{
    if (l == NULL)
    {
        return (-1);
    }

    if ((value && !value_s) || (!value && value_s))
    {
        sprintf(l->err_buf, "%s(): value inconsistency\n", __FUNCTION__);
        return (-1);
    }

    return internal_build_udld_tlv(LIBNET_UDLD_PORT_ID, value, value_s, l, ptag);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_echo(const uint8_t *value, uint8_t value_s, libnet_t * l, libnet_ptag_t ptag)
{
    if (l == NULL)
    {
        return (-1);
    }

    if ((value && !value_s) || (!value && value_s))
    {
        sprintf(l->err_buf, "%s(): value inconsistency\n", __FUNCTION__);
        return (-1);
    }

    return internal_build_udld_tlv(LIBNET_UDLD_ECHO, value, value_s, l, ptag);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_message_interval(const uint8_t *value, libnet_t *l,
libnet_ptag_t ptag)
{
    if (l == NULL)
    {
        return (-1);
    }

    assert(value && "value cannot be a NULL\n");
    if (value == NULL)
    {
        sprintf(l->err_buf, "%s(): value pointer cannot be a NULL\n", __FUNCTION__);
        return (-1);
    }

    return internal_build_udld_tlv(LIBNET_UDLD_MESSAGE_INTERVAL, value, sizeof(uint8_t), l, ptag);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_timeout_interval(const uint8_t *value, libnet_t *l,
libnet_ptag_t ptag)
{
    if (l == NULL)
    {
        return (-1);
    }

    assert(value && "value cannot be a NULL\n");
    if (value == NULL)
    {
        sprintf(l->err_buf, "%s(): value pointer cannot be a NULL\n", __FUNCTION__);
        return (-1);
    }

    return internal_build_udld_tlv(LIBNET_UDLD_TIMEOUT_INTERVAL, (const uint8_t *)value, sizeof(uint8_t), l, ptag);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_device_name(const uint8_t *value, uint8_t value_s,
libnet_t *l, libnet_ptag_t ptag)
{
    if (l == NULL)
    {
        return (-1);
    }

    if ((value && !value_s) || (!value && value_s))
    {
        sprintf(l->err_buf, "%s(): value inconsistency\n", __FUNCTION__);
        return (-1);
    }

    return internal_build_udld_tlv(LIBNET_UDLD_DEVICE_NAME, value, value_s, l, ptag);
}

LIBNET_API libnet_ptag_t
libnet_build_udld_sequence_number(const uint8_t *value, libnet_t *l,
libnet_ptag_t ptag)
{
    if (l == NULL)
    {
        return (-1);
    }

    assert(value != NULL && "value cannot be a NULL\n");
    if (value == NULL)
    {
        sprintf(l->err_buf, "%s(): value pointer cannot be a NULL\n", __FUNCTION__);
        return (-1);
    }

    return internal_build_udld_tlv(LIBNET_UDLD_SEQUENCE_NUMBER, value, sizeof(uint32_t), l, ptag);
}
