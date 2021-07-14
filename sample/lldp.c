/*
 * TODO: let to the user to configure the application.
 *  Parse the CLI arguments.
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include "./libnet_test.h"

#include <assert.h>

#define DEVICE_NAME "lo"

int
main(int argc, char *argv[])
{
  (void)argc; /* unused */

  int c;
  libnet_t *l;
  libnet_ptag_t t;
  char errbuf[LIBNET_ERRBUF_SIZE];
  uint8_t lldp_dst_mac[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};

  l = libnet_init(LIBNET_LINK, DEVICE_NAME, errbuf);
  if (l == NULL)
  {
    fprintf(stderr, "libnet_init() failed: %s", errbuf);
    return (EXIT_FAILURE);
  }

  /*
   * Building of the LLDPDU should be from the tail to the head.
   *  - End of LLDPDU TLV
   *  - Optionals TLVs
   *  - TTL TLV
   *  - Port ID TLV
   *  - Chassis ID TLV
   */

  /*
   * Build End of LLDPDU TLV
   */
  t = libnet_build_lldp_end(l, 0);
  if (t == -1)
  {
    fprintf(stderr, "Can't build lldp end of lldpdu tlv: %s\n",
            libnet_geterror(l));
    goto bad;
  }

  /*
   * Build Organization Specific TLV
   * Build TLV information string manually
   */
  uint8_t org_spec[9] = {0x00, 0x12, 0x0f,              /* IEEE802.3 OUI */
                         0x01,                          /* IEEE 802.3 Subtype: MAC/PHY */
                         0x03, 0xc0, 0x36, 0x00, 0x10}; /* String information */

  t = libnet_build_lldp_org_spec(org_spec, sizeof(org_spec), l, 0);
  if (t == -1)
  {
    fprintf(stderr, "Can't build Organization Specific tlv: %s\n", libnet_geterror(l));
    goto bad;
  }

  /*
   * Build TTL TLV
   */
  const uint16_t ttl = htons(120); /* seconds */
  t = libnet_build_lldp_ttl(ttl, l, 0);
  if (t == -1)
  {
    fprintf(stderr, "Can't build ttl tlv: %s\n", libnet_geterror(l));
    goto bad;
  }

  /*
   * Build Port ID TLV
   */
  uint8_t interface_alias[15] = {0x55, 0x70, 0x6c, 0x69, 0x6e, 0x6b,
                                 0x20, 0x74, 0x6f, 0x20, 0x53, 0x31};
  t = libnet_build_lldp_port(LIBNET_LLDP_PORT_ID_SUBTYPE_IF_ALIAS,
                             interface_alias, sizeof(interface_alias), l, 0);
  if (t == -1)
  {
    fprintf(stderr, "Can't build lldp port id tlv: %s\n", libnet_geterror(l));
    goto bad;
  }

  /*
   * Build Chassis ID TLV
   */
  uint8_t chassis_mac[6] = {0x00, 0x19, 0x2f, 0xa7, 0xb2, 0x8d};
  t = libnet_build_lldp_chassis(LIBNET_LLDP_CHASSIS_ID_SUBTYPE_MAC, chassis_mac,
                                sizeof(chassis_mac), l, 0);
  if (t == -1)
  {
    fprintf(stderr, "Can't build lldp chassis id tlv: %s\n",
            libnet_geterror(l));
    goto bad;
  }

  t = libnet_build_ethernet(lldp_dst_mac, (uint8_t *)libnet_get_hwaddr(l),
                            LIBNET_LLDP_ETH_TYPE, NULL, 0, l, 0);
  if (t == -1)
  {
    fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
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
