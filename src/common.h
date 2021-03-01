#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in.h>

#include <linux/bpf.h>

#include <inttypes.h>
#include <stdbool.h>

#define SEG_MAX 5

struct reverse_route {
	uint32_t prefix;
	struct in6_addr v6;
	struct ipv6_rt_hdr ip6_rt_hdr;
	struct in6_addr segments[SEG_MAX];
};
