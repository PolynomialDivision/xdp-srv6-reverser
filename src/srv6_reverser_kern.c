/* SPDX-License-Identifier: GPL-2.0 */

#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

#define IPV6_EXT_ROUTING 43
#define IPV6_ENCAP 41 // [RFC2473]

#define ipv6_optlen(p) (((p)->hdrlen + 1) << 3)

struct ip6_addr_t {
  unsigned long long hi;
  unsigned long long lo;
};

struct ip6_srh_t {
  unsigned char nexthdr;
  unsigned char hdrlen;
  unsigned char type;
  unsigned char segments_left;
  unsigned char first_segment;
  unsigned char flags;
  unsigned short tag;

  struct ip6_addr_t segments[0];
};

struct bpf_map_def SEC("maps") reversemap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct reverse_route),
    .max_entries = 1,
};

SEC("srv6-reverser")
int xdp_srv6_reverser(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *ehdr = data;
  if (ehdr + 1 > data_end)
    goto out;

  if (bpf_ntohs(ehdr->h_proto) != ETH_P_IPV6) {
    goto out;
  }

  // IPv6 Header
  struct ipv6hdr *ip6_srv6_hdr = (void *)(ehdr + 1);
  if (ip6_srv6_hdr + 1 > data_end)
    goto out;
  if (ip6_srv6_hdr->nexthdr != IPV6_EXT_ROUTING)
    goto out;

  // Routing Header
  struct ipv6_rt_hdr *ip6_hdr = (struct ipv6_rt_hdr *)(ip6_srv6_hdr + 1);
  if (ip6_hdr + 1 > data_end)
    goto out;
  if (ip6_hdr->nexthdr != IPV6_ENCAP)
    goto out;

  // "Orig" IPv6 Header
  struct ipv6hdr *ipv6_orig_header =
      (struct ipv6hdr *)(((void *)ip6_hdr) + ipv6_optlen(ip6_hdr));
  if (ipv6_orig_header + 1 > data_end)
    goto out;

  __u32 key = 0;
  struct reverse_route *reverse = bpf_map_lookup_elem(&reversemap, &key);
  if (!reverse)
    goto out;

  // copy routing header
  // reverse->ip6_rt_hdr = *ip6_hdr;

  // copy source address
  __builtin_memcpy(reverse->v6.s6_addr, ipv6_orig_header->saddr.s6_addr, 16);

  // copy segments
  struct ip6_addr_t *seg;
  struct ip6_srh_t *srh;

  srh = (struct ip6_srh_t *)(void *)(ip6_srv6_hdr + 1);
  if (srh + 1 > data_end)
    goto out;

  reverse->fist_segment = srh->first_segment;
  reverse->segments_left = srh->segments_left;

  seg = (struct ip6_addr_t *)((char *)srh + sizeof(*srh));

  int numseg = reverse->fist_segment + 1;
  if ((seg + SEG_MAX) > data_end)
    goto out;

  #pragma clang loop unroll(full)
  for (int i = 0; i < SEG_MAX; i++) { // ToDo: CHECK!!!
    __builtin_memcpy(reverse->segments[i].s6_addr, seg, 16);
    seg = (struct ip6_addr_t *)((char *)seg + sizeof(*seg));
  }

out:
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
