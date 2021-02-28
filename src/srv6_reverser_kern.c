/* SPDX-License-Identifier: GPL-2.0 */

#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>


SEC("srv6-reverser")
int xdp_srv6_reverser(struct xdp_md *ctx) {
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
