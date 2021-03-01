/* SPDX-License-Identifier: GPL-2.0 */

#include <arpa/inet.h>

#include "common.h"
#include "uxdp.h"

static int print_reverse(struct reverse_route *rev) {
  char buffer[33];

  const char *result = inet_ntop(AF_INET6, &rev->v6, buffer, sizeof(buffer));
  if (result == 0) {
    fprintf(stderr, "Failed to parse address!\n");
  }

  for(int i = 0; i < SEG_MAX; i++)
  {
    const char *seg = inet_ntop(AF_INET6, &rev->segments[i], buffer, sizeof(buffer));
    if (seg == 0) {
      fprintf(stderr, "Failed to parse address!\n");
    }
    printf("Seg[%d]: %s\n", i, seg);
  }

  printf("IP: %s\n", result);
  execl("sh", "sh", "-c", "ip -6 r s", NULL);

  return 0;
}

int main(int argc, char **argv) {
  int ch;

  struct xdp_map xdp_map = {
      .prog = "xdp_srv6_reverser",
      .map = "reversemap",
      .map_want =
          {
              .key_size = sizeof(__u32),
              .value_size = sizeof(struct reverse_route),
              .max_entries = 1,
          },
  };

  while ((ch = getopt(argc, argv, "d:f:p:k:s:l:")) != -1) {
    switch (ch) {
    case 'd':
      xdp_map.net = optarg;
      break;
    default:
      fprintf(stderr, "Invalid argument\n");
      exit(-1);
    }
  }

  if (!xdp_map.net) {
    fprintf(stderr, "invalid arguments\n");
    return -1;
  }

  if (map_lookup(&xdp_map)) {
    fprintf(stderr, "failed to xdp_map map\n");
    return -1;
  }

  struct reverse_route rev;
  __u32 key = 0;
  for (;;) {
    if ((bpf_map_lookup_elem(xdp_map.map_fd, &key, &rev)) != 0) {
      fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
    }
    print_reverse(&rev);
    sleep(100);
  }

  printf("Exiting!\n");

  return 0;
}
