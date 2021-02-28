/* SPDX-License-Identifier: GPL-2.0 */

#include <arpa/inet.h>

#include "common.h"
#include "uxdp.h"


int main(int argc, char **argv) {
  int ch;
  while ((ch = getopt(argc, argv, "d:f:p:k:s:l:")) != -1) {
    switch (ch) {
    case 'd':
      // net = optarg;
      //strcpy(net, optarg);
      break;
    default:
      fprintf(stderr, "Invalid argument\n");
      exit(-1);
    }
  }

  return 0;
}
