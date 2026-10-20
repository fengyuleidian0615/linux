// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/tdx-guest.h>

/*
 * Compile-time check that the TDKEYREQUEST mirror matches the 128-byte
 * td_key_request_t layout required by the TDX module's TDG.MR.KEY.GET leaf.
 */
_Static_assert(sizeof(struct tdx_key_request) == TDX_KEY_REQUEST_LEN,
	       "struct tdx_key_request must be 128 bytes");

/* KEYSIZE_BITMAP selectors: bit 0 => 128-bit key, bit 1 => 256-bit key. */
#define TDX_KEYSIZE_BITMAP_128	0x1
#define TDX_KEYSIZE_BITMAP_256	0x2

/*
 * Request one sealing key of the given size and print it.
 *
 * Using fixed request parameters means the derived key must be identical
 * across reboots on the same platform. Run this test on multiple boots and
 * compare the printed key.
 *
 * Returns 0 on success (non-zero key), 1 on ioctl failure, 2 on an all-zero
 * key.
 */
static int get_sealing_key(int fd, unsigned int keysize_bitmap,
			   unsigned int key_bits)
{
	struct tdx_sealing_key_req req;
	size_t key_bytes = key_bits / 8;
	int ret;

	memset(&req, 0, sizeof(req));

	/*
	 *  - keyname 0 selects the sealing key.
	 *  - keysize_bitmap selects the requested key size.
	 *  - tdkeypolicy binds MRTD so the key is tied to the TD measurement.
	 *  - requestor 0 selects the L1 VM.
	 */
	req.key_request.keyname = 0;
	req.key_request.keysize_bitmap = keysize_bitmap;
	req.key_request.tdkeypolicy.mrtd = 1; /* include MRTD */
	req.requestor = 0;

	ret = ioctl(fd, TDX_CMD_GET_SEALING_KEY, &req);
	if (ret) {
		perror("ioctl(TDX_CMD_GET_SEALING_KEY)");
		return 1;
	}

	printf("TDX sealing key (%u-bit, %zu bytes): ", key_bits, key_bytes);
	for (size_t i = 0; i < key_bytes; ++i)
		printf("%02x", req.key[i]);
	printf("\n");

	for (size_t i = 0; i < key_bytes; ++i) {
		if (req.key[i] != 0)
			return 0;
	}

	fprintf(stderr, "warning: %u-bit TDX sealing key was all zeroes\n",
		key_bits);
	return 2;
}

int main(void)
{
	int fd;
	int ret128;
	int ret256;

	fd = open("/dev/tdx_guest", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/tdx-guest)");
		return 1;
	}

	/* Case 1: 128-bit sealing key (KEYSIZE_BITMAP bit 0). */
	ret128 = get_sealing_key(fd, TDX_KEYSIZE_BITMAP_128, 128);

	/* Case 2: 256-bit sealing key (KEYSIZE_BITMAP bit 1). */
	/* 265bit sealing key is not supported yet till latest TDX_MODULE_2.0.18 release.
	 * This is an implementation limitation of TDX module, and should be fixed easily now.
	 * https://github.com/intel/confidential-computing.tdx.tdx-module/blob/TDX_MODULE_2.0.18/src/vmm_dispatcher/api_calls/tdh_sys_init.c#L1592
	 */
	//ret256 = get_sealing_key(fd, TDX_KEYSIZE_BITMAP_256, 256);

	close(fd);

	return (ret128 || ret256) ? 1 : 0;
}
