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
 * Byte offsets within a TDREPORT of the two TEE TCB SVN fields in TEE_TCB_INFO
 * (which starts at offset 256, after the 8-byte valid bitmap):
 *   valid[8] + tee_tcb_svn[16] + mr_seam[48] + mr_signer_seam[48] +
 *   attributes[8] + tee_tcb_svn2[16].
 * These mirror the kernel's dump_tdx_report_fields() offsets.
 */
#define TDREPORT_TEE_TCB_INFO_OFFSET	256
#define TDREPORT_TEE_TCB_SVN_OFFSET	(TDREPORT_TEE_TCB_INFO_OFFSET + 8)
#define TDREPORT_TEE_TCB_SVN2_OFFSET	(TDREPORT_TEE_TCB_INFO_OFFSET + 8 + 16 + 48 + 48 + 8)

static void dump_hex(const char *label, const __u8 *buf, size_t len)
{
	printf("%s: ", label);
	for (size_t i = 0; i < len; ++i)
		printf("%02x", buf[i]);
	printf("\n");
}

/*
 * Fetch a TDREPORT via TDX_CMD_GET_REPORT0. Returns 0 on success.
 */
static int get_report(int fd, __u8 tdreport[TDX_REPORT_LEN])
{
	struct tdx_report_req req;
	int ret;

	memset(&req, 0, sizeof(req));

	ret = ioctl(fd, TDX_CMD_GET_REPORT0, &req);
	if (ret) {
		perror("ioctl(TDX_CMD_GET_REPORT0)");
		return 1;
	}

	memcpy(tdreport, req.tdreport, TDX_REPORT_LEN);
	return 0;
}

/*
 * Request a 128-bit sealing key, optionally pinning tee_tcb_svn to a caller
 * supplied value. When @tee_tcb_svn is NULL, the field is left zero and the
 * kernel fills in the current platform SVN from a TDREPORT.
 *
 * On success (ret 0) the derived key is copied into @key_out (16 bytes).
 */
static int get_sealing_key_svn(int fd, const __u8 *tee_tcb_svn,
			       __u8 key_out[TDX_SEALING_KEY_LEN])
{
	struct tdx_sealing_key_req req;
	int ret;

	memset(&req, 0, sizeof(req));

	req.key_request.keyname = 0;
	req.key_request.keysize_bitmap = TDX_KEYSIZE_BITMAP_128;
	req.key_request.tdkeypolicy.mrtd = 1; /* include MRTD */
	req.requestor = 0;

	if (tee_tcb_svn)
		memcpy(req.key_request.tee_tcb_svn, tee_tcb_svn,
		       TDX_TEE_TCB_SVN_LEN);

	ret = ioctl(fd, TDX_CMD_GET_SEALING_KEY, &req);
	if (ret) {
		perror("ioctl(TDX_CMD_GET_SEALING_KEY)");
		return 1;
	}

	memcpy(key_out, req.key, TDX_SEALING_KEY_LEN);
	return 0;
}

/*
 * Compare tee_tcb_svn and tee_tcb_svn2 from the TDREPORT. If they differ,
 * request one sealing key pinned to each SVN and report whether the derived
 * keys differ. This isolates tee_tcb_svn as the only varying input (cpusvn is
 * left zero so the kernel fills the same value for both calls).
 *
 * Returns 0 on success, non-zero on error.
 */
static int compare_keys_by_svn(int fd)
{
	__u8 tdreport[TDX_REPORT_LEN];
	__u8 svn[TDX_TEE_TCB_SVN_LEN];
	__u8 svn2[TDX_TEE_TCB_SVN_LEN];
	__u8 key_svn[TDX_SEALING_KEY_LEN];
	__u8 key_svn2[TDX_SEALING_KEY_LEN];

	if (get_report(fd, tdreport))
		return 1;

	memcpy(svn, tdreport + TDREPORT_TEE_TCB_SVN_OFFSET, sizeof(svn));
	memcpy(svn2, tdreport + TDREPORT_TEE_TCB_SVN2_OFFSET, sizeof(svn2));

	dump_hex("tee_tcb_svn ", svn, sizeof(svn));
	dump_hex("tee_tcb_svn2", svn2, sizeof(svn2));

	if (memcmp(svn, svn2, sizeof(svn)) == 0) {
		printf("tee_tcb_svn == tee_tcb_svn2, skip key comparison\n");
		return 0;
	}

	printf("tee_tcb_svn != tee_tcb_svn2, deriving a key for each SVN\n");

	if (get_sealing_key_svn(fd, svn, key_svn))
		return 1;
	dump_hex("key(tee_tcb_svn) ", key_svn, sizeof(key_svn));

	if (get_sealing_key_svn(fd, svn2, key_svn2))
		return 1;
	dump_hex("key(tee_tcb_svn2)", key_svn2, sizeof(key_svn2));

	if (memcmp(key_svn, key_svn2, sizeof(key_svn)) == 0)
		printf("result: keys are IDENTICAL (tee_tcb_svn does not affect this key)\n");
	else
		printf("result: keys DIFFER (tee_tcb_svn changes the derived key)\n");

	return 0;
}

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

	/*
	 * Case 3: compare the derived key when pinning tee_tcb_svn to the
	 * report's tee_tcb_svn vs tee_tcb_svn2 (only runs if they differ).
	 */
	compare_keys_by_svn(fd);

	close(fd);

	return (ret128 || ret256) ? 1 : 0;
}
