/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace interface for TDX guest driver
 *
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _UAPI_LINUX_TDX_GUEST_H_
#define _UAPI_LINUX_TDX_GUEST_H_

#include <linux/ioctl.h>
#include <linux/types.h>

/* Length of the REPORTDATA used in TDG.MR.REPORT TDCALL */
#define TDX_REPORTDATA_LEN              64

/* Length of TDREPORT used in TDG.MR.REPORT TDCALL */
#define TDX_REPORT_LEN                  1024

/* Byte lengths of the fields in a TDX sealing key request (TDG.MR.KEY.GET). */
#define TDX_KEY_REQUEST_LEN             128
#define TDX_CPUSVN_LEN                  16
#define TDX_TEE_TCB_SVN_LEN             16
#define TDX_SALT_LEN                    32

/* Length (in bytes) of the 256-bit sealing key returned by TDG.MR.KEY.GET. */
#define TDX_SEALING_KEY_LEN             32

/**
 * struct tdx_report_req - Request struct for TDX_CMD_GET_REPORT0 IOCTL.
 *
 * @reportdata: User buffer with REPORTDATA to be included into TDREPORT.
 *              Typically it can be some nonce provided by attestation
 *              service, so the generated TDREPORT can be uniquely verified.
 * @tdreport: User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT].
 */
struct tdx_report_req {
	__u8 reportdata[TDX_REPORTDATA_LEN];
	__u8 tdreport[TDX_REPORT_LEN];
};

/**
 * union tdx_key_policy - TDKEYPOLICY bitmap for TDG.MR.KEY.GET.
 *
 * Mirrors the TDX module's td_key_policy_t. Selects which TD
 * measurements/configuration are bound into the derived key.
 *
 * @mrtd: Include MRTD.
 * @mrowner: Include MROWNER.
 * @mrconfigid: Include MRCONFIGID & CONFIGIDSVN.
 * @mrownerconfig: Include MROWNERCONFIG & OWNERCONFIGSVN.
 * @reserved_0: Must be 0.
 * @mrsigroot: Include MRSIGROOT.
 * @mrsigner: Include MRSIGNER.
 * @mrprodid: Include ISVPRODID & ISVSVN.
 * @reserved_1: Must be 0.
 * @rtmr: Per-RTMR include bitmap (RTMR n).
 * @reserved_2: Must be 0.
 * @raw: Raw 64-bit value of the policy.
 */
union tdx_key_policy {
	struct {
		__u64 mrtd		: 1;
		__u64 mrowner		: 1;
		__u64 mrconfigid	: 1;
		__u64 mrownerconfig	: 1;
		__u64 reserved_0	: 4;
		__u64 mrsigroot		: 1;
		__u64 mrsigner		: 1;
		__u64 mrprodid		: 1;
		__u64 reserved_1	: 21;
		__u64 rtmr		: 16;
		__u64 reserved_2	: 16;
	};
	__u64 raw;
};

/**
 * struct tdx_key_request - TDKEYREQUEST input for TDG.MR.KEY.GET.
 *
 * This mirrors the 128-byte td_key_request_t consumed by the TDX module's
 * TDG.MR.KEY.GET leaf; the layout and field offsets match the TDX module ABI
 * exactly. See the "TDG.MR.KEY.GET leaf" in the Intel TDX Module spec.
 *
 * @keyname: Key name selector. Must be 0 (the sealing key).
 * @sw_keyname: Software-defined key name folded into the derivation.
 * @keysize_bitmap: Requested key size(s) as a supported-size bitmap.
 * @reserved_0: Must be zero.
 * @tdkeypolicy: Bitmap selecting which measurements/config are bound into the
 *               key (MRTD, MROWNER, RTMRs, etc.).
 * @attributes_mask: Mask of TD ATTRIBUTES bits bound into the key.
 * @xfam_mask: Mask of XFAM bits bound into the key.
 * @cpusvn: CPU SVN requested for a non-migratable key.
 * @tee_tcb_svn: TEE TCB SVN requested for the key.
 * @isvsvn: ISV SVN selector.
 * @mrconfigsvn: MRCONFIG SVN selector.
 * @mrownerconfigsvn: MROWNERCONFIG SVN selector.
 * @salt: Caller-supplied 256-bit salt folded into the derivation.
 * @reserved_1: Must be zero.
 */
struct tdx_key_request {
	__u16 keyname;
	__u8 sw_keyname;
	__u8 keysize_bitmap;
	__u8 reserved_0[4];
	union tdx_key_policy tdkeypolicy;
	__u64 attributes_mask;
	__u64 xfam_mask;
	__u8 cpusvn[TDX_CPUSVN_LEN];
	__u8 tee_tcb_svn[TDX_TEE_TCB_SVN_LEN];
	__u16 isvsvn;
	__u16 mrconfigsvn;
	__u16 mrownerconfigsvn;
	__u8 salt[TDX_SALT_LEN];
	__u8 reserved_1[26];
};

/*
 * struct tdx_sealing_key_req - Request/response for TDX_CMD_GET_SEALING_KEY.
 *
 * @key_request: TDKEYREQUEST input passed to TDG.MR.KEY.GET (RCX).
 * @requestor: Requestor info passed to TDG.MR.KEY.GET (R8). 0 == L1 VM;
 *             valid range is 0..3.
 * @key: Output buffer that receives the derived 256-bit sealing key (RDX).
 */
struct tdx_sealing_key_req {
	struct tdx_key_request key_request;
	__u64 requestor;
	__u8 key[TDX_SEALING_KEY_LEN];
};

/*
 * TDX_CMD_GET_REPORT0 - Get TDREPORT0 (a.k.a. TDREPORT subtype 0) using
 *                       TDCALL[TDG.MR.REPORT]
 *
 * Return 0 on success, -EIO on TDCALL execution failure, and
 * standard errno on other general error cases.
 */
#define TDX_CMD_GET_REPORT0              _IOWR('T', 1, struct tdx_report_req)

/*
 * TDX_CMD_GET_SEALING_KEY - Get a platform-bound sealing key via
 *                           TDG.MR.KEY.GET.
 *
 * Return 0 on success, or a standard errno otherwise.
 */
#define TDX_CMD_GET_SEALING_KEY          _IOWR('T', 2, struct tdx_sealing_key_req)

#endif /* _UAPI_LINUX_TDX_GUEST_H_ */
