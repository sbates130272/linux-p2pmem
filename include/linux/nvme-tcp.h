/*
 * Copyright (c) 2017 LightBits Labs. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _LINUX_NVME_TCP_H
#define _LINUX_NVME_TCP_H

#include <linux/nvme.h>

#define NVME_TCP_MAX_DOFF	256

enum nvme_tcp_connect_fmt {
	NVME_TCP_CONNECT_FMT_1_1 = 0x0,
};

enum nvme_tcp_connect_status {
	NVME_TCP_CONNECT_INVALID_RECFMT	= 0x01,
	NVME_TCP_CONNECT_INVALID_MAXR2T	= 0x02,
	NVME_TCP_CONNECT_INVALID_DIGEST	= 0x03,
	NVME_TCP_CONNECT_INVALID_HDOFF	= 0x04,
};

enum nvme_tcp_digest_option {
	NVME_TCP_PDU_DIGEST_ENABLE	= (1 << 0),
	NVME_TCP_DATA_DIGEST_ENABLE	= (1 << 1),
};

enum nvme_tcp_pdu_opcode {
	nvme_tcp_connect	= 0x0,
	nvme_tcp_connect_rep	= 0x1,
	nvme_tcp_cmd		= 0x2,
	nvme_tcp_comp		= 0x3,
	nvme_tcp_r2t		= 0x4,
	nvme_tcp_data_h2c	= 0x5,
	nvme_tcp_data_c2h	= 0x6,
};

enum nvme_tcp_pdu_flags {
	NVME_TCP_FLAG_PDGST		= (1 << 0),
	NVME_TCP_FLAG_DDGST		= (1 << 1),
	NVME_TCP_DATA_LAST		= (1 << 2),
	NVME_TCP_DATA_LAST_NO_COMP	= (1 << 3),
};

/**
 * struct nvme_tcp_hdr - nvme tcp generic header
 *
 * @opcode:        pdu opcode
 * @flags:         pdu flags
 * @pdgst:         pdu digest (optional, reserved otherwise)
 * @length:        wire byte-length of pdu
 */
struct nvme_tcp_hdr {
	__u8	opcode;
	__u8	flags;
	__le16	pdgst;
	__le32	length;
} __packed;

/**
 * struct nvme_tcp_init_conn_req_pdu - nvme tcp connect request
 *
 * @hdr:           nvme-tcp generic header
 * @recfmt:        format of the connect request data
 * @maxr2t:        maximum r2ts per request supported
 * @hdoff:         host data offset for c2h data pdu
 * @digest:        digest types enabled
 */
struct nvme_tcp_init_conn_req_pdu {
	struct nvme_tcp_hdr	hdr;
	__le16			recfmt;
	__u16			rsvd1;
	__le32			maxr2t;
	__le16			hdoff;
	__le16			digest;
	__u8			rsvd2[1012];
} __packed;

/**
 * struct nvme_tcp_init_conn_rep_pdu - nvme tcp connect reply
 *
 * @hdr:           nvme-tcp generic header
 * @recfmt:        format of the connect reply data
 * @sts:           error status for the associated connect request
 * @maxdata:       maximum data capsules per r2t supported
 * @digest:        digest types enabled
 * @cdoff:         controller data offset for h2c data pdu
 */
struct nvme_tcp_init_conn_rep_pdu {
	struct nvme_tcp_hdr	hdr;
	__le16			recfmt;
	__le16			sts;
	__le32			maxdata;
	__le16			cdoff;
	__le16			digest;
	__u8			rsvd[1012];
} __packed;

/**
 * struct nvme_tcp_cmd_pdu - nvme tcp command
 *
 * @hdr:           nvme-tcp generic header
 * @cmd:           nvme command
 */
struct nvme_tcp_cmd_pdu {
	struct nvme_tcp_hdr	hdr;
	struct nvme_command	cmd;
} __packed;

/**
 * struct nvme_tcp_comp_pdu - nvme tcp completion
 *
 * @hdr:           nvme-tcp generic header
 * @cqe:           nvme completion queue entry
 */
struct nvme_tcp_comp_pdu {
	struct nvme_tcp_hdr	hdr;
	struct nvme_completion	cqe;
} __packed;

/**
 * struct nvme_tcp_r2t_pdu - nvme tcp ready-to-receive
 *
 * @hdr:           nvme-tcp generic header
 * @command_id:    nvme command identifier which this relates to
 * @r2tt:          r2t tag (controller generated)
 * @r2t_offset:    offset from the start of the command data
 * @r2t_length:    length in bytes the host is allowed to send
 */
struct nvme_tcp_r2t_pdu {
	struct nvme_tcp_hdr	hdr;
	__u16			command_id;
	__u16			r2tt;
	__le32			r2t_offset;
	__le32			r2t_length;
	__u8			rsvd2[4];
} __packed;

/**
 * struct nvme_tcp_data_pdu - nvme tcp data unit
 *
 * @hdr:           nvme-tcp generic header
 * @command_id:    nvme command identifier which this relates to
 * @r2tt:          matches the corresponding r2t pdu r2t tag
 * @data_offset:   offset from the start of the command data
 * @data_length:   length in bytes of the data stream
 */
struct nvme_tcp_data_pdu {
	struct nvme_tcp_hdr	hdr;
	__u16			command_id;
	__u16			r2tt;
	__le32			data_offset;
	__le32			data_length;
	__u8			rsvd2[4];
} __packed;

#endif /* _LINUX_NVME_TCP_H */
