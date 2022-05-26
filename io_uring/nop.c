// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring_types.h"
#include "io_uring.h"
#include "kbuf.h"
#include "nop.h"

struct io_nop {
	struct file			*file;
	u64				extra1;
	u64				extra2;
};

int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	/*
	 * If the ring is setup with CQE32, relay back addr/addr
	 */
	if (req->ctx->flags & IORING_SETUP_CQE32) {
		struct io_nop *nop = io_kiocb_to_cmd(req);

		nop->extra1 = READ_ONCE(sqe->addr);
		nop->extra2 = READ_ONCE(sqe->addr2);
	}

	return 0;
}

/*
 * IORING_OP_NOP just posts a completion event, nothing else.
 */
int io_nop(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_nop *nop = io_kiocb_to_cmd(req);
	void __user *buf;

	if (req->flags & REQ_F_BUFFER_SELECT) {
		size_t len = 1;

		buf = io_buffer_select(req, &len, issue_flags);
		if (!buf)
			return -ENOBUFS;
	}

	io_req_set_res(req, 0, io_put_kbuf(req, issue_flags));

	if (req->ctx->flags & IORING_SETUP_CQE32) {
		__io_req_complete32(req, issue_flags, nop->extra1, nop->extra2);
		return IOU_ISSUE_SKIP_COMPLETE;
	}

	return IOU_OK;
}
