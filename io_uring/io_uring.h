#ifndef IOU_CORE_H
#define IOU_CORE_H

#include <linux/errno.h>
#include "io_uring_types.h"

enum {
	IOU_OK			= 0,
	IOU_ISSUE_SKIP_COMPLETE	= -EIOCBQUEUED,
};

static inline void req_set_fail(struct io_kiocb *req)
{
	req->flags |= REQ_F_FAIL;
	if (req->flags & REQ_F_CQE_SKIP) {
		req->flags &= ~REQ_F_CQE_SKIP;
		req->flags |= REQ_F_SKIP_LINK_CQES;
	}
}

static inline void io_req_set_res(struct io_kiocb *req, s32 res, u32 cflags)
{
	req->cqe.res = res;
	req->cqe.flags = cflags;
}

static inline void io_put_file(struct file *file)
{
	if (file)
		fput(file);
}

void __io_req_complete32(struct io_kiocb *req, unsigned int issue_flags,
			 u64 extra1, u64 extra2);
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags);
unsigned int io_put_kbuf(struct io_kiocb *req, unsigned issue_flags);

struct file *io_file_get_normal(struct io_kiocb *req, int fd);
struct file *io_file_get_fixed(struct io_kiocb *req, int fd,
			       unsigned issue_flags);

#endif
