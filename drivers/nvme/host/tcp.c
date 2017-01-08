/*
 * NVMe over Fabrics TCP host code.
 * Copyright (c) 2017 LightBits Labs.
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
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/blk-mq.h>

#include "nvme.h"
#include "fabrics.h"

#define NVME_TCP_IP_PORT	4420

/*
 * We handle AEN commands ourselves and don't even let the
 * block layer know about them.
 */
#define NVME_TCP_NR_AEN_COMMANDS      1
#define NVME_TCP_AQ_BLKMQ_DEPTH       \
	(NVME_AQ_DEPTH - NVME_TCP_NR_AEN_COMMANDS)

struct nvme_tcp_queue;

enum nvme_tcp_tx_state {
	NVME_TCP_SEND_PDU = 0,
	NVME_TCP_SEND_INLINE
};

struct nvme_tcp_tx_context {
	struct bio		*current_bio;
	struct iov_iter		iter;
	size_t			offset;
	size_t			data_sent;
	enum nvme_tcp_tx_state	state;
};

struct nvme_tcp_rx_context {
	struct iov_iter		iter;
	struct bio		*current_bio;
};

struct nvme_tcp_request {
	struct nvme_request	req;
	struct nvme_tcp_cmd_pdu	*pdu;
	struct nvme_tcp_queue	*queue;
	u32			data_len;
	struct list_head	entry;
	struct nvme_tcp_rx_context rx;
	struct nvme_tcp_tx_context tx;
	unsigned int		qid;
};

enum nvme_tcp_queue_flags {
	NVME_TCP_Q_LIVE		= 0,
	NVME_TCP_Q_DELETING	= 1,
};

enum nvme_tcp_rx_state {
	NVME_TCP_RECV_PDU = 0,
	NVME_TCP_RECV_DATA
};

struct nvme_tcp_queue_rx_context {
	char		comp[sizeof(struct nvme_tcp_comp_pdu)];
	int		comp_remaining;
	size_t		data_remaining;
};

struct nvme_tcp_queue_tx_context {
	struct nvme_tcp_request *request;
};

struct nvme_tcp_ctrl;
struct nvme_tcp_queue {
	struct socket		*sock;
	struct work_struct	io_work;
	int			io_cpu;

	spinlock_t		lock;
	struct list_head	send_list;

	int			queue_size;
	size_t			cmnd_capsule_len;
	struct nvme_tcp_ctrl	*ctrl;
	unsigned long		flags;
	bool			rd_enabled;

	struct nvme_tcp_queue_rx_context rx;
	struct nvme_tcp_queue_tx_context tx;

	struct nvme_tcp_request async_req;

	void (*sc)(struct sock *);
	void (*dr)(struct sock *);
	void (*ws)(struct sock *);
};

struct nvme_tcp_ctrl {
	/* read only in the hot path */
	struct nvme_tcp_queue	*queues;
	struct blk_mq_tag_set	tag_set;

	/* other member variables */
	struct list_head	list;
	struct blk_mq_tag_set	admin_tag_set;
	struct sockaddr_storage addr;
	struct sockaddr_storage src_addr;
	struct nvme_ctrl	ctrl;
};

static LIST_HEAD(nvme_tcp_ctrl_list);
static DEFINE_MUTEX(nvme_tcp_ctrl_mutex);
static struct workqueue_struct *nvme_tcp_wq;
static struct blk_mq_ops nvme_tcp_mq_ops;
static struct blk_mq_ops nvme_tcp_admin_mq_ops;

static inline struct nvme_tcp_ctrl *to_tcp_ctrl(struct nvme_ctrl *ctrl)
{
	return container_of(ctrl, struct nvme_tcp_ctrl, ctrl);
}

static inline int nvme_tcp_queue_id(struct nvme_tcp_queue *queue)
{
	return queue - queue->ctrl->queues;
}

static inline struct blk_mq_tags *nvme_tcp_tagset(struct nvme_tcp_queue *queue)
{
	u32 queue_idx = nvme_tcp_queue_id(queue);

	if (queue_idx == 0)
		return queue->ctrl->admin_tag_set.tags[queue_idx];
	return queue->ctrl->tag_set.tags[queue_idx - 1];
}

static inline size_t nvme_tcp_inline_data_size(struct nvme_tcp_queue *queue)
{
	/* FIXME: add support in non inline data */
	return ULONG_MAX;
}

static inline struct page *nvme_tcp_req_cur_page(struct nvme_tcp_request *req)
{
	return req->tx.iter.bvec->bv_page;
}

static inline size_t nvme_tcp_req_cur_offset(struct nvme_tcp_request *req)
{
	return req->tx.iter.bvec->bv_offset + req->tx.iter.iov_offset;
}

static inline size_t nvme_tcp_req_cur_length(struct nvme_tcp_request *req)
{
	return req->tx.iter.bvec->bv_len - req->tx.iter.iov_offset;
}

static inline size_t nvme_tcp_req_offset(struct nvme_tcp_request *req)
{
	return req->tx.iter.iov_offset;
}

static inline size_t nvme_tcp_req_data_left(struct nvme_tcp_request *req)
{
	return nvme_is_write(&req->pdu->cmd) ?
		req->data_len - req->tx.data_sent : 0;
}

static inline size_t nvme_tcp_req_last_send(struct nvme_tcp_request *req,
		int len)
{
	return nvme_tcp_req_data_left(req) <= len;
}

static void nvme_tcp_prep_send_bio(struct nvme_tcp_request *req)
{
	struct request *rq = blk_mq_tag_to_rq(nvme_tcp_tagset(req->queue),
		req->pdu->cmd.common.command_id);
	struct bio_vec *vec;
	unsigned int size;
	int nsegs;

	if (rq->rq_flags & RQF_SPECIAL_PAYLOAD) {
		vec = &rq->special_vec;
		nsegs = 1;
		size = blk_rq_payload_bytes(rq);
	} else {
		vec = req->tx.current_bio->bi_io_vec;
		nsegs = bio_segments(req->tx.current_bio);
		size = req->tx.current_bio->bi_iter.bi_size;
	}

	iov_iter_bvec(&req->tx.iter, ITER_BVEC | WRITE, vec, nsegs, size);
}

static inline void nvme_tcp_advance_req(struct nvme_tcp_request *req,
		int len)
{
	req->tx.data_sent += len;
	iov_iter_advance(&req->tx.iter, len);
	if (!iov_iter_count(&req->tx.iter) &&
	    req->tx.data_sent < req->data_len) {
		req->tx.current_bio = req->tx.current_bio->bi_next;
		nvme_tcp_prep_send_bio(req);
	}
}

static inline void nvme_tcp_queue_request(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;

	spin_lock_bh(&queue->lock);
	list_add_tail(&req->entry, &queue->send_list);
	spin_unlock_bh(&queue->lock);

	queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);
}

static inline struct nvme_tcp_request *
nvme_tcp_fetch_request(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req;

	spin_lock_bh(&queue->lock);
	req = list_first_entry_or_null(&queue->send_list,
			struct nvme_tcp_request, entry);
	if (req)
		list_del(&req->entry);
	spin_unlock_bh(&queue->lock);

	return req;
}

static void nvme_tcp_exit_request(struct blk_mq_tag_set *set,
		struct request *rq, unsigned int hctx_idx)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

	kfree(req->pdu);
}

static int nvme_tcp_init_request(struct blk_mq_tag_set *set,
		struct request *rq, unsigned int hctx_idx,
		unsigned int numa_node)
{
	struct nvme_tcp_ctrl *ctrl = set->driver_data;
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	int queue_idx = (set == &ctrl->tag_set) ? hctx_idx + 1 : 0;
	struct nvme_tcp_queue *queue = &ctrl->queues[queue_idx];

	req->pdu = kzalloc_node(sizeof(struct nvme_tcp_cmd_pdu),
			GFP_KERNEL, set->numa_node);
	if (!req->pdu)
		return -ENOMEM;

	req->queue = queue;
	req->qid = queue_idx;

	return 0;
}

static int nvme_tcp_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_tcp_ctrl *ctrl = data;
	struct nvme_tcp_queue *queue = &ctrl->queues[hctx_idx + 1];

	BUG_ON(hctx_idx >= ctrl->ctrl.queue_count);

	hctx->driver_data = queue;
	return 0;
}

static int nvme_tcp_init_admin_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_tcp_ctrl *ctrl = data;
	struct nvme_tcp_queue *queue = &ctrl->queues[0];

	BUG_ON(hctx_idx != 0);

	hctx->driver_data = queue;
	return 0;
}

static enum nvme_tcp_rx_state nvme_tcp_rx_state(struct nvme_tcp_queue *queue)
{
	return (queue->rx.comp_remaining) ? NVME_TCP_RECV_PDU : NVME_TCP_RECV_DATA;
}

static void nvme_tcp_queue_prepare_rx(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_queue_rx_context *rx = &queue->rx;

	rx->comp_remaining = sizeof(rx->comp);
	rx->data_remaining = -1;
}

void nvmf_error_recovery(struct nvme_ctrl *ctrl)
{
	if (!nvme_change_ctrl_state(ctrl, NVME_CTRL_RECONNECTING))
		return;

	queue_work(nvme_wq, &ctrl->err_work);
}
EXPORT_SYMBOL_GPL(nvmf_error_recovery);

static int nvme_tcp_process_nvme_cqe(struct nvme_tcp_queue *queue,
		struct nvme_completion *cqe)
{
	struct request *rq;
	struct nvme_tcp_request *req;

	rq = blk_mq_tag_to_rq(nvme_tcp_tagset(queue), cqe->command_id);
	if (!rq) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d tag 0x%x not found\n",
			nvme_tcp_queue_id(queue), cqe->command_id);
		nvmf_error_recovery(&queue->ctrl->ctrl);
		return -EINVAL;
	}
	req = blk_mq_rq_to_pdu(rq);

	nvme_end_request(rq, cqe->status, cqe->result);

	return 0;
}

static int nvme_tcp_recv_data_prepare(struct nvme_tcp_queue *queue,
		struct nvme_tcp_data_pdu *pdu)
{
	struct nvme_tcp_queue_rx_context *rx = &queue->rx;
	struct nvme_tcp_request *req;
	struct request *rq;

	rq = blk_mq_tag_to_rq(nvme_tcp_tagset(queue), pdu->command_id);
	if (!rq) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d tag %#x not found\n",
			nvme_tcp_queue_id(queue), pdu->command_id);
		return -ENOENT;
	}
	req = blk_mq_rq_to_pdu(rq);

	if (!blk_rq_payload_bytes(rq)) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d tag %#x unexpected data\n",
			nvme_tcp_queue_id(queue), rq->tag);
		return -EIO;
	}

	rx->data_remaining = le32_to_cpu(pdu->data_length);
	/* No support for out-of-order */
	WARN_ON(le32_to_cpu(pdu->data_offset));

	return 0;

}

static int nvme_tcp_done_recv_cqe(struct nvme_tcp_queue *queue,
		struct nvme_completion *cqe)
{
	int ret = 0;

	/*
	 * AEN requests are special as they don't time out and can
	 * survive any kind of queue freeze and often don't respond to
	 * aborts.  We don't even bother to allocate a struct request
	 * for them but rather special case them here.
	 */
	if (unlikely(nvme_tcp_queue_id(queue) == 0 &&
	    cqe->command_id >= NVME_TCP_AQ_BLKMQ_DEPTH))
		nvme_complete_async_event(&queue->ctrl->ctrl, cqe->status,
				&cqe->result);
	else
		ret = nvme_tcp_process_nvme_cqe(queue, cqe);

	return ret;
}

static int nvme_tcp_recv_pdu(struct nvme_tcp_queue *queue,
				struct sk_buff *skb,
				unsigned int *offset,
				size_t *len)
{
	struct nvme_tcp_queue_rx_context *rx = &queue->rx;
	struct nvme_tcp_comp_pdu *pdu;
	size_t recv_len = min_t(size_t, *len, rx->comp_remaining);
	int comp_offset = sizeof(*pdu) - rx->comp_remaining;
	int ret;

	ret = skb_copy_bits(skb, *offset, &rx->comp[comp_offset], recv_len);
	if (unlikely(ret))
		return ret;

	rx->comp_remaining -= recv_len;
	*offset += recv_len;
	*len -= recv_len;
	if (queue->rx.comp_remaining)
		return 0;

	pdu = (struct nvme_tcp_comp_pdu *)rx->comp;

	switch (pdu->hdr.opcode) {
	case nvme_tcp_data_c2h:
		ret = nvme_tcp_recv_data_prepare(queue, (void *)pdu);
		break;
	case nvme_tcp_comp:
		nvme_tcp_queue_prepare_rx(queue);
		ret = nvme_tcp_done_recv_cqe(queue, &pdu->cqe);
		break;
	case nvme_tcp_r2t:
		dev_err(queue->ctrl->ctrl.device, "no support for RTR pdu\n");
		return -EINVAL;
	default:
		dev_err(queue->ctrl->ctrl.device, "unsupport pdu opcode (%d)\n",
			pdu->hdr.opcode);
		return -EINVAL;
	}

	return ret;
}

static void nvme_tcp_prep_recv_bio(struct nvme_tcp_request *req)
{
	struct bio *bio = req->rx.current_bio;
	unsigned int nsegs = bio_segments(bio);

	iov_iter_bvec(&req->rx.iter, ITER_BVEC | READ,
			bio->bi_io_vec, nsegs, bio->bi_iter.bi_size);
}

static void nvme_tcp_initialize_request(struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

	req->data_len = blk_rq_payload_bytes(rq);
	req->pdu->cmd.common.command_id = rq->tag;

	req->tx.state = NVME_TCP_SEND_PDU;
	req->tx.offset = 0;
	req->tx.data_sent = 0;

	if (nvme_is_write(&req->pdu->cmd)) {
		req->tx.current_bio = rq->bio;
	} else {
		req->rx.current_bio = rq->bio;
		if (req->rx.current_bio)
			nvme_tcp_prep_recv_bio(req);
	}
}

static int nvme_tcp_recv_data(struct nvme_tcp_queue *queue, struct sk_buff *skb,
			      unsigned int *offset, size_t *len)
{
	struct nvme_tcp_queue_rx_context *qrx = &queue->rx;
	struct nvme_tcp_data_pdu *pdu = (struct nvme_tcp_data_pdu *)qrx->comp;
	struct nvme_tcp_rx_context *crx;
	struct nvme_tcp_request *req;
	struct request *rq;

	rq = blk_mq_tag_to_rq(nvme_tcp_tagset(queue), pdu->command_id);
	if (!rq) {
		dev_err(queue->ctrl->ctrl.device,
			"queue %d tag %#x not found\n",
			nvme_tcp_queue_id(queue), pdu->command_id);
		return -ENOENT;
	}

	req = blk_mq_rq_to_pdu(rq);
	crx = &req->rx;

	while (true) {
		int recv_len;
		int result;

		recv_len = min_t(size_t, *len, qrx->data_remaining);
		if (!recv_len)
			break;

		/*
		 * FIXME: This assumes that data comes in-order,
		 *  need to handle the out-of-order case.
		 */
		if (!iov_iter_count(&crx->iter)) {
			crx->current_bio = crx->current_bio->bi_next;

			/*
			 * If we don`t have any bios it means that controller
			 * sent more data than we requested, hence error
			 */
			if (!crx->current_bio) {
				dev_err(queue->ctrl->ctrl.device,
					"queue %d no space in request %#x",
					nvme_tcp_queue_id(queue), rq->tag);
				nvme_tcp_queue_prepare_rx(queue);
				return -EIO;
			}
			nvme_tcp_prep_recv_bio(req);
		}

		/* we can read only from what is left in this bio */
		recv_len = min_t(size_t, recv_len,
				iov_iter_count(&crx->iter));

		result = skb_copy_datagram_iter(skb, *offset,
				&crx->iter, recv_len);
		if (result) {
			dev_err(queue->ctrl->ctrl.device,
				"queue %d failed to copy request %#x data",
				nvme_tcp_queue_id(queue), rq->tag);
			return result;
		}

		*len -= recv_len;
		*offset += recv_len;
		qrx->data_remaining -= recv_len;
	}

	if (!qrx->data_remaining)
		nvme_tcp_queue_prepare_rx(queue);

	return 0;
}

static int nvme_tcp_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
			     unsigned int offset, size_t len)
{
	struct nvme_tcp_queue *queue = desc->arg.data;
	size_t consumed = len;
	int result;

	while (len) {
		switch (nvme_tcp_rx_state(queue)) {
		case NVME_TCP_RECV_PDU:
			result = nvme_tcp_recv_pdu(queue, skb, &offset, &len);
			break;
		case NVME_TCP_RECV_DATA:
			result = nvme_tcp_recv_data(queue, skb, &offset, &len);
			break;
		default:
			result = -EFAULT;
		}
		if (result) {
			dev_err(queue->ctrl->ctrl.device,
				"receive failed:  %d\n", result);
			queue->rd_enabled = false;
			nvmf_error_recovery(&queue->ctrl->ctrl);
			return result;
		}
	}

	return consumed;
}

static void nvme_tcp_data_ready(struct sock *sk)
{
	read_descriptor_t rd_desc;
	struct nvme_tcp_queue *queue;

	read_lock(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (unlikely(!queue || !queue->rd_enabled))
		goto done;

	rd_desc.arg.data = queue;
	rd_desc.count = 1;
	tcp_read_sock(sk, &rd_desc, nvme_tcp_recv_skb);
done:
	read_unlock(&sk->sk_callback_lock);
}

static void nvme_tcp_write_space(struct sock *sk)
{
	struct nvme_tcp_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;

	if (!queue)
		goto done;

	if (sk_stream_is_writeable(sk)) {
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		queue_work_on(queue->io_cpu, nvme_tcp_wq, &queue->io_work);
	}
done:
	read_unlock_bh(&sk->sk_callback_lock);
}

static void nvme_tcp_state_change(struct sock *sk)
{
	struct nvme_tcp_queue *queue;

	read_lock(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto done;

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
		if (queue->ctrl->ctrl.state == NVME_CTRL_LIVE)
			nvmf_error_recovery(&queue->ctrl->ctrl);
		break;
	default:
		dev_info(queue->ctrl->ctrl.device,
			"queue %d socket state %d\n",
			nvme_tcp_queue_id(queue), sk->sk_state);
	}

	queue->sc(sk);
done:
	read_unlock(&sk->sk_callback_lock);
}

static void nvme_tcp_fail_request(struct nvme_tcp_request *req)
{
	struct nvme_tcp_cmd_pdu *pdu = req->pdu;
	struct request *rq = blk_mq_tag_to_rq(nvme_tcp_tagset(req->queue),
		pdu->cmd.common.command_id);
	union nvme_result res = {};

	nvme_end_request(rq, NVME_SC_DATA_XFER_ERROR | NVME_SC_DNR, res);
}

static int nvme_tcp_try_send_data(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;

	while (true) {
		struct page *page = nvme_tcp_req_cur_page(req);
		size_t offset = nvme_tcp_req_cur_offset(req);
		size_t len = nvme_tcp_req_cur_length(req);
		bool last = nvme_tcp_req_last_send(req, len);
		int flags, ret;

		if (last)
			flags = MSG_DONTWAIT | MSG_EOR;
		else
			flags = MSG_DONTWAIT | MSG_MORE;

		ret = kernel_sendpage(queue->sock, page, offset, len, flags);
		if (ret <= 0)
			return ret;

		/* fully successfull last write*/
		if (last && ret == len)
			return 1;

		nvme_tcp_advance_req(req, ret);
	}
	return -EAGAIN;
}

static void nvme_tcp_prep_inline(struct nvme_tcp_request *req)
{
	req->tx.state = NVME_TCP_SEND_INLINE;
	nvme_tcp_prep_send_bio(req);
}

static int nvme_tcp_try_send_pdu(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;
	struct nvme_tcp_tx_context *tx = &req->tx;
	struct nvme_tcp_cmd_pdu *pdu = req->pdu;
	bool has_data =  nvme_is_write(&pdu->cmd) && req->data_len > 0;
	int flags = MSG_DONTWAIT | (has_data ? MSG_MORE : MSG_EOR);
	int len = sizeof(*pdu) - tx->offset;
	int ret;

	ret = kernel_sendpage(queue->sock, virt_to_page(pdu),
			offset_in_page(pdu) + tx->offset, len,  flags);
	if (unlikely(ret <= 0))
		return ret;

	len -= ret;
	if (!len) {
		if (has_data)
			nvme_tcp_prep_inline(req);
		return 1;
	}
	tx->offset += ret;

	return -EAGAIN;
}

static int nvme_tcp_try_send(struct nvme_tcp_request *req)
{
	int ret = 1;

	if (req->tx.state == NVME_TCP_SEND_PDU) {
		ret = nvme_tcp_try_send_pdu(req);
		if (ret <= 0)
			goto done;
	}

	if (req->tx.state == NVME_TCP_SEND_INLINE)
		ret = nvme_tcp_try_send_data(req);

done:
	if (ret == -EAGAIN)
		ret = 0;
	return ret;
}

static void nvme_tcp_io_work(struct work_struct *w)
{
	struct nvme_tcp_queue *queue =
		container_of(w, struct nvme_tcp_queue, io_work);
	unsigned long start = jiffies;
	int result;

	while (true) {
		if (!queue->tx.request) {
			queue->tx.request = nvme_tcp_fetch_request(queue);
			if (!queue->tx.request)
				return;
		}

		result = nvme_tcp_try_send(queue->tx.request);
		if (unlikely(result < 0)) {
			dev_err(queue->ctrl->ctrl.device,
				"failed to issue request to controller: %d\n", result);
			nvme_tcp_fail_request(queue->tx.request);
			return;
		}

		if (result == 0)
			return;
		queue->tx.request = NULL;

		 /* break if quota is exhausted */
		if (time_after(jiffies, start)) {
			queue_work_on(queue->io_cpu, nvme_tcp_wq,
				&queue->io_work);
			return;
		}
	}
}

static void nvme_tcp_free_async_req(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *async = &queue->async_req;

	kfree(async->pdu);
}

static int nvme_tcp_alloc_async_req(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *async = &queue->async_req;

	async->pdu = kzalloc(sizeof(struct nvme_tcp_cmd_pdu), GFP_KERNEL);
	if (!async->pdu)
		return -ENOMEM;
	async->queue = queue;
	return 0;
}

static void nvme_tcp_free_queue(struct nvme_ctrl *nctrl, int qid)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[qid];

	if (test_and_set_bit(NVME_TCP_Q_DELETING, &queue->flags))
		return;

	if (!qid)
		nvme_tcp_free_async_req(queue);

	sock_release(queue->sock);
}

static int nvme_tcp_alloc_queue(struct nvme_ctrl *nctrl,
		int qid, size_t queue_size)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[qid];
	int ret, opt;

	queue->ctrl = ctrl;
	INIT_LIST_HEAD(&queue->send_list);
	spin_lock_init(&queue->lock);
	INIT_WORK(&queue->io_work, nvme_tcp_io_work);
	queue->cmnd_capsule_len = ctrl->ctrl.ioccsz * 16;
	queue->queue_size = queue_size;

	ret = sock_create(ctrl->addr.ss_family, SOCK_STREAM,
			IPPROTO_TCP, &queue->sock);
	if (ret) {
		dev_err(ctrl->ctrl.device,
			"failed to create socket: %d\n", ret);
		return ret;
	}

	/* Single syn retry */
	opt = 1;
	ret = kernel_setsockopt(queue->sock, IPPROTO_TCP, TCP_SYNCNT,
			(char *)&opt, sizeof(opt));
	if (ret) {
		dev_err(ctrl->ctrl.device,
			"failed to set TCP_SYNCNT sock opt %d\n", ret);
		goto err_sock;
	}

	/* Set TCP no delay */
	opt = 1;
	ret = kernel_setsockopt(queue->sock, IPPROTO_TCP,
			TCP_NODELAY, (char *)&opt, sizeof(opt));
	if (ret) {
		dev_err(ctrl->ctrl.device,
			"failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}


	queue->sock->sk->sk_allocation = GFP_ATOMIC;
	queue->io_cpu = (qid == 0) ? 0 : qid - 1;
	queue->tx.request = NULL;
	queue->rx.data_remaining = 0;
	queue->rx.comp_remaining = 0;
	sk_set_memalloc(queue->sock->sk);

	if (ctrl->ctrl.opts->mask & NVMF_OPT_HOST_TRADDR) {
		ret = kernel_bind(queue->sock, (struct sockaddr *)&ctrl->src_addr,
			sizeof(ctrl->src_addr));
		if (ret) {
			dev_err(ctrl->ctrl.device,
				"failed to bind queue %d socket %d\n",
				qid, ret);
			goto err_sock;
		}
	}

	dev_dbg(ctrl->ctrl.device, "connecting queue %d\n",
			nvme_tcp_queue_id(queue));

	ret = kernel_connect(queue->sock, (struct sockaddr *)&ctrl->addr,
		sizeof(ctrl->addr), 0);
	if (ret) {
		dev_err(ctrl->ctrl.device,
			"failed to connect socket: %d\n", ret);
		goto err_sock;
	}

	queue->rd_enabled = true;
	clear_bit(NVME_TCP_Q_DELETING, &queue->flags);
	nvme_tcp_queue_prepare_rx(queue);

	write_lock_bh(&queue->sock->sk->sk_callback_lock);
	queue->sock->sk->sk_user_data = queue;
	queue->sc = queue->sock->sk->sk_state_change;
	queue->dr = queue->sock->sk->sk_data_ready;
	queue->ws = queue->sock->sk->sk_write_space;
	queue->sock->sk->sk_data_ready = nvme_tcp_data_ready;
	queue->sock->sk->sk_state_change = nvme_tcp_state_change;
	queue->sock->sk->sk_write_space = nvme_tcp_write_space;
	write_unlock_bh(&queue->sock->sk->sk_callback_lock);

	return 0;

err_sock:
	sock_release(queue->sock);
	queue->sock = NULL;
	return ret;
}

static void nvme_tcp_restore_sock_calls(struct nvme_tcp_queue *queue)
{
	struct socket *sock = queue->sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data  = NULL;
	sock->sk->sk_data_ready = queue->dr;
	sock->sk->sk_state_change = queue->sc;
	sock->sk->sk_write_space  = queue->ws;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

static void nvme_tcp_stop_queue(struct nvme_ctrl *nctrl, int qid)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct nvme_tcp_queue *queue = &ctrl->queues[qid];

	if (!test_and_clear_bit(NVME_TCP_Q_LIVE, &queue->flags))
		return;

	kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	nvme_tcp_restore_sock_calls(queue);
	cancel_work_sync(&queue->io_work);
}

static int nvme_tcp_start_queue(struct nvme_ctrl *nctrl, int idx)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	int ret;

	if (idx)
		ret = nvmf_connect_io_queue(nctrl, idx);
	else
		ret = nvmf_connect_admin_queue(nctrl);

	if (!ret)
		set_bit(NVME_TCP_Q_LIVE, &ctrl->queues[idx].flags);
	else
		dev_err(nctrl->device,
			"failed to connect queue: %d ret=%d\n", idx, ret);
	return ret;
}

static void nvme_tcp_free_tagset(struct nvme_ctrl *nctrl,
		struct blk_mq_tag_set *set)
{
	blk_mq_free_tag_set(set);
}

static struct blk_mq_tag_set *nvme_tcp_alloc_tagset(struct nvme_ctrl *nctrl,
		bool admin)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	struct blk_mq_tag_set *set;
	int ret;

	if (admin) {
		set = &ctrl->admin_tag_set;
		memset(set, 0, sizeof(*set));
		set->ops = &nvme_tcp_admin_mq_ops;
		set->queue_depth = NVME_TCP_AQ_BLKMQ_DEPTH;
		set->reserved_tags = 2; /* connect + keep-alive */
		set->numa_node = NUMA_NO_NODE;
		set->cmd_size = sizeof(struct nvme_tcp_request);
		set->driver_data = ctrl;
		set->nr_hw_queues = 1;
		set->timeout = ADMIN_TIMEOUT;
	} else {
		set = &ctrl->tag_set;
		memset(set, 0, sizeof(*set));
		set->ops = &nvme_tcp_mq_ops;
		set->queue_depth = nctrl->opts->queue_size;
		set->reserved_tags = 1; /* fabric connect */
		set->numa_node = NUMA_NO_NODE;
		set->flags = BLK_MQ_F_SHOULD_MERGE;
		set->cmd_size = sizeof(struct nvme_tcp_request);
		set->driver_data = ctrl;
		set->nr_hw_queues = nctrl->queue_count - 1;
		set->timeout = NVME_IO_TIMEOUT;
	}

	ret = blk_mq_alloc_tag_set(set);
	if (ret)
		return ERR_PTR(ret);

	return set;
}

static void nvme_tcp_free_admin_queue(struct nvme_ctrl *ctrl)
{
	nvme_tcp_free_queue(ctrl, 0);
}

static void nvme_tcp_free_io_queues(struct nvme_ctrl *ctrl)
{
	int i;

	for (i = 1; i < ctrl->queue_count; i++)
		nvme_tcp_free_queue(ctrl, i);
}

static void nvme_tcp_stop_admin_queue(struct nvme_ctrl *ctrl)
{
	nvme_tcp_stop_queue(ctrl, 0);
}

static void nvme_tcp_stop_io_queues(struct nvme_ctrl *ctrl)
{
	int i;

	for (i = 1; i < ctrl->queue_count; i++)
		nvme_tcp_stop_queue(ctrl, i);
}

static int nvme_tcp_start_admin_queue(struct nvme_ctrl *ctrl)
{
	return nvme_tcp_start_queue(ctrl, 0);
}

static int nvme_tcp_start_io_queues(struct nvme_ctrl *ctrl)
{
	int i, ret = 0;

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvme_tcp_start_queue(ctrl, i);
		if (ret)
			goto out_stop_queues;
	}

	return 0;

out_stop_queues:
	for (i--; i >= 1; i--)
		nvme_tcp_stop_queue(ctrl, i);
	return ret;
}

static int nvme_tcp_alloc_admin_queue(struct nvme_ctrl *ctrl)
{
	int ret;

	ret = nvme_tcp_alloc_queue(ctrl, 0, NVME_AQ_DEPTH);
	if (ret)
		return ret;

	ret = nvme_tcp_alloc_async_req(&to_tcp_ctrl(ctrl)->queues[0]);
	if (ret)
		goto out_free_queue;

	return 0;

out_free_queue:
	nvme_tcp_free_queue(ctrl, 0);
	return ret;
}

static int nvme_tcp_alloc_io_queues(struct nvme_ctrl *ctrl)
{
	int i, ret;

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvme_tcp_alloc_queue(ctrl, i,
				ctrl->sqsize + 1);
		if (ret)
			goto out_free_queues;
	}

	return 0;

out_free_queues:
	for (i--; i >= 1; i--)
		nvme_tcp_free_queue(ctrl, i);

	return ret;
}

static unsigned int nvme_tcp_nr_io_queues(struct nvme_ctrl *ctrl)
{
	return num_online_cpus();
}

static int nvme_alloc_io_queues(struct nvme_ctrl *ctrl)
{
	unsigned int nr_io_queues;
	int ret;

	nr_io_queues = nvme_tcp_nr_io_queues(ctrl);
	ret = nvme_set_queue_count(ctrl, &nr_io_queues);
	if (ret)
		return ret;

	ctrl->queue_count = nr_io_queues + 1;
	if (ctrl->queue_count < 2)
		return 0;

	dev_info(ctrl->device,
		"creating %d I/O queues.\n", nr_io_queues);

	return nvme_tcp_alloc_io_queues(ctrl);
}

void nvme_destroy_io_queues(struct nvme_ctrl *ctrl, bool remove)
{
	nvme_tcp_stop_io_queues(ctrl);
	if (remove) {
		if (ctrl->ops->flags & NVME_F_FABRICS)
			blk_cleanup_queue(ctrl->connect_q);
		nvme_tcp_free_tagset(ctrl, ctrl->tagset);
	}
	nvme_tcp_free_io_queues(ctrl);
}
EXPORT_SYMBOL_GPL(nvme_destroy_io_queues);

int nvme_configure_io_queues(struct nvme_ctrl *ctrl, bool new)
{
	int ret;

	ret = nvme_alloc_io_queues(ctrl);
	if (ret)
		return ret;

	if (new) {
		ctrl->tagset = nvme_tcp_alloc_tagset(ctrl, false);
		if (IS_ERR(ctrl->tagset)) {
			ret = PTR_ERR(ctrl->tagset);
			goto out_free_io_queues;
		}

		if (ctrl->ops->flags & NVME_F_FABRICS) {
			ctrl->connect_q = blk_mq_init_queue(ctrl->tagset);
			if (IS_ERR(ctrl->connect_q)) {
				ret = PTR_ERR(ctrl->connect_q);
				goto out_free_tag_set;
			}
		}
       } else {
		ret = nvme_reinit_tagset(ctrl, ctrl->tagset);
		if (ret)
			goto out_free_io_queues;

		blk_mq_update_nr_hw_queues(ctrl->tagset,
			ctrl->queue_count - 1);
       }

	ret = nvme_tcp_start_io_queues(ctrl);
	if (ret)
		goto out_cleanup_connect_q;

	return 0;

out_cleanup_connect_q:
	if (new && (ctrl->ops->flags & NVME_F_FABRICS))
		blk_cleanup_queue(ctrl->connect_q);
out_free_tag_set:
       if (new)
		nvme_tcp_free_tagset(ctrl, ctrl->tagset);
out_free_io_queues:
	nvme_tcp_free_io_queues(ctrl);
       return ret;
}
EXPORT_SYMBOL_GPL(nvme_configure_io_queues);

void nvme_destroy_admin_queue(struct nvme_ctrl *ctrl, bool remove)
{
	nvme_tcp_stop_admin_queue(ctrl);
	if (remove) {
		free_opal_dev(ctrl->opal_dev);
		blk_cleanup_queue(ctrl->admin_q);
		nvme_tcp_free_tagset(ctrl, ctrl->admin_tagset);
	}
	nvme_tcp_free_admin_queue(ctrl);
}
EXPORT_SYMBOL_GPL(nvme_destroy_admin_queue);

int nvme_configure_admin_queue(struct nvme_ctrl *ctrl, bool new)
{
	bool was_suspend = !!(ctrl->ctrl_config & NVME_CC_SHN_NORMAL);
	int error;

	error = nvme_tcp_alloc_admin_queue(ctrl);
	if (error)
		return error;

	if (new) {
		ctrl->admin_tagset = nvme_tcp_alloc_tagset(ctrl, true);
		if (IS_ERR(ctrl->admin_tagset)) {
			error = PTR_ERR(ctrl->admin_tagset);
			goto out_free_queue;
		}

		ctrl->admin_q = blk_mq_init_queue(ctrl->admin_tagset);
		if (IS_ERR(ctrl->admin_q)) {
			error = PTR_ERR(ctrl->admin_q);
			goto out_free_tagset;
		}
	} else {
		error = nvme_reinit_tagset(ctrl, ctrl->admin_tagset);
		if (error)
			goto out_free_queue;
	}

	error = nvme_tcp_start_admin_queue(ctrl);
	if (error)
		goto out_cleanup_queue;

	error = ctrl->ops->reg_read64(ctrl, NVME_REG_CAP, &ctrl->cap);
	if (error) {
		dev_err(ctrl->device,
			"prop_get NVME_REG_CAP failed\n");
		goto out_cleanup_queue;
	}

	ctrl->sqsize = min_t(int, NVME_CAP_MQES(ctrl->cap), ctrl->sqsize);

	error = nvme_enable_ctrl(ctrl, ctrl->cap);
	if (error)
		goto out_cleanup_queue;

	error = nvme_init_identify(ctrl);
	if (error)
		goto out_cleanup_queue;

	if (ctrl->oacs & NVME_CTRL_OACS_SEC_SUPP) {
		if (!ctrl->opal_dev)
			ctrl->opal_dev = init_opal_dev(ctrl, &nvme_sec_submit);
		else if (was_suspend)
			opal_unlock_from_suspend(ctrl->opal_dev);
	} else {
		free_opal_dev(ctrl->opal_dev);
		ctrl->opal_dev = NULL;
	}

	return 0;

out_cleanup_queue:
	if (new)
		blk_cleanup_queue(ctrl->admin_q);
out_free_tagset:
	if (new)
		nvme_tcp_free_tagset(ctrl, ctrl->admin_tagset);
out_free_queue:
	nvme_tcp_free_admin_queue(ctrl);
	return error;
}
EXPORT_SYMBOL_GPL(nvme_configure_admin_queue);

static void nvmf_reconnect_or_remove(struct nvme_ctrl *ctrl)
{
	/* If we are resetting/deleting then do nothing */
	if (ctrl->state != NVME_CTRL_RECONNECTING) {
		WARN_ON_ONCE(ctrl->state == NVME_CTRL_NEW ||
			ctrl->state == NVME_CTRL_LIVE);
		return;
	}

	if (nvmf_should_reconnect(ctrl)) {
		dev_info(ctrl->device, "Reconnecting in %d seconds...\n",
			ctrl->opts->reconnect_delay);
		queue_delayed_work(nvme_wq, &ctrl->reconnect_work,
				ctrl->opts->reconnect_delay * HZ);
	} else {
		dev_info(ctrl->device, "Removing controller...\n");
		nvme_delete_ctrl(ctrl);
	}
}

static void nvmf_reconnect_ctrl_work(struct work_struct *work)
{
	struct nvme_ctrl *ctrl = container_of(to_delayed_work(work),
			struct nvme_ctrl, reconnect_work);
	bool changed;
	int ret;

	++ctrl->nr_reconnects;

	ret = nvme_configure_admin_queue(ctrl, false);
	if (ret)
		goto requeue;

	if (ctrl->queue_count > 1) {
		ret = nvme_configure_io_queues(ctrl, false);
		if (ret)
			goto destroy_admin;
	}

	changed = nvme_change_ctrl_state(ctrl, NVME_CTRL_LIVE);
	if (!changed) {
		/* state change failure is ok if we're in DELETING state */
		WARN_ON_ONCE(ctrl->state != NVME_CTRL_DELETING);
		return;
	}

	nvme_start_ctrl(ctrl);

	dev_info(ctrl->device, "Successfully reconnected (%d attepmpt)\n",
			ctrl->nr_reconnects);

	ctrl->nr_reconnects = 0;

	return;

destroy_admin:
	nvme_destroy_admin_queue(ctrl, false);
requeue:
	dev_info(ctrl->device, "Failed reconnect attempt %d\n",
			ctrl->nr_reconnects);
	nvmf_reconnect_or_remove(ctrl);
}

static void nvmf_error_recovery_work(struct work_struct *work)
{
	struct nvme_ctrl *ctrl = container_of(work,
			struct nvme_ctrl, err_work);

	nvme_stop_keep_alive(ctrl);

	if (ctrl->queue_count > 1) {
		nvme_stop_queues(ctrl);
		blk_mq_tagset_busy_iter(ctrl->tagset,
					nvme_cancel_request, ctrl);
		nvme_destroy_io_queues(ctrl, false);
	}

	blk_mq_quiesce_queue(ctrl->admin_q);
	blk_mq_tagset_busy_iter(ctrl->admin_tagset,
				nvme_cancel_request, ctrl);
	nvme_destroy_admin_queue(ctrl, false);

	/*
	 * queues are not a live anymore, so restart the queues to fail fast
	 * new IO
	 */
	nvme_start_queues(ctrl);
	blk_mq_unquiesce_queue(ctrl->admin_q);

	nvmf_reconnect_or_remove(ctrl);
}

static void nvme_teardown_ctrl(struct nvme_ctrl *ctrl, bool shutdown)
{
	if (ctrl->queue_count > 1) {
		nvme_stop_queues(ctrl);
		blk_mq_tagset_busy_iter(ctrl->tagset,
					nvme_cancel_request, ctrl);
		nvme_destroy_io_queues(ctrl, shutdown);
	}

	if (shutdown)
		nvme_shutdown_ctrl(ctrl);
	else
		nvme_disable_ctrl(ctrl, ctrl->cap);

	blk_mq_quiesce_queue(ctrl->admin_q);
	blk_mq_tagset_busy_iter(ctrl->admin_tagset,
				nvme_cancel_request, ctrl);
	blk_mq_unquiesce_queue(ctrl->admin_q);
	nvme_destroy_admin_queue(ctrl, shutdown);
}

static void nvme_remove_ctrl(struct nvme_ctrl *ctrl)
{
	nvme_remove_namespaces(ctrl);
	nvme_teardown_ctrl(ctrl, true);
	nvme_uninit_ctrl(ctrl);
	nvme_put_ctrl(ctrl);
}

static void nvme_del_ctrl_host(struct nvme_ctrl *ctrl)
{
	nvme_stop_ctrl(ctrl);
	nvme_remove_ctrl(ctrl);
}

static void nvme_reset_ctrl_work(struct work_struct *work)
{
	struct nvme_ctrl *ctrl =
		container_of(work, struct nvme_ctrl, reset_work);
	int ret;
	bool changed;

	nvme_stop_ctrl(ctrl);
	nvme_teardown_ctrl(ctrl, false);

	ret = nvme_configure_admin_queue(ctrl, false);
	if (ret)
		goto out_fail;

	if (ctrl->queue_count > 1) {
		ret = nvme_configure_io_queues(ctrl, false);
		if (ret)
			goto out_fail;
	}

	changed = nvme_change_ctrl_state(ctrl, NVME_CTRL_LIVE);
	if (!changed) {
		/* state change failure is ok if we're in DELETING state */
		WARN_ON_ONCE(ctrl->state != NVME_CTRL_DELETING);
		return;
	}

	nvme_start_ctrl(ctrl);

	return;

out_fail:
	dev_warn(ctrl->device, "Removing after reset failure\n");
	nvme_remove_ctrl(ctrl);
}

static int nvme_tcp_post_configure(struct nvme_ctrl *ctrl)
{
	struct nvmf_ctrl_options *opts = ctrl->opts;

	/* sanity check icdoff */
	if (ctrl->icdoff) {
		dev_err(ctrl->device, "icdoff is not supported!\n");
		return -EINVAL;
	}

	if (opts->queue_size > ctrl->maxcmd) {
		/* warn if maxcmd is lower than queue_size */
		dev_warn(ctrl->device,
			"queue_size %zu > ctrl maxcmd %u, clamping down\n",
			opts->queue_size, ctrl->maxcmd);
		opts->queue_size = ctrl->maxcmd;
	}

	if (opts->queue_size > ctrl->sqsize + 1) {
		/* warn if sqsize is lower than queue_size */
		dev_warn(ctrl->device,
			"queue_size %zu > ctrl sqsize %u, clamping down\n",
			opts->queue_size, ctrl->sqsize + 1);
		opts->queue_size = ctrl->sqsize + 1;
	}

	return 0;
}

int nvme_probe_ctrl(struct nvme_ctrl *ctrl, struct device *dev,
		const struct nvme_ctrl_ops *ops, unsigned long quirks)
{
	bool changed;
	int ret;

	ret = nvme_init_ctrl(ctrl, dev, ops, quirks);
	if (ret)
		return ret;

	INIT_WORK(&ctrl->reset_work, nvme_reset_ctrl_work);

	ret = nvme_configure_admin_queue(ctrl, true);
	if (ret)
		goto out_uninit_ctrl;

	ret = nvme_tcp_post_configure(ctrl);
	if (ret)
		goto out_remove_admin_queue;

	if (ctrl->queue_count > 1) {
		ret = nvme_configure_io_queues(ctrl, true);
		if (ret)
			goto out_remove_admin_queue;
	}

	changed = nvme_change_ctrl_state(ctrl, NVME_CTRL_LIVE);
	WARN_ON_ONCE(!changed);

	nvme_start_ctrl(ctrl);

	return 0;
out_remove_admin_queue:
	nvme_destroy_admin_queue(ctrl, true);
out_uninit_ctrl:
	nvme_uninit_ctrl(ctrl);
	return ret;
}
EXPORT_SYMBOL_GPL(nvme_probe_ctrl);


static void nvme_tcp_free_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_del(&ctrl->list);
	mutex_unlock(&nvme_tcp_ctrl_mutex);

	kfree(ctrl->queues);
	nvmf_free_options(nctrl->opts);
	kfree(ctrl);
}

static int nvme_tcp_set_sg_null(struct nvme_command *c)
{
	struct nvme_sgl_desc *sg = &c->common.dptr.sgl;

	sg->addr = 0;
	sg->length = 0;
	sg->type = (NVME_TRANSPORT_SGL_DATA_DESC << 4) |
			NVME_SGL_FMT_TRANSPORT_A;
	return 0;
}

static void nvme_tcp_submit_async_event(struct nvme_ctrl *arg, int aer_idx)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(arg);
	struct nvme_tcp_queue *queue = &ctrl->queues[0];
	struct nvme_tcp_cmd_pdu *pdu = queue->async_req.pdu;
	struct nvme_command *cmd = &pdu->cmd;

	if (WARN_ON_ONCE(aer_idx != 0))
		return;

	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.opcode = nvme_tcp_cmd;
	pdu->hdr.flags = 0;
	pdu->hdr.pdgst = 0;
	pdu->hdr.length = sizeof(pdu);

	cmd->common.opcode = nvme_admin_async_event;
	cmd->common.command_id = NVME_TCP_AQ_BLKMQ_DEPTH;
	cmd->common.flags |= NVME_CMD_SGL_METABUF;
	nvme_tcp_set_sg_null(cmd);

	queue->async_req.tx.state = NVME_TCP_SEND_PDU;
	queue->async_req.tx.offset = 0;
	queue->async_req.tx.current_bio = NULL;
	queue->async_req.rx.current_bio = NULL;
	queue->async_req.data_len = 0;

	nvme_tcp_queue_request(&queue->async_req);
}

static enum blk_eh_timer_return
nvme_tcp_timeout(struct request *rq, bool reserved)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_tcp_ctrl *ctrl = req->queue->ctrl;

	dev_dbg(ctrl->ctrl.device,
		"queue %d: timeout request %#x opcode %d\n",
		nvme_tcp_queue_id(req->queue), rq->tag,
		req->pdu->hdr.opcode);

	/* queue error recovery */
	nvmf_error_recovery(&ctrl->ctrl);

	/* fail with DNR on cmd timeout */
	nvme_req(rq)->status = NVME_SC_ABORT_REQ | NVME_SC_DNR;
	return BLK_EH_HANDLED;
}

/*
 * We cannot accept any other command until the Connect command has completed.
 */
static inline blk_status_t nvme_tcp_is_ready(struct nvme_tcp_queue *queue,
		struct request *rq)
{
	if (unlikely(!test_bit(NVME_TCP_Q_LIVE, &queue->flags))) {
		struct nvme_command *cmd = nvme_req(rq)->cmd;

		if (!blk_rq_is_passthrough(rq) ||
		    cmd->common.opcode != nvme_fabrics_command ||
		    cmd->fabrics.fctype != nvme_fabrics_type_connect) {
			/*
			 * deleting state means that the ctrl will never accept
			 * commands again, fail it permanently.
			 */
			if (queue->ctrl->ctrl.state == NVME_CTRL_DELETING) {
				nvme_req(rq)->status = NVME_SC_ABORT_REQ;
				return BLK_STS_IOERR;
			}
			/*
			 * reconnecting state means transport disruption, which
			 * can take a long time and even might fail permanently,
			 * fail fast to give upper layers a chance to failover.
			 */
			if (queue->ctrl->ctrl.state == NVME_CTRL_RECONNECTING) {
				nvme_req(rq)->status = NVME_SC_ABORT_REQ;
				return BLK_STS_IOERR;
			}
			return BLK_STS_RESOURCE; /* try again later */
		}
	}

	return 0;
}

static int nvme_tcp_map_sg_inline(struct nvme_tcp_queue *queue,
		struct nvme_tcp_request *req, struct nvme_command *c)
{
	struct nvme_sgl_desc *sg = &c->common.dptr.sgl;

	sg->addr = cpu_to_le64(queue->ctrl->ctrl.icdoff);
	sg->length = cpu_to_le32(req->data_len);
	sg->type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_OFFSET;

	return 0;
}

static blk_status_t nvme_tcp_map_data(struct nvme_tcp_queue *queue,
			struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_command *c = &req->pdu->cmd;

	c->common.flags |= NVME_CMD_SGL_METABUF;

	if (!blk_rq_payload_bytes(rq))
		nvme_tcp_set_sg_null(c);

	if (rq_data_dir(rq) == WRITE &&
	    req->data_len <= nvme_tcp_inline_data_size(queue))
		return nvme_tcp_map_sg_inline(queue, req, c);

	return 0;
}

static blk_status_t nvme_tcp_setup_cmd_pdu(struct nvme_ns *ns,
		struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_tcp_cmd_pdu *pdu = req->pdu;

	pdu->hdr.opcode = nvme_tcp_cmd;
	pdu->hdr.flags = 0;
	pdu->hdr.pdgst = 0;
	pdu->hdr.length = sizeof(pdu) +	blk_rq_payload_bytes(rq);

	return nvme_setup_cmd(ns, rq, &pdu->cmd);
}

static blk_status_t nvme_tcp_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct nvme_ns *ns = hctx->queue->queuedata;
	struct nvme_tcp_queue *queue = hctx->driver_data;
	struct request *rq = bd->rq;
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	int ret;

	WARN_ON_ONCE(rq->tag < 0);

	ret = nvme_tcp_is_ready(queue, rq);
	if (unlikely(ret))
		return ret;

	ret = nvme_tcp_setup_cmd_pdu(ns, rq);
	if (unlikely(ret))
		return ret;

	nvme_tcp_initialize_request(rq);

	ret = nvme_tcp_map_data(queue, rq);
	if (unlikely(ret)) {
		dev_err(queue->ctrl->ctrl.device,
			"Failed to map data (%d)\n", ret);
		return ret;
	}

	blk_mq_start_request(rq);

	nvme_tcp_queue_request(req);

	return BLK_STS_OK;
}

static struct blk_mq_ops nvme_tcp_mq_ops = {
	.queue_rq	= nvme_tcp_queue_rq,
	.complete	= nvme_complete_rq,
	.init_request	= nvme_tcp_init_request,
	.exit_request	= nvme_tcp_exit_request,
	.init_hctx	= nvme_tcp_init_hctx,
	.timeout	= nvme_tcp_timeout,
};

static struct blk_mq_ops nvme_tcp_admin_mq_ops = {
	.queue_rq	= nvme_tcp_queue_rq,
	.complete	= nvme_complete_rq,
	.init_request	= nvme_tcp_init_request,
	.exit_request	= nvme_tcp_exit_request,
	.init_hctx	= nvme_tcp_init_admin_hctx,
	.timeout	= nvme_tcp_timeout,
};

static const struct nvme_ctrl_ops nvme_tcp_ctrl_ops = {
	.name			= "tcp",
	.module			= THIS_MODULE,
	.flags			= NVME_F_FABRICS,
	.reg_read32		= nvmf_reg_read32,
	.reg_read64		= nvmf_reg_read64,
	.reg_write32		= nvmf_reg_write32,
	.free_ctrl		= nvme_tcp_free_ctrl,
	.submit_async_event	= nvme_tcp_submit_async_event,
	.delete_ctrl		= nvme_del_ctrl_host,
	.get_address		= nvmf_get_address,
};

static struct nvme_ctrl *nvme_tcp_create_ctrl(struct device *dev,
		struct nvmf_ctrl_options *opts)
{
	struct nvme_tcp_ctrl *ctrl;
	char *port;
	int ret;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&ctrl->list);
	ctrl->ctrl.opts = opts;
	ctrl->ctrl.queue_count = opts->nr_io_queues + 1; /* +1 for admin queue */
	ctrl->ctrl.sqsize = opts->queue_size - 1;
	ctrl->ctrl.kato = opts->kato;

	INIT_DELAYED_WORK(&ctrl->ctrl.reconnect_work,
			nvmf_reconnect_ctrl_work);
	INIT_WORK(&ctrl->ctrl.err_work, nvmf_error_recovery_work);

	if (opts->mask & NVMF_OPT_TRSVCID)
		port = opts->trsvcid;
	else
		port = __stringify(NVME_TCP_IP_PORT);

	ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
			opts->traddr, port, &ctrl->addr);
	if (ret) {
		pr_err("malformed address passed: %s:%s\n", opts->traddr, port);
		goto out_free_ctrl;
	}

	if (opts->mask & NVMF_OPT_HOST_TRADDR) {
		ret = inet_pton_with_scope(&init_net, AF_UNSPEC,
			opts->host_traddr, NULL, &ctrl->src_addr);
		if (ret) {
			pr_err("malformed src address passed: %s\n",
			       opts->host_traddr);
			goto out_free_ctrl;
		}
	}

	ctrl->queues = kcalloc(opts->nr_io_queues + 1, sizeof(*ctrl->queues),
				GFP_KERNEL);
	if (!ctrl->queues) {
		ret = -ENOMEM;
		goto out_free_ctrl;
	}

	ret = nvme_probe_ctrl(&ctrl->ctrl, dev, &nvme_tcp_ctrl_ops, 0);
	if (ret)
		goto out_kfree_queues;

	dev_info(ctrl->ctrl.device, "new ctrl: NQN \"%s\", addr %pISp\n",
		ctrl->ctrl.opts->subsysnqn, &ctrl->addr);

	nvme_get_ctrl(&ctrl->ctrl);

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_add_tail(&ctrl->list, &nvme_tcp_ctrl_list);
	mutex_unlock(&nvme_tcp_ctrl_mutex);

	return &ctrl->ctrl;

out_kfree_queues:
	kfree(ctrl->queues);
out_free_ctrl:
	kfree(ctrl);
	return ERR_PTR(ret);
}

static struct nvmf_transport_ops nvme_tcp_transport = {
	.name		= "tcp",
	.required_opts	= NVMF_OPT_TRADDR,
	.allowed_opts	= NVMF_OPT_TRSVCID | NVMF_OPT_RECONNECT_DELAY |
			  NVMF_OPT_HOST_TRADDR | NVMF_OPT_CTRL_LOSS_TMO,
	.create_ctrl	= nvme_tcp_create_ctrl,
};

static int __init nvme_tcp_init_module(void)
{
	nvme_tcp_wq = alloc_workqueue("nvme_tcp_wq", 0, 0);
	if (!nvme_tcp_wq)
		return -ENOMEM;

	nvmf_register_transport(&nvme_tcp_transport);
	return 0;
}

static void __exit nvme_tcp_cleanup_module(void)
{
	struct nvme_tcp_ctrl *ctrl;

	nvmf_unregister_transport(&nvme_tcp_transport);

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_for_each_entry(ctrl, &nvme_tcp_ctrl_list, list)
		nvme_delete_ctrl(&ctrl->ctrl);
	mutex_unlock(&nvme_tcp_ctrl_mutex);
	flush_workqueue(nvme_wq);

	destroy_workqueue(nvme_tcp_wq);
}

module_init(nvme_tcp_init_module);
module_exit(nvme_tcp_cleanup_module);

MODULE_LICENSE("GPL v2");
