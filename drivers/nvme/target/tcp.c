/*
 * NVMe over Fabrics TCP target.
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
#include <linux/inet.h>
#include <linux/llist.h>

#include "nvmet.h"

#define NVMET_TCP_INLINE_DATA_SIZE	(4 * PAGE_SIZE)

static unsigned nvmet_tcp_recv_budget = 8;
module_param_named(recv_budget, nvmet_tcp_recv_budget, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(recv_budget, "recvs budget");

static unsigned nvmet_tcp_send_budget = 8;
module_param_named(send_budget, nvmet_tcp_send_budget, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(send_budget, "sends budget");

static unsigned nvmet_tcp_io_work_budget = 64;
module_param_named(io_work_budget, nvmet_tcp_io_work_budget, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(io_work_budget, "io work budget");

enum nvemt_tcp_tx_state {
	NVMET_SEND_DATA_PDU = 0,
	NVMET_SEND_DATA,
	NVMET_SEND_RESPONSE
};

enum nvemt_tcp_rx_state {
	NVMET_RECV_PDU = 0,
	NVMET_RECV_INLINE_DATA,
	NVMET_RECV_ERR_DATA,
};

struct nvmet_tcp_tx_context {
	u32			offset;
	struct scatterlist	*cur_sg;
	enum nvemt_tcp_tx_state state;
};

struct nvmet_tcp_cmd {
	struct nvmet_tcp_queue		*queue;
	struct nvmet_req		req;

	struct nvme_tcp_cmd_pdu		*cmd_pdu;
	struct nvme_tcp_comp_pdu	*rsp_pdu;
	struct nvme_tcp_data_pdu	*data_pdu;

	u32				rbytes_done;
	u32				wbytes_done;

	u32				nr_inline;
	u32				inline_len;
	struct msghdr			recv_msg;
	struct kvec			*iov;
	u32				flags;

	struct list_head		entry;
	struct llist_node		lentry;
	struct nvmet_tcp_tx_context	tx;
};

enum nvmet_tcp_queue_state {
	NVMET_TCP_Q_CONNECTING,
	NVMET_TCP_Q_LIVE,
	NVMET_TCP_Q_DISCONNECTING,
};

struct nvmet_tcp_queue_rx_context {
	struct nvme_tcp_cmd_pdu		pdu;
	int				offset;
	enum nvemt_tcp_rx_state 	state;
	struct nvmet_tcp_cmd		*cmd;
};

struct nvmet_tcp_queue {
	struct socket		*sock;
	struct nvmet_tcp_port	*port;

	struct nvmet_tcp_cmd	*cmds;
	unsigned		nr_cmds;
	struct list_head	free_list;
	struct llist_head	resp_list;
	struct list_head	resp_send_list;
	int			send_list_len;

	spinlock_t		state_lock;
	enum nvmet_tcp_queue_state state;
	struct nvmet_cq		nvme_cq;
	struct nvmet_sq		nvme_sq;

	struct sockaddr_storage	sockaddr;
	struct sockaddr_storage	sockaddr_peer;
	struct work_struct	release_work;
	struct work_struct	io_work;

	int			idx;
	int			cpu;

	struct list_head	queue_list;
	struct nvmet_tcp_cmd	*tx_cmd;
	struct nvmet_tcp_queue_rx_context rx;

	struct nvmet_tcp_cmd	connect;

	void (*old_data_ready)(struct sock *);
	void (*old_state_change)(struct sock *);
	void (*old_write_space)(struct sock *);
};

struct nvmet_tcp_port {
	struct socket		*sock;
	struct work_struct	accept_work;
	struct nvmet_port	*nport;
	void (*old_data_ready)  (struct sock *);
};

static DEFINE_IDA(nvmet_tcp_queue_ida);
static LIST_HEAD(nvmet_tcp_queue_list);
static DEFINE_MUTEX(nvmet_tcp_queue_mutex);

static struct workqueue_struct *nvmet_tcp_wq;
static struct nvmet_fabrics_ops nvmet_tcp_ops;

static inline bool nvmet_tcp_need_data_in(struct nvmet_tcp_cmd *cmd)
{
	return nvme_is_write(cmd->req.cmd) &&
		cmd->rbytes_done < cmd->req.data_len;
}

static inline bool nvmet_tcp_has_write_data(struct nvmet_tcp_cmd *cmd)
{
	return !nvme_is_write(cmd->req.cmd) &&
		cmd->req.data_len > 0 &&
		!cmd->req.rsp->status;
}

static inline bool nvmet_tcp_has_inline(struct nvmet_tcp_cmd *cmd)
{
	/* FIXME: enforce in-capsule data length */
	return nvme_is_write(cmd->req.cmd) && cmd->req.data_len;
}

static inline struct nvmet_tcp_cmd *
nvmet_tcp_get_cmd(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_cmd *cmd;

	cmd = list_first_entry_or_null(&queue->free_list,
				struct nvmet_tcp_cmd, entry);
	if (!cmd)
		return NULL;
	list_del_init(&cmd->entry);

	cmd->rbytes_done = cmd->wbytes_done = 0;
	cmd->nr_inline = 0;
	cmd->inline_len = 0;
	cmd->iov = NULL;
	cmd->flags = 0;
	return cmd;
}

static inline void nvmet_tcp_put_cmd(struct nvmet_tcp_cmd *cmd)
{
	list_add_tail(&cmd->entry, &cmd->queue->free_list);
}

static void nvmet_tcp_free_sgl(struct scatterlist *sgl, unsigned int nents)
{
	struct scatterlist *sg;
	int count;

	if (!sgl || !nents)
		return;

	for_each_sg(sgl, sg, nents, count)
		put_page(sg_page(sg));
	kfree(sgl);
}

static int nvmet_tcp_alloc_sgl(struct scatterlist **sgl, unsigned int *nents,
		u32 length)
{
	struct scatterlist *sg;
	struct page *page;
	unsigned int nent;
	int i = 0;

	nent = DIV_ROUND_UP(length, PAGE_SIZE);
	sg = kmalloc_array(nent, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sg)
		goto out;

	sg_init_table(sg, nent);

	while (length) {
		u32 page_len = min_t(u32, length, PAGE_SIZE);

		page = alloc_page(GFP_KERNEL);
		if (!page)
			goto out_put_pages;

		sg_set_page(&sg[i], page, page_len, 0);
		length -= page_len;
		i++;
	}
	*sgl = sg;
	*nents = nent;
	return 0;

out_put_pages:
	while (i > 0) {
		i--;
		put_page(sg_page(&sg[i]));
	}
	kfree(sg);
out:
	return -ENOMEM;
}

static void nvmet_tcp_free_recv_iovec(struct scatterlist *sgl,
		unsigned int nents, struct kvec *iovec)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i)
		kunmap(sg_page(sg));
	kfree(iovec);
}

static int nvmet_tcp_alloc_recv_iovec(struct scatterlist *sgl,
		unsigned int nents, u32 length, struct kvec **iovec)
{
	struct scatterlist *sg;
	struct kvec *iov;
	int i;

	iov = kmalloc_array(nents, sizeof(*iov), GFP_KERNEL);
	if (!iov)
		goto out;

	for_each_sg(sgl, sg, nents, i) {
		iov[i].iov_base = kmap(sg_page(sg)) + sg->offset;
		iov[i].iov_len = sg->length;
	}

	*iovec = iov;
	return 0;

out:
	kfree(iov);
	return -ENOMEM;
}

static void nvmet_tcp_fatal_error(struct nvmet_tcp_queue *queue)
{
	if (queue->nvme_sq.ctrl)
		nvmet_ctrl_fatal_error(queue->nvme_sq.ctrl);
	else
		kernel_sock_shutdown(queue->sock, SHUT_RDWR);
}

static int nvmet_tcp_map_data(struct nvmet_tcp_cmd *cmd)
{
	int ret;

	if (!cmd->req.data_len)
		return 0;

	ret = nvmet_tcp_alloc_sgl(&cmd->req.sg, &cmd->req.sg_cnt,
			cmd->req.data_len);

	if (ret)
		return ret;

	cmd->tx.cur_sg = cmd->req.sg;

	if (nvmet_tcp_need_data_in(cmd)) {
		ret = nvmet_tcp_alloc_recv_iovec(cmd->req.sg, cmd->req.sg_cnt,
				cmd->req.data_len, &cmd->iov);
		if (ret)
			goto err;
	}

	return 0;
err:
	nvmet_tcp_free_sgl(cmd->req.sg, cmd->req.sg_cnt);
	return ret;
}

static void nvmet_prepare_data_command(struct nvmet_tcp_cmd *cmd)
{
	struct nvme_tcp_data_pdu *pdu = cmd->data_pdu;

	cmd->tx.offset = 0;
	cmd->tx.state = NVMET_SEND_DATA_PDU;

	pdu->hdr.opcode = nvme_tcp_data_c2h;
	pdu->hdr.flags = 0;
	pdu->hdr.pdgst = 0;
	pdu->hdr.length = sizeof(pdu) + cpu_to_le32(cmd->req.data_len);

	pdu->command_id = cmd->req.rsp->command_id;
	pdu->data_length = cpu_to_le32(cmd->req.data_len);
	pdu->data_offset = cpu_to_le32(cmd->wbytes_done);
}

static void nvmet_prepare_response(struct nvmet_tcp_cmd *cmd)
{
	struct nvme_tcp_comp_pdu *pdu = cmd->rsp_pdu;

	cmd->tx.offset = 0;
	cmd->tx.state = NVMET_SEND_RESPONSE;

	pdu->hdr.opcode = nvme_tcp_comp;
	pdu->hdr.flags = 0;
	pdu->hdr.pdgst = 0;
	pdu->hdr.length = sizeof(pdu);
}

static struct nvmet_tcp_cmd *nvmet_tcp_reverse_list(struct nvmet_tcp_queue *queue, struct llist_node *node)
{
	struct nvmet_tcp_cmd *cmd;

	while (node) {
		struct nvmet_tcp_cmd *cmd = container_of(node, struct nvmet_tcp_cmd, lentry);

		list_add(&cmd->entry, &queue->resp_send_list);
		node = node->next;
		queue->send_list_len++;
	}

	cmd = list_first_entry(&queue->resp_send_list, struct nvmet_tcp_cmd, entry);
	return cmd;
}

static struct nvmet_tcp_cmd *nvmet_tcp_fetch_send_command(struct nvmet_tcp_queue *queue)
{
	struct llist_node *node;

	BUG_ON(!queue);

	queue->tx_cmd = list_first_entry_or_null(&queue->resp_send_list, struct nvmet_tcp_cmd, entry);
	if (!queue->tx_cmd) {
		node = llist_del_all(&queue->resp_list);
		if (!node)
			return NULL;
		queue->tx_cmd = nvmet_tcp_reverse_list(queue, node);
	}

	list_del_init(&queue->tx_cmd->entry);
	queue->send_list_len--;

	if (nvmet_tcp_has_write_data(queue->tx_cmd))
		nvmet_prepare_data_command(queue->tx_cmd);
	else
		nvmet_prepare_response(queue->tx_cmd);

	return queue->tx_cmd;
}

static int nvmet_try_send_data_pdu(struct nvmet_tcp_cmd *cmd)
{
	struct nvmet_tcp_tx_context *tx = &cmd->tx;
	int left_to_send = sizeof(*cmd->data_pdu) - tx->offset;
	int ret;

	BUG_ON(left_to_send <= 0);

	ret = kernel_sendpage(cmd->queue->sock, virt_to_page(cmd->data_pdu),
			offset_in_page(cmd->data_pdu) + tx->offset,
			left_to_send, MSG_DONTWAIT | MSG_MORE);
	if (ret <= 0)
		return ret;

	tx->offset += ret;
	left_to_send -= ret;

	if (left_to_send)
		return -EAGAIN;

	tx->state = NVMET_SEND_DATA;
	tx->offset  = 0;
	return 1;
}

static int nvmet_try_send_data(struct nvmet_tcp_cmd *cmd)
{
	struct nvmet_tcp_tx_context *tx = &cmd->tx;
	int ret;

	while (tx->cur_sg) {
		u32 left_to_send = tx->cur_sg->length - tx->offset;

		BUG_ON(tx->offset >= tx->cur_sg->length);

		ret = kernel_sendpage(cmd->queue->sock, sg_page(tx->cur_sg),
				tx->offset, left_to_send,
				MSG_DONTWAIT | MSG_MORE);
		if (ret <= 0)
			return ret;

		tx->offset += ret;
		cmd->wbytes_done += ret;

		/* Done with sg?*/
		if (tx->offset == tx->cur_sg->length) {
			tx->cur_sg = sg_next(tx->cur_sg);
			tx->offset = 0;
		}
	}

	nvmet_prepare_response(cmd);
	return 1;

}

static int nvmet_try_send_response(struct nvmet_tcp_cmd *cmd, bool last_in_batch)
{
	struct nvmet_tcp_tx_context *tx = &cmd->tx;
	int left_to_send = sizeof(*cmd->rsp_pdu) - tx->offset;
	int flags = MSG_DONTWAIT;
	int ret;

	if (!last_in_batch && cmd->queue->send_list_len)
		flags |= MSG_MORE;
	else
		flags |= MSG_EOR;

	ret = kernel_sendpage(cmd->queue->sock, virt_to_page(cmd->rsp_pdu),
			offset_in_page(cmd->rsp_pdu) + tx->offset,
			left_to_send, flags);
	if (ret <= 0)
		return ret;
	tx->offset += ret;
	left_to_send -= ret;

	if (left_to_send)
		return -EAGAIN;

	nvmet_tcp_free_recv_iovec(cmd->req.sg, cmd->req.sg_cnt, cmd->iov);
	nvmet_tcp_free_sgl(cmd->req.sg, cmd->req.sg_cnt);
	cmd->queue->tx_cmd = NULL;
	nvmet_tcp_put_cmd(cmd);
	return 1;
}

static int nvmet_tcp_try_send_one(struct nvmet_tcp_queue *queue,
		bool last_in_batch)
{
	struct nvmet_tcp_cmd *cmd = queue->tx_cmd;
	int ret = 0;

	if (!cmd || queue->state == NVMET_TCP_Q_DISCONNECTING) {
		cmd = nvmet_tcp_fetch_send_command(queue);
		if (unlikely(!cmd))
			return 0;
	}

	if (cmd->tx.state == NVMET_SEND_DATA_PDU) {
		ret = nvmet_try_send_data_pdu(cmd);
		if (ret <= 0)
			goto done_send;
	}

	if (cmd->tx.state == NVMET_SEND_DATA) {
		ret = nvmet_try_send_data(cmd);
		if (ret <= 0)
			goto done_send;
	}

	if (cmd->tx.state == NVMET_SEND_RESPONSE)
		ret = nvmet_try_send_response(cmd, last_in_batch);

done_send:
	if (ret < 0) {
		if (ret == -EAGAIN)
			return 0;
		return ret;
	}

	return 1;
}

static int nvmet_tcp_try_send(struct nvmet_tcp_queue *queue,
		int budget, int *sends)
{
	int i, ret = 0;

	for (i = 0; i < budget; i++) {
		ret = nvmet_tcp_try_send_one(queue, i == budget - 1);
		if (ret <= 0)
			break;
		(*sends)++;
	}

	return ret;
}

static void nvmet_prepare_receive_pdu(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_queue_rx_context *rx = &queue->rx;

	rx->offset = 0;
	rx->cmd = NULL;
	rx->state = NVMET_RECV_PDU;
}

static void nvmet_tcp_init_inline_data(struct nvmet_tcp_cmd  *cmd)
{
	/*
	 * FIXME: we should consider NVMET_TCP_INLINE_DATA_SIZE constant
	 * but currently everything is inline
	 */
	cmd->inline_len = cmd->req.data_len;
	cmd->nr_inline = DIV_ROUND_UP(cmd->inline_len, PAGE_SIZE);
	iov_iter_kvec(&cmd->recv_msg.msg_iter, READ | ITER_KVEC,
			cmd->iov, cmd->nr_inline, cmd->inline_len);
}

static int nvmet_tcp_done_recv_pdu(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_queue_rx_context *rx = &queue->rx;
	struct nvme_command *nvme_cmd = (void *)&rx->pdu.cmd;
	struct nvmet_req *req;
	int ret;

	if (rx->pdu.hdr.opcode == nvme_tcp_data_h2c) {
		/* FIXME: need to handle non-inline data */
		pr_err("%s: data pdu\n", __func__);
		BUG();
		nvmet_prepare_receive_pdu(queue);
		return 0;
	}

	rx->cmd = nvmet_tcp_get_cmd(queue);
	if (unlikely(!rx->cmd)) {
		/* This should never happen */
		pr_err("failed to allocate command in queue %d queue->nr_cmds: %d, send_list_len: %d, opcode: %d",
			queue->idx, queue->nr_cmds, queue->send_list_len, nvme_cmd->common.opcode);
		BUG();
		return -ENOMEM;
	}

	req = &rx->cmd->req;
	memcpy(req->cmd, nvme_cmd, sizeof(*nvme_cmd));

	if (unlikely(!nvmet_req_init(req, &queue->nvme_cq,
			&queue->nvme_sq, &nvmet_tcp_ops))) {
		pr_err("%s: failed cmd %p id %d opcode %d, data_len: %d\n", __func__,
			req->cmd, req->cmd->common.command_id, req->cmd->common.opcode,
			le32_to_cpu(req->cmd->common.dptr.sgl.length));
		req->data_len = le32_to_cpu(req->cmd->common.dptr.sgl.length);
		rx->state = NVMET_RECV_ERR_DATA;
		if (!nvmet_tcp_has_inline(rx->cmd)) {
			ret = -EAGAIN;
			goto err;
		}
	}

	ret = nvmet_tcp_map_data(rx->cmd);
	if (unlikely(ret)) {
		pr_err("Failed to allocate data for request on queue %d err=%d\n",
			queue->idx, ret);
		nvmet_req_complete(req, NVME_SC_INTERNAL);
		/*
		 * FIXME: in this stage we cannot proceed reading "next command"
		 * as there is THIS command in socket buffer but we dont know how many to read
		 * we must fail here and abort connection with this client
		 * BUT we cannot go to failure mode before we actually sent all responses
		 * so this needs some other handing than just reutrn error i.e. flush responses
		 */
		ret = -EINVAL;
		goto err;
	}

	if (nvmet_tcp_has_inline(rx->cmd)) {
		if (rx->state == NVMET_RECV_PDU)
			rx->state = NVMET_RECV_INLINE_DATA;
		nvmet_tcp_init_inline_data(rx->cmd);
		return 0;
	}

	rx->cmd->req.execute(&rx->cmd->req);
err:
	nvmet_prepare_receive_pdu(queue);
	return ret;
}

static int nvmet_tcp_try_recv_pdu(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_queue_rx_context *rx = &queue->rx;
	struct nvme_tcp_hdr *hdr;
	int len, pdu_len;
	struct kvec iov;
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};

	iov.iov_base = (void *)&rx->pdu + rx->offset;
	iov.iov_len = sizeof(rx->pdu) - rx->offset;

	len = kernel_recvmsg(queue->sock, &msg, &iov, 1,
			iov.iov_len, msg.msg_flags);
	if (len < 0)
		return len;

	rx->offset += len;
	if (rx->offset <  sizeof(struct nvme_tcp_hdr))
		return -EAGAIN;

	hdr = &rx->pdu.hdr;
	switch (hdr->opcode) {
	case nvme_tcp_cmd:
		pdu_len = sizeof(struct nvme_tcp_cmd_pdu);
		break;
	case nvme_tcp_data_h2c:
		pdu_len = sizeof(struct nvme_tcp_data_pdu);
		break;
	default:
		pr_err("unexpected nvme-tcp opcode (%d)\n", hdr->opcode);
		nvmet_tcp_fatal_error(queue);
		return -EIO;
	}

	if (rx->offset < pdu_len)
		return -EAGAIN;

	return nvmet_tcp_done_recv_pdu(queue);
}

static int nvmet_tcp_try_recv_inline_data(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_cmd  *cmd = queue->rx.cmd;
	int ret;

	while (msg_data_left(&cmd->recv_msg)) {
		ret = sock_recvmsg(cmd->queue->sock, &cmd->recv_msg,
			cmd->recv_msg.msg_flags);

		if (ret <= 0)
			return ret;

		cmd->rbytes_done += ret;
	}

	BUG_ON(cmd->rbytes_done != cmd->inline_len);

	cmd->req.execute(&cmd->req);
	nvmet_prepare_receive_pdu(queue);
	return 0;
}

static int nvmet_tcp_try_recv_err_data(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_cmd  *cmd = queue->rx.cmd;
	int ret;

	while (msg_data_left(&cmd->recv_msg)) {
		ret = sock_recvmsg(cmd->queue->sock, &cmd->recv_msg,
			cmd->recv_msg.msg_flags);

		/*
		 * FIXME: this is due to the coupling of recv and send
		 * flows in the io_work. We must not send before we return
		 * to recv because we might trigger a bad dereference.
		 */
		if (ret == 0)
			return -EIO;

		if (ret < 0)
			continue;

		cmd->rbytes_done += ret;
	}

	BUG_ON(cmd->rbytes_done != cmd->inline_len);

	nvmet_prepare_receive_pdu(queue);
	return 0;
}

static int nvmet_tcp_try_recv_one(struct nvmet_tcp_queue *queue)
{

	struct nvmet_tcp_queue_rx_context *rx = &queue->rx;
	int result;

	if (rx->state == NVMET_RECV_PDU) {
		result = nvmet_tcp_try_recv_pdu(queue);
		if (result != 0)
			goto done_recv;
	}

	if (rx->state == NVMET_RECV_INLINE_DATA) {
		result = nvmet_tcp_try_recv_inline_data(queue);
		if (result != 0)
			goto done_recv;
	}

	if (rx->state == NVMET_RECV_ERR_DATA) {
		nvmet_tcp_try_recv_err_data(queue);
	}

done_recv:
	if (result < 0) {
		if (result == -EAGAIN)
			return 0;
		return result;
	}
	return 1;
}

static int nvmet_tcp_try_recv(struct nvmet_tcp_queue *queue,
		int budget, int *recvs)
{
	int i, ret = 0;

	for (i = 0; i < budget; i++) {
		ret = nvmet_tcp_try_recv_one(queue);
		if (ret <= 0)
			break;
		(*recvs)++;
	}

	return ret;
}

static void nvmet_tcp_schedule_release_queue(struct nvmet_tcp_queue *queue)
{
	spin_lock(&queue->state_lock);
	if (queue->state == NVMET_TCP_Q_DISCONNECTING)
		goto out;

	queue->state = NVMET_TCP_Q_DISCONNECTING;
	schedule_work(&queue->release_work);
out:
	spin_unlock(&queue->state_lock);
}

static void nvmet_tcp_io_work(struct work_struct *w)
{
	struct nvmet_tcp_queue *queue =
		container_of(w, struct nvmet_tcp_queue, io_work);
	bool pending;
	int ret, ops = 0;

	do {
		pending = false;

		ret = nvmet_tcp_try_recv(queue, nvmet_tcp_recv_budget, &ops);
		if (ret > 0) {
			pending = true;
		} else if (ret < 0) {
			nvmet_tcp_fatal_error(queue);
			return;
		}

		ret = nvmet_tcp_try_send(queue, nvmet_tcp_send_budget, &ops);
		if (ret > 0) {
			/* transmitted message/data */
			pending = true;
		} else if (ret < 0) {
			nvmet_tcp_fatal_error(queue);
			return;
		}

	} while (pending && ops < nvmet_tcp_io_work_budget);

	/*
	 * We exahusted our budget, requeue our selves
	 */
	if (pending)
		queue_work_on(queue->cpu, nvmet_tcp_wq, &queue->io_work);
}

static int nvmet_tcp_alloc_cmd(struct nvmet_tcp_queue *queue,
		struct nvmet_tcp_cmd *c)
{
	c->queue = queue;
	c->req.port = queue->port->nport;

	c->cmd_pdu = kmalloc(sizeof(*c->cmd_pdu), GFP_KERNEL);
	if (!c->cmd_pdu)
		return -ENOMEM;
	c->req.cmd = &c->cmd_pdu->cmd;

	c->rsp_pdu = kmalloc(sizeof(*c->rsp_pdu), GFP_KERNEL);
	if (!c->rsp_pdu)
		goto out_free_cmd;
	c->req.rsp = &c->rsp_pdu->cqe;

	c->data_pdu = kmalloc(sizeof(*c->data_pdu), GFP_KERNEL);
	if (!c->data_pdu)
		goto out_free_rsp;

	c->recv_msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	list_add_tail(&c->entry, &queue->free_list);

	return 0;

out_free_rsp:
	kfree(c->rsp_pdu);
out_free_cmd:
	kfree(c->cmd_pdu);
	return -ENOMEM;
}

static void nvmet_tcp_free_cmd(struct nvmet_tcp_cmd *c)
{
	kfree(c->data_pdu);
	kfree(c->rsp_pdu);
	kfree(c->cmd_pdu);
}

static int nvmet_tcp_alloc_cmds(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_cmd *cmds;
	int i, ret = -EINVAL, nr_cmds = queue->nr_cmds;

	cmds = kcalloc(nr_cmds, sizeof(struct nvmet_tcp_cmd), GFP_KERNEL);
	if (!cmds)
		goto out;

	for (i = 0; i < nr_cmds; i++) {
		ret = nvmet_tcp_alloc_cmd(queue, cmds + i);
		if (ret)
			goto out_free;
	}

	queue->cmds = cmds;

	return 0;
out_free:
	while (--i >= 0)
		nvmet_tcp_free_cmd(cmds + i);
	kfree(cmds);
out:
	return ret;
}

static void nvmet_tcp_free_cmds(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_cmd *cmds = queue->cmds;
	int i;

	for (i = 0; i < queue->nr_cmds; i++)
		nvmet_tcp_free_cmd(cmds + i);

	nvmet_tcp_free_cmd(&queue->connect);

	kfree(cmds);
}

static void nvmet_tcp_restore_socket_callbacks(struct nvmet_tcp_queue *queue)
{
	struct socket *sock = queue->sock;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready =  queue->old_data_ready;
	sock->sk->sk_state_change = queue->old_state_change;
	sock->sk->sk_write_space = queue->old_write_space;
	sock->sk->sk_user_data = NULL;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

static void nvmet_tcp_release_queue_work(struct work_struct *w)
{
	struct nvmet_tcp_queue *queue =
		container_of(w, struct nvmet_tcp_queue, release_work);

	mutex_lock(&nvmet_tcp_queue_mutex);
	list_del_init(&queue->queue_list);
	mutex_unlock(&nvmet_tcp_queue_mutex);

	nvmet_tcp_restore_socket_callbacks(queue);

	nvmet_sq_destroy(&queue->nvme_sq);
	flush_work(&queue->io_work);
	sock_release(queue->sock);
	nvmet_tcp_free_cmds(queue);
	ida_simple_remove(&nvmet_tcp_queue_ida, queue->idx);

	kfree(queue);
}

static void nvmet_tcp_queue_response(struct nvmet_req *req)
{
	struct nvmet_tcp_cmd *cmd =
		container_of(req, struct nvmet_tcp_cmd, req);
	struct nvmet_tcp_queue	*queue = cmd->queue;

	llist_add(&cmd->lentry, &queue->resp_list);
	queue_work_on(cmd->queue->cpu, nvmet_tcp_wq, &cmd->queue->io_work);
}

static void nvmet_tcp_data_ready(struct sock *sk)
{
	struct nvmet_tcp_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto out;

	queue_work_on(queue->cpu, nvmet_tcp_wq, &queue->io_work);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static void nvmet_tcp_write_space(struct sock *sk)
{
	struct nvmet_tcp_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto out;

	if (sk_stream_is_writeable(sk)) {
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		queue_work_on(queue->cpu, nvmet_tcp_wq, &queue->io_work);
	}
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static void nvmet_tcp_state_change(struct sock *sk)
{
	struct nvmet_tcp_queue *queue;

	write_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	if (!queue)
		goto done;

	switch (sk->sk_state) {
	case TCP_FIN_WAIT1:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSE:
		/* FALLTHRU */
		sk->sk_user_data = NULL;
		nvmet_tcp_schedule_release_queue(queue);
		break;
	default:
		pr_warn("queue %d unhandled state %d\n", queue->idx, sk->sk_state);
	}
done:
	write_unlock_bh(&sk->sk_callback_lock);
}

static int nvmet_tcp_set_queue_sock(struct nvmet_tcp_queue *queue)
{
	struct socket *sock = queue->sock;
	int addrlen, ret;

	ret = kernel_getsockname(sock,
		(struct sockaddr *)&queue->sockaddr, &addrlen);
	if (ret)
		return ret;

	ret = kernel_getpeername(sock,
		(struct sockaddr *)&queue->sockaddr_peer, &addrlen);
	if (ret)
		return ret;

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = queue;
	queue->old_data_ready = sock->sk->sk_data_ready;
	sock->sk->sk_data_ready = nvmet_tcp_data_ready;
	queue->old_state_change = sock->sk->sk_state_change;
	sock->sk->sk_state_change = nvmet_tcp_state_change;
	queue->old_write_space = sock->sk->sk_write_space;
	sock->sk->sk_write_space = nvmet_tcp_write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	return 0;
}

static int nvmet_tcp_alloc_queue(struct nvmet_tcp_port *port,
		struct socket *newsock)
{
	struct nvmet_port *nport = port->nport;
	struct nvmet_tcp_queue *queue;
	int ret;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	INIT_WORK(&queue->release_work, nvmet_tcp_release_queue_work);
	INIT_WORK(&queue->io_work, nvmet_tcp_io_work);
	queue->sock = newsock;
	queue->port = port;
	queue->nr_cmds = 0;
	spin_lock_init(&queue->state_lock);
	queue->state = NVMET_TCP_Q_CONNECTING;
	INIT_LIST_HEAD(&queue->free_list);
	init_llist_head(&queue->resp_list);
	INIT_LIST_HEAD(&queue->resp_send_list);

	queue->idx = ida_simple_get(&nvmet_tcp_queue_ida, 0, 0, GFP_KERNEL);
	if (queue->idx < 0) {
		ret = queue->idx;
		goto out_free_queue;
	}

	ret = nvmet_tcp_alloc_cmd(queue, &queue->connect);
	if (ret)
		goto out_ida_remove;

	ret = nvmet_sq_init(&queue->nvme_sq);
	if (ret)
		goto out_ida_remove;

	queue->cpu = nport->cpus[queue->idx % nport->nr_cpus];
	nvmet_prepare_receive_pdu(queue);

	mutex_lock(&nvmet_tcp_queue_mutex);
	list_add_tail(&queue->queue_list, &nvmet_tcp_queue_list);
	mutex_unlock(&nvmet_tcp_queue_mutex);

	queue->state = NVMET_TCP_Q_LIVE;

	ret = nvmet_tcp_set_queue_sock(queue);
	if (ret)
		goto out_destroy_sq;

	queue_work_on(queue->cpu, nvmet_tcp_wq, &queue->io_work);

	return 0;
out_destroy_sq:
	mutex_lock(&nvmet_tcp_queue_mutex);
	list_del_init(&queue->queue_list);
	mutex_unlock(&nvmet_tcp_queue_mutex);
	nvmet_sq_destroy(&queue->nvme_sq);
out_ida_remove:
	ida_simple_remove(&nvmet_tcp_queue_ida, queue->idx);
out_free_queue:
	kfree(queue);
	return ret;
}

static void nvmet_tcp_accept_work(struct work_struct *w)
{
	struct nvmet_tcp_port *port =
		container_of(w, struct nvmet_tcp_port, accept_work);
	struct socket *newsock;
	int ret;

	while (true) {
		ret = kernel_accept(port->sock, &newsock, O_NONBLOCK);
		if (ret < 0) {
			if (ret != -EAGAIN)
				pr_warn("failed to accept err=%d\n", ret);
			return;
		}
		ret = nvmet_tcp_alloc_queue(port, newsock);
		if (ret) {
			pr_err("failed to allocate queue\n");
			sock_release(newsock);
		}
	}
}

static void nvmet_tcp_listen_data_ready(struct sock *sk)
{
	struct nvmet_tcp_port *port;

	read_lock_bh(&sk->sk_callback_lock);
	port = sk->sk_user_data;
	if (!port)
		goto out;

	if (sk->sk_state == TCP_LISTEN)
		schedule_work(&port->accept_work);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static int nvmet_tcp_add_port(struct nvmet_port *nport)
{
	struct nvmet_tcp_port *port;
	struct sockaddr_storage addr = { };
	__kernel_sa_family_t af;
	int opt, ret;

	switch (nport->disc_addr.adrfam) {
	case NVMF_ADDR_FAMILY_IP4:
		af = AF_INET;
		break;
	case NVMF_ADDR_FAMILY_IP6:
		af = AF_INET6;
		break;
	default:
		pr_err("address family %d not supported\n",
				nport->disc_addr.adrfam);
		return -EINVAL;
	}

	ret = inet_pton_with_scope(&init_net, af, nport->disc_addr.traddr,
			nport->disc_addr.trsvcid, &addr);
	if (ret) {
		pr_err("malformed ip/port passed: %s:%s\n",
			nport->disc_addr.traddr, nport->disc_addr.trsvcid);
		return ret;
	}

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	port->nport = nport;
	INIT_WORK(&port->accept_work, nvmet_tcp_accept_work);

	ret = sock_create(addr.ss_family, SOCK_STREAM,
				IPPROTO_TCP, &port->sock);
	if (ret) {
		pr_err("failed to create a socket\n");
		goto err_port;
	}

	port->sock->sk->sk_user_data = port;
	port->old_data_ready = port->sock->sk->sk_data_ready;
	port->sock->sk->sk_data_ready = nvmet_tcp_listen_data_ready;

	opt = 1;
	ret = kernel_setsockopt(port->sock, IPPROTO_TCP,
			TCP_NODELAY, (char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}

	ret = kernel_setsockopt(port->sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set SO_REUSEADDR sock opt %d\n", ret);
		goto err_sock;
	}

	ret = kernel_bind(port->sock, (struct sockaddr *)&addr,
			sizeof(addr));
	if (ret) {
		pr_err("failed to bind port socket %d\n", ret);
		goto err_sock;
	}

	ret = kernel_listen(port->sock, 128);
	if (ret) {
		pr_err("failed to listen %d on port sock\n", ret);
		goto err_sock;
	}

	nport->priv = port;
	pr_info("enabling port %d (%pISpc)\n",
		le16_to_cpu(nport->disc_addr.portid), &addr);

	return 0;

err_sock:
	sock_release(port->sock);
err_port:
	kfree(port);
	return ret;
}

static void nvmet_tcp_remove_port(struct nvmet_port *nport)
{
	struct nvmet_tcp_port *port = nport->priv;

	write_lock_bh(&port->sock->sk->sk_callback_lock);
	port->sock->sk->sk_data_ready = port->old_data_ready;
	port->sock->sk->sk_user_data = NULL;
	write_unlock_bh(&port->sock->sk->sk_callback_lock);
	cancel_work_sync(&port->accept_work);

	sock_release(port->sock);
	kfree(port);
}

static void nvmet_tcp_delete_ctrl(struct nvmet_ctrl *ctrl)
{
	struct nvmet_tcp_queue *queue, *n;

	mutex_lock(&nvmet_tcp_queue_mutex);
	list_for_each_entry_safe(queue, n, &nvmet_tcp_queue_list, queue_list)
		if (queue->nvme_sq.ctrl == ctrl)
			kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	mutex_unlock(&nvmet_tcp_queue_mutex);
}

static int nvmet_tcp_install_queue(struct nvmet_sq *nvme_sq)
{
	struct nvmet_tcp_queue *queue, *n;
	int ret = -EINVAL;

	/* FIXME: move queue to per controller queues list and fix delete_ctrl callout */
	mutex_lock(&nvmet_tcp_queue_mutex);
	list_for_each_entry_safe(queue, n, &nvmet_tcp_queue_list, queue_list) {
		if (&queue->nvme_sq != nvme_sq)
			continue;

		queue->nr_cmds = nvme_sq->size;
		ret = nvmet_tcp_alloc_cmds(queue);
		break;
	}
	mutex_unlock(&nvmet_tcp_queue_mutex);
	return ret;
}

static struct nvmet_fabrics_ops nvmet_tcp_ops = {
	.owner			= THIS_MODULE,
	.type			= NVMF_TRTYPE_TCP,
	.sqe_inline_size	= NVMET_TCP_INLINE_DATA_SIZE,
	.msdbd			= 1,
	.has_keyed_sgls		= 0,
	.add_port		= nvmet_tcp_add_port,
	.remove_port		= nvmet_tcp_remove_port,
	.queue_response		= nvmet_tcp_queue_response,
	.delete_ctrl		= nvmet_tcp_delete_ctrl,
	.install_queue		= nvmet_tcp_install_queue,
};

static int __init nvmet_tcp_init(void)
{
	int ret;

	nvmet_tcp_wq = alloc_workqueue("nvmet_tcp_wq", WQ_HIGHPRI, 0);
	if (!nvmet_tcp_wq)
		return -ENOMEM;

	ret = nvmet_register_transport(&nvmet_tcp_ops);
	if (ret)
		goto err;

	return 0;
err:
	destroy_workqueue(nvmet_tcp_wq);
	return ret;
}

static void __exit nvmet_tcp_exit(void)
{
	struct nvmet_tcp_queue *queue, *n;

	nvmet_unregister_transport(&nvmet_tcp_ops);

	flush_scheduled_work();
	mutex_lock(&nvmet_tcp_queue_mutex);
	list_for_each_entry_safe(queue, n, &nvmet_tcp_queue_list, queue_list)
		kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	mutex_unlock(&nvmet_tcp_queue_mutex);
	flush_scheduled_work();

	destroy_workqueue(nvmet_tcp_wq);
}

module_init(nvmet_tcp_init);
module_exit(nvmet_tcp_exit);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("nvmet-transport-3"); /* 3 == NVMF_TRTYPE_TCP */
