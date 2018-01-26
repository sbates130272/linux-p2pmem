/*
 * NVMe Over Fabrics Target Passthrough command implementation.
 * Copyright (c) 2017-2018 Western Digital Corporation or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include "../host/nvme.h"
#include "nvmet.h"

static inline struct nvme_ctrl *nvmet_pt_ctrl(struct nvmet_req *req)
{
	return req->sq->ctrl->subsys->pt_ctrl;
}

static void nvmet_passthru_req_done(struct request *rq,
		blk_status_t blk_status)
{
	struct nvmet_req *req = rq->end_io_data;
	u16 status = nvme_req(rq)->status;

	nvmet_set_result(req, nvme_req(rq)->result.u32);

	/* prioritize nvme request status over blk_status_t */
	if (!status && blk_status)
		status = NVME_SC_INTERNAL;

	nvmet_req_complete(req, status);
	__blk_put_request(rq->q, rq);

	if (req->pt_ns)
		nvme_put_ns(req->pt_ns);
}

static struct request *nvmet_blk_make_request(struct nvmet_req *req,
		struct bio *bio, gfp_t gfp_mask)
{
	struct request *rq;
	struct request_queue *queue = NULL;
	struct nvme_ctrl *pt_ctrl = nvmet_pt_ctrl(req);

	if (likely(req->sq->qid != 0))
		queue = req->pt_ns->queue;
	else
		queue = pt_ctrl->admin_q;

	rq = nvme_alloc_request(queue, req->cmd, BLK_MQ_REQ_NOWAIT,
			NVME_QID_ANY);
	if (IS_ERR(rq))
		return rq;

	for_each_bio(bio) {
		int ret = blk_rq_append_bio(rq, &bio);

		if (unlikely(ret)) {
			blk_put_request(rq);
			return ERR_PTR(ret);
		}
	}
	req->cmd->common.flags &= NVME_CMD_FUSE_FIRST | NVME_CMD_FUSE_SECOND |
		(!NVME_CMD_SGL_ALL);

	return rq;
}

static inline u16 nvmet_admin_format_nvm_start(struct nvmet_req *req)
{
	u16 status = NVME_SC_SUCCESS;
	int nsid = req->cmd->format.nsid;
	int lbaf = le32_to_cpu(req->cmd->format.cdw10) & 0x0000000F;
	struct nvme_id_ns *id;

	id = nvme_identify_ns(nvmet_pt_ctrl(req), nsid);
	if (!id)
		return NVME_SC_INTERNAL;
	/*
	 * XXX: Please update this code once NVMeOF target starts supoorting
	 * metadata. We don't support ns lba format with metadata over fabrics
	 * right now, so report error if format nvm cmd tries to format
	 * a namespace with the LBA format which has metadata.
	 */
	if (id->lbaf[lbaf].ms)
		status = NVME_SC_INVALID_NS;

	kfree(id);
	return status;
}

static inline u16 nvmet_admin_passthru_start(struct nvmet_req *req)
{
	u16 status = NVME_SC_SUCCESS;

	/*
	 * Handle command specific preprocessing and avoid commands which
	 * we don't support and cannot be rounted through default target path.
	 */
	switch (req->cmd->common.opcode) {
	case nvme_admin_format_nvm:
		status = nvmet_admin_format_nvm_start(req);
		break;
	}
	return status;
}

static inline u16 nvmet_id_ctrl_populate_fabircs_fields(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvme_id_ctrl *id;
	u16 status = NVME_SC_SUCCESS;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id) {
		status = NVME_SC_INTERNAL;
		goto out;
	}
	status = nvmet_copy_from_sgl(req, 0, id, sizeof(struct nvme_id_ctrl));
	if (status)
		goto out_free;

	/* to allow loop mode don't use passsthru ctrl value */
	id->cntlid = cpu_to_le16(ctrl->cntlid);

	id->acl = NVMET_ID_CTRL_ACL;
	/* XXX: update these values when AER is implemented for the passthru */
	id->aerl = 0;

	/* we always emulate kas as most of the PCIe ctrl don't support kas */
	id->kas = cpu_to_le16(NVMET_KAS);

	/* don't support host memory buffer */
	id->hmpre = 0;
	id->hmmin = 0;

	id->sqes = min((__u8)NVMET_ID_CTRL_SQES, id->sqes);
	id->cqes = min((__u8)NVMET_ID_CTRL_CQES, id->cqes);
	id->maxcmd = cpu_to_le16(NVMET_MAX_CMD);

	/* don't support fuse commands */
	id->fuses = 0;

	id->sgls = cpu_to_le32(1 << 0); /* we always support SGLs */
	if (ctrl->ops->has_keyed_sgls)
		id->sgls |= cpu_to_le32(1 << 2);
	if (ctrl->ops->sqe_inline_size)
		id->sgls |= cpu_to_le32(1 << 20);

	/* Don't use passthru ctrl subnqn, it will fail in the loopback mode */
	memcpy(id->subnqn, ctrl->subsysnqn, sizeof(id->subnqn));

	/* use fabric id-ctrl values */
	id->ioccsz = cpu_to_le32((sizeof(struct nvme_command) +
				ctrl->ops->sqe_inline_size) / 16);
	id->iorcsz = cpu_to_le32(sizeof(struct nvme_completion) / 16);

	id->msdbd = ctrl->ops->msdbd;

	status = nvmet_copy_to_sgl(req, 0, id, sizeof(struct nvme_id_ctrl));

out_free:
	kfree(id);
out:
	return status;
}

static inline u16 nvmet_id_ns_populate_fabircs_fields(struct nvmet_req *req)
{
	int i;
	struct nvme_id_ns *id;
	u16 status = NVME_SC_SUCCESS;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id) {
		status = NVME_SC_INTERNAL;
		goto out;
	}

	status = nvmet_copy_from_sgl(req, 0, id, sizeof(struct nvme_id_ns));
	if (status)
		goto out_free;

	/* don't report the metadata support, clear respective fields */
	for (i = 0; i < id->nlbaf + 1; i++)
		if (id->lbaf[i].ms)
			memset(&id->lbaf[i], 0, sizeof(id->lbaf[i]));

	id->flbas = id->flbas & ~(1 << 4);
	id->mc = 0;

	status = nvmet_copy_to_sgl(req, 0, id, sizeof(*id));

out_free:
	kfree(id);
out:
	return status;
}

static inline u16 nvmet_admin_cmd_identify_end(struct nvmet_req *req)
{
	u16 status = NVME_SC_SUCCESS;

	switch (req->cmd->identify.cns) {
	case NVME_ID_CNS_CTRL:
		status = nvmet_id_ctrl_populate_fabircs_fields(req);
		break;
	case NVME_ID_CNS_NS:
		status = nvmet_id_ns_populate_fabircs_fields(req);
		break;
	}

	return status;
}

static u16 nvmet_admin_passthru_end(struct nvmet_req *req)
{
	u16 status = NVME_SC_SUCCESS;

	switch (req->cmd->common.opcode) {
	case nvme_admin_identify:
		status = nvmet_admin_cmd_identify_end(req);
		break;
	case nvme_admin_ns_mgmt:
	case nvme_admin_ns_attach:
	case nvme_admin_format_nvm:
		nvmet_add_async_event(req->sq->ctrl,
				NVME_AER_TYPE_NOTICE, 0, 0);
		break;
	}
	return status;
}

static void nvmet_execute_admin_cmd(struct nvmet_req *req,
		struct request *ptrq)
{
	u16 status;
	u32 effects;

	status = nvmet_admin_passthru_start(req);
	if (status) {
		nvmet_req_complete(req, status);
		goto out;
	}
	effects = nvme_passthru_start(nvmet_pt_ctrl(req), NULL,
			req->cmd->common.opcode);
	blk_execute_rq(ptrq->q, NULL, ptrq, 0);

	nvme_passthru_end(nvmet_pt_ctrl(req), effects);
	status = nvmet_admin_passthru_end(req);

	if (status)
		nvmet_req_complete(req, status);
	else {
		nvmet_set_result(req, nvme_req(ptrq)->result.u32);
		nvmet_req_complete(req, nvme_req(ptrq)->status);
	}
out:
	__blk_put_request(ptrq->q, ptrq);
}

static void nvmet_execute_passthru(struct nvmet_req *req)
{
	int i;
	int op = REQ_OP_READ;
	int op_flags = 0;
	int sg_cnt = req->sg_cnt;
	struct scatterlist *sg;
	struct bio *bio = NULL;
	struct bio *prev = NULL;
	struct bio *first_bio = NULL;
	struct request *ptrq;

	if (nvme_is_write(req->cmd)) {
		op = REQ_OP_WRITE;
		op_flags = REQ_SYNC;
	}
	if (req->sg_cnt) {
		bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
		first_bio = bio;
		bio->bi_end_io = bio_put;

		for_each_sg(req->sg, sg, req->sg_cnt, i) {
			if (bio_add_page(bio, sg_page(sg), sg->length,
						sg->offset) != sg->length) {
				prev = bio;
				bio_set_op_attrs(bio, op, op_flags);
				bio = bio_alloc(GFP_KERNEL,
						min(sg_cnt, BIO_MAX_PAGES));
				bio_chain(bio, prev);
			}
			sg_cnt--;
		}
	}
	ptrq = nvmet_blk_make_request(req, first_bio, GFP_KERNEL);
	if (!ptrq || IS_ERR(ptrq))
		goto fail_free_bio;

	if (likely(req->sq->qid != 0)) {
		ptrq->end_io_data = req;
		blk_execute_rq_nowait(ptrq->q, NULL, ptrq, 0,
				nvmet_passthru_req_done);
	} else
		nvmet_execute_admin_cmd(req, ptrq);
	return;

fail_free_bio:
	while (first_bio) {
		bio = first_bio;
		first_bio = first_bio->bi_next;
		bio_endio(bio);
	}
}

static inline bool nvmet_is_passthru_admin_cmd_supported(struct nvmet_req *req)
{
	bool ret = true;
	unsigned int fid;
	struct nvme_command *cmd = req->cmd;

	switch (cmd->common.opcode) {
	/* black listed commands */
	case nvme_admin_create_sq:
	case nvme_admin_create_cq:
	case nvme_admin_delete_sq:
	case nvme_admin_delete_cq:
	case nvme_fabrics_command:
	case nvme_admin_async_event:	/* not implemented */
	case nvme_admin_activate_fw:
	case nvme_admin_download_fw:
	case nvme_admin_directive_send:
	case nvme_admin_directive_recv:
	case nvme_admin_dbbuf:
	case nvme_admin_security_send:
	case nvme_admin_security_recv:
	/*
	 * Most PCIe ctrls don't support keep alive cmd, we route
	 * keep alive to the non-passthru mode. In future please change
	 * this code when PCIe ctrls with keep alive support available.
	 */
	case nvme_admin_keep_alive:
		ret = false;
		break;
	case nvme_admin_set_features:
		fid = le32_to_cpu(req->cmd->features.fid);
		switch (fid) {
		case NVME_FEAT_NUM_QUEUES:	/* disabled */
		case NVME_FEAT_ASYNC_EVENT:	/* not implemented */
		case NVME_FEAT_KATO:		/* route through target code */
			ret = false;
			break;
		}
		break;
	}
	return ret;
}

bool nvmet_is_passthru_cmd_supported(struct nvmet_req *req)
{
	if (unlikely(req->sq->qid == 0))
		return nvmet_is_passthru_admin_cmd_supported(req);

	return true;
}

u16 nvmet_parse_passthru_cmd(struct nvmet_req *req)
{
	if (nvmet_check_ctrl_status(req, req->cmd))
		return NVME_SC_INVALID_NS | NVME_SC_DNR;

	req->data_len = req->transfer_len;
	req->execute = nvmet_execute_passthru;

	/* parse io command */
	if (likely(req->sq->qid != 0))  {
		req->pt_ns = nvme_find_get_ns(nvmet_pt_ctrl(req),
				req->cmd->rw.nsid);
		if (!req->pt_ns)
			return NVME_SC_INVALID_NS | NVME_SC_DNR;

	}
	return NVME_SC_SUCCESS;
}
