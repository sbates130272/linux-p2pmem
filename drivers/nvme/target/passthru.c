// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe Over Fabrics Target Passthrough command implementation.
 *
 * Copyright (c) 2017-2018 Western Digital Corporation or its
 * affiliates.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>

#include "../host/nvme.h"
#include "nvmet.h"

static u16 nvmet_passthru_override_id_ctrl(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvme_ctrl *pctrl = ctrl->subsys->passthru_ctrl;
	u16 status = NVME_SC_SUCCESS;
	struct nvme_id_ctrl *id;
	u32 max_hw_sectors;
	int page_shift;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id) {
		status = NVME_SC_INTERNAL;
		goto out;
	}
	status = nvmet_copy_from_sgl(req, 0, id, sizeof(*id));
	if (status)
		goto out_free;

	id->cntlid = cpu_to_le16(ctrl->cntlid);
	id->ver = cpu_to_le32(ctrl->subsys->ver);

	/*
	 * The passthru NVMe driver may have a limit on the number of segments
	 * which depends on the host's memory fragementation. To solve this,
	 * ensure mdts is limitted to the pages equal to the number of
	 * segments.
	 */
	max_hw_sectors = min_not_zero(pctrl->max_segments << (PAGE_SHIFT - 9),
				      pctrl->max_hw_sectors);

	page_shift = NVME_CAP_MPSMIN(ctrl->cap) + 12;

	id->mdts = ilog2(max_hw_sectors) + 9 - page_shift;

	id->acl = 3;
	/*
	 * We export aerl limit for the fabrics controller, update this when
	 * passthru based aerl support is added.
	 */
	id->aerl = NVMET_ASYNC_EVENTS - 1;

	/* emulate kas as most of the PCIe ctrl don't have a support for kas */
	id->kas = cpu_to_le16(NVMET_KAS);

	/* don't support host memory buffer */
	id->hmpre = 0;
	id->hmmin = 0;


	id->sqes = min_t(__u8, ((0x6 << 4) | 0x6), id->sqes);
	id->cqes = min_t(__u8, ((0x4 << 4) | 0x4), id->cqes);
	id->maxcmd = cpu_to_le16(NVMET_MAX_CMD);

	/* don't support fuse commands */
	id->fuses = 0;

	id->sgls = cpu_to_le32(1 << 0); /* we always support SGLs */
	if (ctrl->ops->has_keyed_sgls)
		id->sgls |= cpu_to_le32(1 << 2);
	if (req->port->inline_data_size)
		id->sgls |= cpu_to_le32(1 << 20);

	/*
	 * When passsthru controller is setup using nvme-loop transport it will
	 * export the passthru ctrl subsysnqn (PCIe NVMe ctrl) and will fail in
	 * the nvme/host/core.c in the nvme_init_subsystem()->nvme_active_ctrl()
	 * code path with duplicate ctr subsynqn. In order to prevent that we
	 * mask the passthru-ctrl subsysnqn with the target ctrl subsysnqn.
	 */
	memcpy(id->subnqn, ctrl->subsysnqn, sizeof(id->subnqn));

	/* use fabric id-ctrl values */
	id->ioccsz = cpu_to_le32((sizeof(struct nvme_command) +
				req->port->inline_data_size) / 16);
	id->iorcsz = cpu_to_le32(sizeof(struct nvme_completion) / 16);

	id->msdbd = ctrl->ops->msdbd;

	/* Support multipath connections with fabrics */
	id->cmic |= 1 << 1;

	status = nvmet_copy_to_sgl(req, 0, id, sizeof(struct nvme_id_ctrl));

out_free:
	kfree(id);
out:
	return status;
}

static u16 nvmet_passthru_override_id_ns(struct nvmet_req *req)
{
	u16 status = NVME_SC_SUCCESS;
	struct nvme_id_ns *id;
	int i;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id) {
		status = NVME_SC_INTERNAL;
		goto out;
	}

	status = nvmet_copy_from_sgl(req, 0, id, sizeof(struct nvme_id_ns));
	if (status)
		goto out_free;

	for (i = 0; i < (id->nlbaf + 1); i++)
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

static u16 nvmet_passthru_fixup_identify(struct nvmet_req *req)
{
	u16 status = NVME_SC_SUCCESS;

	switch (req->cmd->identify.cns) {
	case NVME_ID_CNS_CTRL:
		status = nvmet_passthru_override_id_ctrl(req);
		break;
	case NVME_ID_CNS_NS:
		status = nvmet_passthru_override_id_ns(req);
		break;
	}
	return status;
}

static u16 nvmet_passthru_admin_passthru_end(struct nvmet_req *req)
{
	u8 aer_type = NVME_AER_TYPE_NOTICE;
	u16 status = NVME_SC_SUCCESS;

	switch (req->cmd->common.opcode) {
	case nvme_admin_identify:
		status = nvmet_passthru_fixup_identify(req);
		break;
	case nvme_admin_ns_mgmt:
	case nvme_admin_ns_attach:
	case nvme_admin_format_nvm:
		if (nvmet_add_async_event(req->sq->ctrl, aer_type, 0, 0))
			status = NVME_SC_INTERNAL;
		break;
	}
	return status;
}

static void nvmet_passthru_req_done(struct request *rq,
				    blk_status_t blk_status)
{
	struct nvmet_req *req = rq->end_io_data;
	u16 status = nvme_req(rq)->status;

	if (unlikely(req->sq->qid == 0) && status == NVME_SC_SUCCESS)
		status = nvmet_passthru_admin_passthru_end(req);

	req->cqe->result = nvme_req(rq)->result;
	nvmet_req_complete(req, status);
	blk_put_request(rq);
}

static int nvmet_passthru_map_sg(struct nvmet_req *req, struct request *rq)
{
	int sg_cnt = req->sg_cnt;
	struct scatterlist *sg;
	int op_flags = 0;
	struct bio *bio;
	int i, ret;

	if (req->cmd->common.opcode == nvme_cmd_flush)
		op_flags = REQ_FUA;
	else if (nvme_is_write(req->cmd))
		op_flags = REQ_SYNC | REQ_IDLE;


	bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
	bio->bi_end_io = bio_put;

	for_each_sg(req->sg, sg, req->sg_cnt, i) {
		if (bio_add_page(bio, sg_page(sg), sg->length,
				 sg->offset) != sg->length) {
			ret = blk_rq_append_bio(rq, &bio);
			if (unlikely(ret))
				return ret;

			bio->bi_opf = req_op(rq) | op_flags;
			bio = bio_alloc(GFP_KERNEL,
					min(sg_cnt, BIO_MAX_PAGES));
		}
		sg_cnt--;
	}

	ret = blk_rq_append_bio(rq, &bio);
	if (unlikely(ret))
		return ret;

	return 0;
}

static void nvmet_passthru_execute_cmd(struct nvmet_req *req)
{
	struct request *rq = NULL;
	struct nvme_ns *ns = NULL;
	struct request_queue *q;
	u16 status;
	int ret;

	if (likely(req->sq->qid != 0)) {
		u32 nsid = le32_to_cpu(req->cmd->common.nsid);

		ns = nvme_find_get_ns(nvmet_req_passthru_ctrl(req), nsid);
		if (unlikely(!ns)) {
			pr_err("failed to get passthru ns nsid:%u\n", nsid);
			status = NVME_SC_INVALID_NS | NVME_SC_DNR;
			goto fail_out;
		}
	}

	if (ns)
		q = ns->queue;
	else
		q = nvmet_req_passthru_ctrl(req)->admin_q;

	rq = nvme_alloc_request(q, req->cmd, BLK_MQ_REQ_NOWAIT, NVME_QID_ANY);
	if (IS_ERR(rq)) {
		rq = NULL;
		status = NVME_SC_INTERNAL;
		goto fail_out;
	}

	if (req->sg_cnt) {
		ret = nvmet_passthru_map_sg(req, rq);
		if (unlikely(ret)) {
			status = NVME_SC_INTERNAL;
			goto fail_out;
		}
	}

	if (blk_rq_nr_phys_segments(rq) > queue_max_segments(rq->q)) {
		status = NVME_SC_INVALID_FIELD;
		goto fail_out;
	}

	if ((blk_rq_payload_bytes(rq) >> 9) > queue_max_hw_sectors(rq->q)) {
		status = NVME_SC_INVALID_FIELD;
		goto fail_out;
	}

	rq->end_io_data = req;
	nvme_execute_passthru_rq_nowait(rq, nvmet_passthru_req_done);

	if (ns)
		nvme_put_ns(ns);

	return;

fail_out:
	if (ns)
		nvme_put_ns(ns);
	nvmet_req_complete(req, status);
	blk_put_request(rq);
}

u16 nvmet_setup_passthru_command(struct nvmet_req *req)
{
	req->execute = nvmet_passthru_execute_cmd;
	return NVME_SC_SUCCESS;
}

/*
 * In the passthru mode we support three types for commands:-
 * 1. Commands which are black-listed.
 * 2. Commands which are routed through target code.
 * 3. Commands which are emulated in the target code, since we can't rely
 *    on passthru-ctrl and cannot route through the target code.
 */
u16 nvmet_parse_passthru_admin_cmd(struct nvmet_req *req)
{
	/*
	 * Passthru all vendor specific commands
	 */
	if (req->cmd->common.opcode >= nvme_admin_vendor_start)
		return nvmet_setup_passthru_command(req);

	switch (req->cmd->common.opcode) {
	case nvme_admin_async_event:
		req->execute = nvmet_execute_async_event;
		return 0;
	case nvme_admin_keep_alive:
		/*
		 * Most PCIe ctrls don't support keep alive cmd, we route keep
		 * alive to the non-passthru mode. In future please change this
		 * code when PCIe ctrls with keep alive support available.
		 */
		req->execute = nvmet_execute_keep_alive;
		return 0;
	case nvme_admin_set_features:
		switch (le32_to_cpu(req->cmd->features.fid)) {
		case NVME_FEAT_ASYNC_EVENT:
		case NVME_FEAT_KATO:
		case NVME_FEAT_NUM_QUEUES:
			req->execute = nvmet_execute_set_features;
			return 0;
		default:
			return nvmet_setup_passthru_command(req);
		}
		break;
	case nvme_admin_get_features:
		switch (le32_to_cpu(req->cmd->features.fid)) {
		case NVME_FEAT_ASYNC_EVENT:
		case NVME_FEAT_KATO:
		case NVME_FEAT_NUM_QUEUES:
			req->execute = nvmet_execute_get_features;
			return 0;
		default:
			return nvmet_setup_passthru_command(req);
		}
		break;
	case nvme_admin_identify:
		return nvmet_setup_passthru_command(req);
	default:
		/* By default, blacklist all admin commands */
		return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
	}
}
