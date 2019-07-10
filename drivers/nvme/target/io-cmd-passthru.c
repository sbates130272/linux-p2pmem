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

/*
 * xarray to maintain one passthru subsystem per nvme controller.
 */
static DEFINE_XARRAY(passthru_subsystems);

static struct workqueue_struct *passthru_wq;

int nvmet_passthru_init(void)
{
	passthru_wq = alloc_workqueue("nvmet-passthru-wq", WQ_MEM_RECLAIM, 0);
	if (!passthru_wq)
		return -ENOMEM;

	return 0;
}

void nvmet_passthru_destroy(void)
{
	destroy_workqueue(passthru_wq);
}

int nvmet_passthru_ctrl_enable(struct nvmet_subsys *subsys)
{
	struct nvme_ctrl *ctrl;
	int ret = -EINVAL;
	void *old;

	mutex_lock(&subsys->lock);
	if (!subsys->passthru_ctrl_path)
		goto out_unlock;
	if (subsys->passthru_ctrl)
		goto out_unlock;

	if (subsys->nr_namespaces) {
		pr_info("cannot enable both passthru and regular namespaces for a single subsystem");
		goto out_unlock;
	}

	ctrl = nvme_ctrl_get_by_path(subsys->passthru_ctrl_path);
	if (IS_ERR(ctrl)) {
		ret = PTR_ERR(ctrl);
		pr_err("failed to open nvme controller %s\n",
		       subsys->passthru_ctrl_path);

		goto out_unlock;
	}

	old = xa_cmpxchg(&passthru_subsystems, ctrl->cntlid, NULL,
			 subsys, GFP_KERNEL);
	if (xa_is_err(old)) {
		ret = xa_err(old);
		goto out_put_ctrl;
	}

	if (old)
		goto out_put_ctrl;

	subsys->passthru_ctrl = ctrl;

	mutex_unlock(&subsys->lock);
	return 0;

out_put_ctrl:
	nvme_put_ctrl(ctrl);
out_unlock:
	mutex_unlock(&subsys->lock);
	return ret;
}

static void __nvmet_passthru_ctrl_disable(struct nvmet_subsys *subsys)
{
	if (subsys->passthru_ctrl) {
		xa_erase(&passthru_subsystems, subsys->passthru_ctrl->cntlid);
		nvme_put_ctrl(subsys->passthru_ctrl);
	}
	subsys->passthru_ctrl = NULL;
}

void nvmet_passthru_ctrl_disable(struct nvmet_subsys *subsys)
{
	mutex_lock(&subsys->lock);
	__nvmet_passthru_ctrl_disable(subsys);
	mutex_unlock(&subsys->lock);
}

void nvmet_passthru_subsys_free(struct nvmet_subsys *subsys)
{
	mutex_lock(&subsys->lock);
	__nvmet_passthru_ctrl_disable(subsys);
	kfree(subsys->passthru_ctrl_path);
	mutex_unlock(&subsys->lock);
}

static void nvmet_passthru_req_complete(struct nvmet_req *req,
		struct request *rq, u16 status)
{
	nvmet_req_complete(req, status);

	if (rq)
		blk_put_request(rq);
}

static void nvmet_passthru_req_done(struct request *rq,
		blk_status_t blk_status)
{
	struct nvmet_req *req = rq->end_io_data;
	u16 status = nvme_req(rq)->status;

	req->cqe->result.u32 = nvme_req(rq)->result.u32;

	nvmet_passthru_req_complete(req, rq, status);
}

static u16 nvmet_passthru_override_format_nvm(struct nvmet_req *req)
{
	int lbaf = le32_to_cpu(req->cmd->format.cdw10) & 0x0000000F;
	int nsid = le32_to_cpu(req->cmd->format.nsid);
	u16 status = NVME_SC_SUCCESS;
	struct nvme_id_ns *id;

	id = nvme_identify_ns(nvmet_req_passthru_ctrl(req), nsid);
	if (!id)
		return NVME_SC_INTERNAL;
	/*
	 * XXX: Please update this code once NVMeOF target starts supporting
	 * metadata. We don't support ns lba format with metadata over fabrics
	 * right now, so report an error if format nvm cmd tries to format
	 * a namespace with the LBA format which has metadata.
	 */
	if (id->lbaf[lbaf].ms)
		status = NVME_SC_INVALID_NS;

	kfree(id);
	return status;
}

static void nvmet_passthru_set_mdts(struct nvmet_ctrl *ctrl,
				    struct nvme_id_ctrl *id)
{
	struct nvme_ctrl *pctrl = ctrl->subsys->passthru_ctrl;
	u32 max_hw_sectors;
	int page_shift;

	/*
	 * The passthru NVMe driver may have a limit on the number
	 * of segments which depends on the host's memory fragementation.
	 * To solve this, ensure mdts is limitted to the pages equal to
	 * the number of segments.
	 */

	max_hw_sectors = min_not_zero(pctrl->max_segments << (PAGE_SHIFT - 9),
				      pctrl->max_hw_sectors);

	page_shift = NVME_CAP_MPSMIN(ctrl->cap) + 12;

	id->mdts = ilog2(max_hw_sectors) + 9 - page_shift;
}

static u16 nvmet_passthru_override_id_ctrl(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	u16 status = NVME_SC_SUCCESS;
	struct nvme_id_ctrl *id;

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

	nvmet_passthru_set_mdts(ctrl, id);

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

static u16 nvmet_passthru_admin_passthru_start(struct nvmet_req *req)
{
	u16 status = NVME_SC_SUCCESS;

	switch (req->cmd->common.opcode) {
	case nvme_admin_format_nvm:
		status = nvmet_passthru_override_format_nvm(req);
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

static void nvmet_passthru_execute_admin_cmd(struct nvmet_req *req)
{
	u8 opcode = req->cmd->common.opcode;
	u32 effects;
	u16 status;

	status = nvmet_passthru_admin_passthru_start(req);
	if (status)
		goto out;

	effects = nvme_passthru_start(nvmet_req_passthru_ctrl(req), NULL,
				      opcode);

	/*
	 * Admin Commands have side effects and it is better to handle those
	 * side effects in the submission thread context than in the request
	 * completion path, which is in the interrupt context. Also in this
	 * way, we keep the passhru admin command code path consistent with the
	 * nvme/host/core.c sync command submission APIs/IOCTLs and use
	 * nvme_passthru_start/end() to handle side effects consistently.
	 */
	blk_execute_rq(req->p.rq->q, NULL, req->p.rq, 0);

	nvme_passthru_end(nvmet_req_passthru_ctrl(req), effects);
	status = nvmet_passthru_admin_passthru_end(req);
out:
	if (status == NVME_SC_SUCCESS) {
		nvmet_set_result(req, nvme_req(req->p.rq)->result.u32);
		status = nvme_req(req->p.rq)->status;
	}

	nvmet_passthru_req_complete(req, req->p.rq, status);
}

static int nvmet_passthru_map_sg(struct nvmet_req *req, struct request *rq)
{
	int sg_cnt = req->sg_cnt;
	struct scatterlist *sg;
	int op = REQ_OP_READ;
	int op_flags = 0;
	struct bio *bio;
	int i, ret;

	if (req->cmd->common.opcode == nvme_cmd_flush) {
		op_flags = REQ_FUA;
	} else if (nvme_is_write(req->cmd)) {
		op = REQ_OP_WRITE;
		op_flags = REQ_SYNC | REQ_IDLE;
	}

	bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
	bio->bi_end_io = bio_put;

	for_each_sg(req->sg, sg, req->sg_cnt, i) {
		if (bio_add_page(bio, sg_page(sg), sg->length,
				 sg->offset) != sg->length) {
			ret = blk_rq_append_bio(rq, &bio);
			if (unlikely(ret))
				return ret;

			bio_set_op_attrs(bio, op, op_flags);
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

static struct request *nvmet_passthru_blk_make_request(struct nvmet_req *req,
		struct nvme_ns *ns, gfp_t gfp_mask)
{
	struct nvme_ctrl *passthru_ctrl = nvmet_req_passthru_ctrl(req);
	struct nvme_command *cmd = req->cmd;
	struct request_queue *q;
	struct request *rq;
	int ret;

	if (ns)
		q = ns->queue;
	else
		q = passthru_ctrl->admin_q;

	rq = nvme_alloc_request(q, cmd, BLK_MQ_REQ_NOWAIT, NVME_QID_ANY);
	if (unlikely(IS_ERR(rq)))
		return rq;

	if (blk_queue_io_stat(q))
		rq->rq_flags |= RQF_IO_STAT;

	if (req->sg_cnt) {
		ret = nvmet_passthru_map_sg(req, rq);
		if (unlikely(ret)) {
			blk_put_request(rq);
			return ERR_PTR(ret);
		}
	}

	/*
	 * We don't support fused cmds, also nvme-pci driver uses its own
	 * sgl_threshold parameter to decide whether to use SGLs or PRPs hence
	 * turn off those bits in the flags.
	 */
	req->cmd->common.flags &= ~(NVME_CMD_FUSE_FIRST | NVME_CMD_FUSE_SECOND |
			NVME_CMD_SGL_ALL);
	return rq;
}


static void nvmet_passthru_execute_admin_work(struct work_struct *w)
{
	struct nvmet_req *req = container_of(w, struct nvmet_req, p.work);

	nvmet_passthru_execute_admin_cmd(req);
}

static void nvmet_passthru_submit_admin_cmd(struct nvmet_req *req)
{
	INIT_WORK(&req->p.work, nvmet_passthru_execute_admin_work);
	queue_work(passthru_wq, &req->p.work);
}

static void nvmet_passthru_execute_cmd(struct nvmet_req *req)
{
	struct request *rq = NULL;
	struct nvme_ns *ns = NULL;
	u16 status;

	if (likely(req->sq->qid != 0)) {
		u32 nsid = le32_to_cpu(req->cmd->common.nsid);

		ns = nvme_find_get_ns(nvmet_req_passthru_ctrl(req), nsid);
		if (unlikely(!ns)) {
			pr_err("failed to get passthru ns nsid:%u\n", nsid);
			status = NVME_SC_INVALID_NS | NVME_SC_DNR;
			goto fail_out;
		}
	}

	rq = nvmet_passthru_blk_make_request(req, ns, GFP_KERNEL);
	if (unlikely(IS_ERR(rq))) {
		rq = NULL;
		status = NVME_SC_INTERNAL;
		goto fail_out;
	}

	if (unlikely(blk_rq_nr_phys_segments(rq) > queue_max_segments(rq->q) ||
	    (blk_rq_payload_bytes(rq) >> 9) > queue_max_hw_sectors(rq->q))) {
		status = NVME_SC_INVALID_FIELD;
		goto fail_out;
	}

	rq->end_io_data = req;
	if (req->sq->qid != 0) {
		blk_execute_rq_nowait(rq->q, ns->disk, rq, 0,
				      nvmet_passthru_req_done);
	} else {
		req->p.rq = rq;
		nvmet_passthru_submit_admin_cmd(req);
	}

	if (ns)
		nvme_put_ns(ns);

	return;

fail_out:
	if (ns)
		nvme_put_ns(ns);
	nvmet_passthru_req_complete(req, rq, status);
}

/*
 * We emulate commands which are not routed through the existing target
 * code and not supported by the passthru ctrl. E.g consider a scenario where
 * passthru ctrl version is < 1.3.0. Target Fabrics ctrl version is >= 1.3.0
 * in that case in order to be fabrics compliant we need to emulate ns-desc-list
 * command which is 1.3.0 compliant but not present for the passthru ctrl due
 * to lower version.
 */
static void nvmet_passthru_emulate_id_desclist(struct nvmet_req *req)
{
	int nsid = le32_to_cpu(req->cmd->common.nsid);
	u16 status = NVME_SC_SUCCESS;
	struct nvme_ns_ids *ids;
	struct nvme_ns *ns;
	off_t off = 0;

	ns = nvme_find_get_ns(nvmet_req_passthru_ctrl(req), nsid);
	if (unlikely(!ns)) {
		pr_err("failed to get passthru ns nsid:%u\n", nsid);
		status = NVME_SC_INVALID_NS | NVME_SC_DNR;
		goto out;
	}
	/*
	 * Instead of refactoring and creating helpers, keep it simple and
	 * just re-use the code from admin-cmd.c ->
	 * nvmet_execute_identify_ns_desclist().
	 */
	ids = &ns->head->ids;
	if (memchr_inv(ids->eui64, 0, sizeof(ids->eui64))) {
		status = nvmet_copy_ns_identifier(req, NVME_NIDT_EUI64,
						  NVME_NIDT_EUI64_LEN,
						  &ids->eui64, &off);
		if (status)
			goto out_put_ns;
	}
	if (memchr_inv(&ids->uuid, 0, sizeof(ids->uuid))) {
		status = nvmet_copy_ns_identifier(req, NVME_NIDT_UUID,
						  NVME_NIDT_UUID_LEN,
						  &ids->uuid, &off);
		if (status)
			goto out_put_ns;
	}
	if (memchr_inv(ids->nguid, 0, sizeof(ids->nguid))) {
		status = nvmet_copy_ns_identifier(req, NVME_NIDT_NGUID,
						  NVME_NIDT_NGUID_LEN,
						  &ids->nguid, &off);
		if (status)
			goto out_put_ns;
	}

	if (sg_zero_buffer(req->sg, req->sg_cnt, NVME_IDENTIFY_DATA_SIZE - off,
			off) != NVME_IDENTIFY_DATA_SIZE - off)
		status = NVME_SC_INTERNAL | NVME_SC_DNR;
out_put_ns:
	nvme_put_ns(ns);
out:
	nvmet_req_complete(req, status);
}

/*
 * In the passthru mode we support three types for commands:-
 * 1. Commands which are black-listed.
 * 2. Commands which are routed through target code.
 * 3. Commands which are emulated in the target code, since we can't rely
 *    on passthru-ctrl and cannot route through the target code.
 */
static u16 nvmet_parse_passthru_admin_cmd(struct nvmet_req *req)
{
	struct nvme_command *cmd = req->cmd;
	u16 status = 0;

	if (cmd->common.opcode >= nvme_admin_vendor_unique_start) {
		/*
		 * Passthru all vendor unique commands
		 */
		req->execute = nvmet_passthru_execute_cmd;
		return status;
	}

	switch (cmd->common.opcode) {
	/* 2. commands which are routed through target code */
	case nvme_admin_async_event:
	/*
	 * Right now we don't monitor any events for the passthru controller.
	 * Instead generate asyn event notice for the ns-mgmt/format/attach
	 * commands so that host can update it's ns-inventory.
	 */
		/* fallthru */
	case nvme_admin_keep_alive:
	/*
	 * Most PCIe ctrls don't support keep alive cmd, we route keep alive
	 * to the non-passthru mode. In future please change this code when
	 * PCIe ctrls with keep alive support available.
	 */
		status = nvmet_parse_admin_cmd(req);
		break;
	case nvme_admin_set_features:
		switch (le32_to_cpu(req->cmd->features.fid)) {
		case NVME_FEAT_ASYNC_EVENT:
		case NVME_FEAT_KATO:
		case NVME_FEAT_NUM_QUEUES:
			status = nvmet_parse_admin_cmd(req);
			break;
		default:
			req->execute = nvmet_passthru_execute_cmd;
		}
		break;
	/* 3. commands which are emulated in the passthru code */
	case nvme_admin_identify:
		switch (req->cmd->identify.cns) {
		case NVME_ID_CNS_NS_DESC_LIST:
			req->execute = nvmet_passthru_emulate_id_desclist;
			break;
		default:
			req->execute = nvmet_passthru_execute_cmd;
		}
		break;
	/* 4. By default, blacklist all admin commands */
	default:

		status = NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
		req->execute = NULL;
		break;
	}

	return status;
}

u16 nvmet_parse_passthru_cmd(struct nvmet_req *req)
{
	int ret;

	if (unlikely(req->cmd->common.opcode == nvme_fabrics_command))
		return nvmet_parse_fabrics_cmd(req);
	else if (unlikely(req->sq->ctrl->subsys->type == NVME_NQN_DISC))
		return nvmet_parse_discovery_cmd(req);

	ret = nvmet_check_ctrl_status(req, req->cmd);
	if (unlikely(ret))
		return ret;

	if (unlikely(req->sq->qid == 0))
		return nvmet_parse_passthru_admin_cmd(req);

	req->execute = nvmet_passthru_execute_cmd;
	return NVME_SC_SUCCESS;
}
