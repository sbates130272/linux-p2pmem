/*
 * Copyright (c) 2017, Mellanox Technologies, Ltd.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "rdma_offload.h"

static void nvmet_rdma_stop_master_peer(struct pci_dev *pdev)
{
	pr_info("%s: pdev %p\n", __func__, pdev);
}

static int nvmet_rdma_fill_srq_nvmf_attrs(struct ib_srq_init_attr *srq_attr,
					  struct nvmet_rdma_xrq *xrq)
{
	struct ib_nvmf_caps *nvmf_caps = &xrq->ndev->device->attrs.nvmf_caps;

	srq_attr->ext.nvmf.type = IB_NVMF_READ_WRITE_FLUSH_OFFLOAD;
	srq_attr->ext.nvmf.log_max_namespace = nvmf_caps->max_namespace;
	srq_attr->ext.nvmf.cmd_size = (sizeof(struct nvme_command) + NVMET_RDMA_INLINE_DATA_SIZE) / 16;
	srq_attr->ext.nvmf.data_offset = 0;
	srq_attr->ext.nvmf.log_max_io_size = ilog2(nvmf_caps->max_io_sz);
	srq_attr->ext.nvmf.nvme_memory_log_page_size = 0;
	srq_attr->ext.nvmf.nvme_queue_size = min_t(u16, NVMET_QUEUE_SIZE, nvmf_caps->max_queue_sz);
	srq_attr->ext.nvmf.staging_buffer_number_of_pages = xrq->st->num_pages;
	srq_attr->ext.nvmf.staging_buffer_log_page_size = ilog2(xrq->st->page_size >> 12); //4k granularity in PRM
	srq_attr->ext.nvmf.staging_buffer_pas = kzalloc(sizeof(dma_addr_t) * xrq->st->num_pages, GFP_KERNEL);
	if (!srq_attr->ext.nvmf.staging_buffer_pas)
		return -ENOMEM;

	return 0;
}

static void nvmet_rdma_free_st_buff(struct nvmet_rdma_staging_buf *st)
{
	if (st->dynamic)
		kfree(st->staging_pages);
	kfree(st->staging_dma_addrs);
	kfree(st);
}

/**
 * Called with nvmet_rdma_xrq_mutex held
 **/
static void nvmet_rdma_release_st_buff(struct nvmet_rdma_staging_buf *st)
{
	if (st->dynamic)
		nvmet_rdma_free_st_buff(st);
	else
		list_add_tail(&st->entry, &nvmet_rdma_st_pool.list);
}

static struct nvmet_rdma_staging_buf *nvmet_rdma_alloc_st_buff(u16 num_pages,
		unsigned int page_size_mb, bool dynamic)
{
	struct nvmet_rdma_staging_buf *st;

	st = kzalloc(sizeof(struct nvmet_rdma_staging_buf), GFP_KERNEL);
	if (!st)
		return NULL;

	st->staging_dma_addrs = kzalloc(sizeof(dma_addr_t) * num_pages, GFP_KERNEL);
	if (!st->staging_dma_addrs)
		goto free_st;

	if (dynamic) {
		/* only in dynamic allocation we use virtual addresses too */
		st->staging_pages = kzalloc(sizeof(void*) * num_pages, GFP_KERNEL);
		if (!st->staging_pages)
			goto free_st_dma_addrs;
	}

	st->num_pages = num_pages;
	st->page_size = page_size_mb * SZ_1M;
	st->dynamic = dynamic;

	return st;

free_st_dma_addrs:
	kfree(st->staging_dma_addrs);
free_st:
	kfree(st);

	return NULL;
}

static void nvmet_rdma_destroy_xrq(struct kref *ref)
{
	struct nvmet_rdma_xrq *xrq =
		container_of(ref, struct nvmet_rdma_xrq, ref);
	struct nvmet_rdma_device *ndev = xrq->ndev;
	struct nvmet_rdma_staging_buf *st = xrq->st;
	int i;

	pr_info("destroying XRQ %p port %p\n", xrq, xrq->port);
	/* TODO: check if need to reduce refcound on pdev */
	nvmet_rdma_free_cmds(ndev, xrq->ofl_srq_cmds, xrq->ofl_srq_size, false);
	ib_destroy_srq(xrq->ofl_srq);
	if (st->dynamic) {
		for (i = 0 ; i < st->num_pages ; i++)
			dma_free_coherent(ndev->device->dma_device, st->page_size,
					  st->staging_pages[i], st->staging_dma_addrs[i]);
	}

	ib_free_cq(xrq->cq);
	nvmet_rdma_release_st_buff(st);
	kfree(xrq);
	kref_put(&ndev->ref, nvmet_rdma_free_dev);
}

static int nvmet_rdma_init_xrq(struct nvmet_rdma_device *ndev,
			       struct nvmet_rdma_queue *queue)
{
	struct ib_srq_init_attr srq_attr = { NULL, };
	struct ib_srq *srq;
	size_t srq_size;
	int ret, i, j;
	struct nvmet_rdma_xrq *xrq;
	struct nvmet_port *port = queue->port;


	xrq = kzalloc(sizeof(*xrq), GFP_KERNEL);
	if (!xrq)
		return -ENOMEM;

	kref_init(&xrq->ref);
	INIT_LIST_HEAD(&xrq->offload_ctrls_list);
	mutex_init(&xrq->offload_ctrl_mutex);
	INIT_LIST_HEAD(&xrq->be_ctrls_list);
	mutex_init(&xrq->be_mutex);
	xrq->ndev = ndev;
	xrq->port = port;

	if (!list_empty(&nvmet_rdma_st_pool.list)) {
		xrq->st = list_first_entry(&nvmet_rdma_st_pool.list,
					struct nvmet_rdma_staging_buf, entry);
		list_del(&xrq->st->entry);
	} else {
		u16 num_pages = nvmet_rdma_offload_buffer_size_mb / NVMET_DYNAMIC_STAGING_BUFFER_PAGE_SIZE_MB;
		xrq->st = nvmet_rdma_alloc_st_buff(max_t(u16, NVMET_MIN_DYNAMIC_STAGING_BUFFER_NUM_PAGES, num_pages),
						   NVMET_DYNAMIC_STAGING_BUFFER_PAGE_SIZE_MB,
						   true);
	}
	if (!xrq->st) {
		ret = -ENOMEM;
		goto free_xrq;
	}

	pr_info("using %s staging buffer %p\n",
		xrq->st->dynamic ? "dynamic" : "static", xrq->st);


	xrq->cq = ib_alloc_cq(ndev->device, queue, 4096,
			      queue->idx % ndev->device->num_comp_vectors,
			      IB_POLL_WORKQUEUE);
	if (IS_ERR(xrq->cq)) {
		ret = PTR_ERR(xrq->cq);
		pr_err("failed to create CQ for xrq cqe= %d ret= %d\n",
		       4096, ret);
		goto free_xrq_st;
	}

	srq_size = 4095;
	srq_attr.attr.max_wr = srq_size;
	srq_attr.attr.max_sge = 2;
	srq_attr.srq_type = IB_EXP_SRQT_NVMF;
	if (nvmet_rdma_fill_srq_nvmf_attrs(&srq_attr, xrq)) {
		ret = -ENOMEM;
		goto free_xrq_cq;
	}

	for (i = 0 ; i < xrq->st->num_pages ; i++) {
		if (xrq->st->dynamic) {
			xrq->st->staging_pages[i] = dma_zalloc_coherent(ndev->device->dma_device,
									xrq->st->page_size,
									&xrq->st->staging_dma_addrs[i],
									GFP_KERNEL);
			if (!xrq->st->staging_pages[i]) {
				ret = -ENOMEM;
				goto release_st_buf;
			}
		}
		memcpy(&srq_attr.ext.nvmf.staging_buffer_pas[i],
		       &xrq->st->staging_dma_addrs[i], sizeof(dma_addr_t));
	}

	srq_attr.ext.cq = xrq->cq;
	srq = ib_create_srq(ndev->pd, &srq_attr);
	if (IS_ERR(srq)) {
		pr_err("failed to create xrq SRQ");
		ret = PTR_ERR(srq);
		goto release_st_buf;
	}

	xrq->ofl_srq_cmds = nvmet_rdma_alloc_cmds(ndev, srq_size, false);
	if (IS_ERR(xrq->ofl_srq_cmds)) {
		ret = PTR_ERR(xrq->ofl_srq_cmds);
		goto out_destroy_srq;
	}

	if (!kref_get_unless_zero(&ndev->ref)) {
		ret = -EINVAL;
		goto out_free_cmds;
	}

	xrq->ofl_srq = srq;
	xrq->ofl_srq_size = srq_size;
	xrq->st->xrq = xrq;
	queue->xrq = xrq;

	for (i = 0; i < srq_size; i++) {
		xrq->ofl_srq_cmds[i].queue = queue;
		xrq->ofl_srq_cmds[i].srq = srq;
		nvmet_rdma_post_recv(ndev, &xrq->ofl_srq_cmds[i]);
	}

	kfree(srq_attr.ext.nvmf.staging_buffer_pas);

	return 0;

out_free_cmds:
	nvmet_rdma_free_cmds(ndev, xrq->ofl_srq_cmds, srq_size, false);
out_destroy_srq:
	ib_destroy_srq(srq);
release_st_buf:
	if (xrq->st->dynamic) {
		for (j = 0 ; j < i ; j++)
			dma_free_coherent(ndev->device->dma_device, xrq->st->page_size,
					  xrq->st->staging_pages[j], xrq->st->staging_dma_addrs[j]);
	}
	kfree(srq_attr.ext.nvmf.staging_buffer_pas);
free_xrq_cq:
	ib_free_cq(xrq->cq);
free_xrq_st:
	nvmet_rdma_release_st_buff(xrq->st);
free_xrq:
	kfree(xrq);

	return ret;
}

static int nvmet_rdma_find_get_xrq(struct nvmet_rdma_device *ndev,
				   struct nvmet_rdma_queue *queue)
{
	struct nvmet_rdma_xrq *xrq;
	int ret = 0;

	mutex_lock(&nvmet_rdma_xrq_mutex);
	list_for_each_entry(xrq, &nvmet_rdma_xrq_list, entry) {
		if (xrq->port == queue->port && kref_get_unless_zero(&xrq->ref)) {
			queue->xrq = xrq;
			goto out_unlock;
		}
	}

	ret = nvmet_rdma_init_xrq(ndev, queue);
	if (!ret) {
		kref_get(&queue->xrq->ref);
		list_add_tail(&queue->xrq->entry, &nvmet_rdma_xrq_list);
	}
out_unlock:
	mutex_unlock(&nvmet_rdma_xrq_mutex);
	return ret;
}

static int nvmet_rdma_install_offload_queue(struct nvmet_ctrl *ctrl,
					    u16 qid)
{
	struct nvmet_rdma_queue *queue;
	struct nvmet_rdma_xrq *xrq;
	struct nvmet_rdma_offload_ctrl *offload_ctrl;
	struct ib_qp_attr attr;
	int ret = -ENODEV;

	mutex_lock(&nvmet_rdma_queue_mutex);
	list_for_each_entry(queue, &nvmet_rdma_queue_list, queue_list) {
		mutex_lock(&nvmet_rdma_xrq_mutex);
		list_for_each_entry(xrq, &nvmet_rdma_xrq_list, entry) {
			if (queue->xrq == xrq) {
				mutex_lock(&xrq->offload_ctrl_mutex);
				list_for_each_entry(offload_ctrl, &xrq->offload_ctrls_list, entry) {
					if (offload_ctrl->ctrl == ctrl && queue->host_qid == qid) {
						attr.qp_state = IB_QPS_RTS;
						attr.offload_type = IB_QP_OFFLOAD_NVMF;
						ret = ib_modify_qp(queue->cm_id->qp, &attr,
								   IB_QP_STATE | IB_QP_OFFLOAD_TYPE);
						break;
					}
				}
				mutex_unlock(&xrq->offload_ctrl_mutex);
			}
		}
		mutex_unlock(&nvmet_rdma_xrq_mutex);
	}
	mutex_unlock(&nvmet_rdma_queue_mutex);

	return ret;
}

static void nvmet_rdma_free_be_ctrl(struct nvmet_rdma_backend_ctrl *be_ctrl)
{
	if (be_ctrl->ibns)
		ib_detach_nvmf_ns(be_ctrl->ibns);
	if (be_ctrl->ibctrl)
		ib_destroy_nvmf_backend_ctrl(be_ctrl->ibctrl);
	if (be_ctrl->ofl)
		nvme_peer_put_resource(be_ctrl->ofl);
	kfree(be_ctrl);
}

static void nvmet_rdma_init_be_ctrl_attr(struct ib_nvmf_backend_ctrl_init_attr *attr,
					 struct nvme_peer_resource *ofl)
{
	memset(attr, 0, sizeof(*attr));

	attr->cq_page_offset = 0;
	attr->sq_page_offset = 0;
	attr->cq_log_page_size = ilog2(ofl->nvme_cq_size >> 12);
	attr->sq_log_page_size = ilog2(ofl->nvme_sq_size >> 12);
	attr->initial_cqh_db_value = 0;
	attr->initial_sqt_db_value = 0;
	attr->cqh_dbr_addr = ofl->cqh_dbr_addr;
	attr->sqt_dbr_addr = ofl->sqt_dbr_addr;
	attr->cq_pas = ofl->cq_dma_addr;
	attr->sq_pas = ofl->sq_dma_addr;
}

static void nvmet_rdma_init_ns_attr(struct ib_nvmf_ns_init_attr *attr,
				    u32 frontend_namespace,
				    u32 backend_namespace,
				    u16 lba_data_size,
				    u16 backend_ctrl_id)
{
	memset(attr, 0, sizeof(*attr));

	attr->frontend_namespace = frontend_namespace;
	attr->backend_namespace = backend_namespace;
	attr->lba_data_size = lba_data_size;
	attr->backend_ctrl_id = backend_ctrl_id;
}

static struct nvmet_rdma_backend_ctrl *
nvmet_rdma_create_be_ctrl(struct nvmet_rdma_xrq *xrq,
			  struct nvmet_ns *ns)
{
	struct nvmet_rdma_backend_ctrl *be_ctrl;
	struct ib_nvmf_backend_ctrl_init_attr init_attr;
	struct ib_nvmf_ns_init_attr ns_init_attr;
	int err;

	be_ctrl = kzalloc(sizeof(*be_ctrl), GFP_KERNEL);
	if (!be_ctrl)
		return ERR_PTR(-ENOMEM);

	be_ctrl->ofl = nvme_peer_get_resource(ns->pdev,
			NVME_PEER_SQT_DBR      |
			NVME_PEER_CQH_DBR      |
			NVME_PEER_SQ_PAS       |
			NVME_PEER_CQ_PAS       |
			NVME_PEER_SQ_SZ        |
			NVME_PEER_CQ_SZ        |
			NVME_PEER_MEM_LOG_PG_SZ,
			nvmet_rdma_stop_master_peer);
	if (!be_ctrl->ofl) {
		err = -ENODEV;
		goto out_free_be_ctrl;
	}
	be_ctrl->pdev = ns->pdev;

	nvmet_rdma_init_be_ctrl_attr(&init_attr, be_ctrl->ofl);
	be_ctrl->ibctrl = ib_create_nvmf_backend_ctrl(xrq->ofl_srq, &init_attr);
	if (IS_ERR(be_ctrl->ibctrl)) {
		err = PTR_ERR(be_ctrl->ibctrl);
		goto out_put_resource;
	}

	nvmet_rdma_init_ns_attr(&ns_init_attr, ns->nsid, 1, 0,
				be_ctrl->ibctrl->id);
	be_ctrl->ibns = ib_attach_nvmf_ns(be_ctrl->ibctrl, &ns_init_attr);
	if (IS_ERR(be_ctrl->ibns)) {
		err = PTR_ERR(be_ctrl->ibns);
		goto out_destroy_be_ctrl;
	}

	return be_ctrl;

out_destroy_be_ctrl:
	ib_destroy_nvmf_backend_ctrl(be_ctrl->ibctrl);
out_put_resource:
	nvme_peer_put_resource(be_ctrl->ofl);
out_free_be_ctrl:
	kfree(be_ctrl);

	return ERR_PTR(err);
}

static int nvmet_rdma_create_offload_ctrl(struct nvmet_ctrl *ctrl)
{
	struct nvmet_rdma_xrq *xrq;
	struct nvmet_ns *ns;
	struct nvmet_rdma_backend_ctrl *be_ctrl, *next;
	struct nvmet_rdma_offload_ctrl *offload_ctrl = NULL;
	int err = 0;

	mutex_lock(&nvmet_rdma_xrq_mutex);
	list_for_each_entry(xrq, &nvmet_rdma_xrq_list, entry) {
		if (xrq->port == ctrl->port) {
			offload_ctrl = kzalloc(sizeof(*offload_ctrl), GFP_KERNEL);
			if (!offload_ctrl) {
				err = -ENOMEM;
				goto out_unlock;
			}
			if (xrq->subsys != ctrl->subsys) {
				rcu_read_lock();
				list_for_each_entry_rcu(ns, &ctrl->subsys->namespaces, dev_link) {
					be_ctrl = nvmet_rdma_create_be_ctrl(xrq, ns);
					if (IS_ERR(be_ctrl)) {
						err = PTR_ERR(be_ctrl);
						goto out_free;
					}
					mutex_lock(&xrq->be_mutex);
					list_add_tail(&be_ctrl->entry, &xrq->be_ctrls_list);
					mutex_unlock(&xrq->be_mutex);
				}
				rcu_read_unlock();
				xrq->subsys = ctrl->subsys;
			}
			mutex_lock(&xrq->offload_ctrl_mutex);
			list_add_tail(&offload_ctrl->entry, &xrq->offload_ctrls_list);
			offload_ctrl->ctrl = ctrl;
			offload_ctrl->xrq = xrq;
			mutex_unlock(&xrq->offload_ctrl_mutex);
		}
	}

	mutex_unlock(&nvmet_rdma_xrq_mutex);

	return offload_ctrl ? 0 : -ENODEV;

out_free:
	kfree(offload_ctrl);
	mutex_lock(&xrq->be_mutex);
	list_for_each_entry_safe(be_ctrl, next, &xrq->be_ctrls_list, entry) {
			list_del_init(&be_ctrl->entry);
			nvmet_rdma_free_be_ctrl(be_ctrl);
	}
	mutex_unlock(&xrq->be_mutex);
	rcu_read_unlock();
out_unlock:
	mutex_unlock(&nvmet_rdma_xrq_mutex);

	return err;
}

static void nvmet_rdma_destroy_offload_ctrl(struct nvmet_ctrl *ctrl)
{
	struct nvmet_rdma_xrq *xrq;
	struct nvmet_rdma_backend_ctrl *be_ctrl, *next;
	struct nvmet_rdma_offload_ctrl *offload_ctrl, *offload_next;

	mutex_lock(&nvmet_rdma_xrq_mutex);
	list_for_each_entry(xrq, &nvmet_rdma_xrq_list, entry) {
		if (xrq->port == ctrl->port && xrq->subsys == ctrl->subsys) {
			mutex_lock(&xrq->offload_ctrl_mutex);
			list_for_each_entry_safe(offload_ctrl, offload_next, &xrq->offload_ctrls_list, entry) {
				if (offload_ctrl->ctrl == ctrl) {
					list_del_init(&offload_ctrl->entry);
					kfree(offload_ctrl);
				}
			}
			mutex_unlock(&xrq->offload_ctrl_mutex);

			if (list_empty(&xrq->offload_ctrls_list)) {
				xrq->subsys = NULL;
				mutex_lock(&xrq->be_mutex);
				list_for_each_entry_safe(be_ctrl, next, &xrq->be_ctrls_list, entry) {
					list_del_init(&be_ctrl->entry);
					nvmet_rdma_free_be_ctrl(be_ctrl);
				}
				mutex_unlock(&xrq->be_mutex);
			}
		}
	}
	mutex_unlock(&nvmet_rdma_xrq_mutex);

}

static u8 nvmet_rdma_peer_to_peer_mdts(struct nvmet_port *port)
{
	struct rdma_cm_id *cm_id = port->priv;

	/* we assume ctrl page_size is 4K */
	return ilog2(cm_id->device->attrs.nvmf_caps.max_io_sz / SZ_4K);
}

static bool nvmet_rdma_peer_to_peer_capable(struct nvmet_port *port)
{
	struct rdma_cm_id *cm_id = port->priv;

	return cm_id->device->attrs.device_cap_flags & IB_DEVICE_NVMF_TARGET_OFFLOAD;
}

static int nvmet_rdma_init_st_pool(struct nvmet_rdma_staging_buf_pool *pool,
				   unsigned long long mem_start,
				   unsigned int mem_size,
				   unsigned int buffer_size)
{
	struct nvmet_rdma_staging_buf *st, *tmp;
	int i, err = -EINVAL;
	int size = mem_size / buffer_size;
	unsigned long start_pfn, end_pfn;

	if (!PAGE_ALIGNED(mem_start))
		goto out;

	start_pfn = PFN_DOWN(mem_start);
	end_pfn = PFN_DOWN(mem_start + mem_size * SZ_1M);
	for (; start_pfn < end_pfn; start_pfn++) {
		if (pfn_valid(start_pfn))
			goto out;
	}

	for (i = 0; i < size; i++) {
		st = nvmet_rdma_alloc_st_buff(1, buffer_size, false);
		if (!st) {
			err = -ENOMEM;
			goto error;
		}
		st->staging_dma_addrs[0] = mem_start + i * buffer_size * SZ_1M;
		pr_debug("pool_entry=%d staging_buffer_address=0x%llx\n", i, st->staging_dma_addrs[0]);
		list_add_tail(&st->entry, &pool->list);
		pool->size++;
	}

	pr_info("offload_mem_start=0x%llx pool_size=%d, buf_size=%u\n",
		mem_start,
		pool->size,
		buffer_size);

	return 0;

error:
	list_for_each_entry_safe(st, tmp, &pool->list, entry) {
		list_del(&st->entry);
		nvmet_rdma_free_st_buff(st);
	}
out:
	return err;
}

