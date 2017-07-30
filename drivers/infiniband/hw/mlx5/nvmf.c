/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/mlx5/qp.h>
#include <linux/mlx5/srq.h>
#include <linux/mlx5/nvmf.h>

#include "mlx5_ib.h"

void mlx5_ib_internal_fill_nvmf_caps(struct mlx5_ib_dev *dev)
{
	struct ib_nvmf_caps *caps = &dev->nvmf_caps;
	struct mlx5_core_dev *mdev = dev->mdev;

	memset(caps, 0, sizeof(*caps));

	if (MLX5_CAP_NVMF(mdev, write_offload_dc))
		caps->offload_type_dc |= IB_NVMF_WRITE_OFFLOAD;
	if (MLX5_CAP_NVMF(mdev, read_offload_dc))
		caps->offload_type_dc |= IB_NVMF_READ_OFFLOAD;
	if (MLX5_CAP_NVMF(mdev, read_write_offload_dc))
		caps->offload_type_dc |= IB_NVMF_READ_WRITE_OFFLOAD;
	if (MLX5_CAP_NVMF(mdev, read_write_flush_offload_dc))
		caps->offload_type_dc |= IB_NVMF_READ_WRITE_FLUSH_OFFLOAD;

	if (MLX5_CAP_NVMF(mdev, write_offload_rc))
		caps->offload_type_rc |= IB_NVMF_WRITE_OFFLOAD;
	if (MLX5_CAP_NVMF(mdev, read_offload_rc))
		caps->offload_type_rc |= IB_NVMF_READ_OFFLOAD;
	if (MLX5_CAP_NVMF(mdev, read_write_offload_rc))
		caps->offload_type_rc |= IB_NVMF_READ_WRITE_OFFLOAD;
	if (MLX5_CAP_NVMF(mdev, read_write_flush_offload_rc))
		caps->offload_type_rc |= IB_NVMF_READ_WRITE_FLUSH_OFFLOAD;

	caps->max_namespace =
		1 << MLX5_CAP_NVMF(mdev, log_max_namespace_per_xrq);
	caps->max_staging_buffer_sz =
		1 << MLX5_CAP_NVMF(mdev, log_max_staging_buffer_size);
	caps->min_staging_buffer_sz =
		1 << MLX5_CAP_NVMF(mdev, log_min_staging_buffer_size);
	caps->max_io_sz = 1 << MLX5_CAP_NVMF(mdev, log_max_io_size);
	caps->max_be_ctrl =
		1 << MLX5_CAP_NVMF(mdev, log_max_backend_controller_per_xrq);
	caps->max_queue_sz =
		1 << MLX5_CAP_NVMF(mdev, log_max_queue_size);
	caps->min_queue_sz =
		1 << MLX5_CAP_NVMF(mdev, log_min_queue_size);
	caps->min_cmd_size = MLX5_CAP_NVMF(mdev, min_ioccsz);
	caps->max_cmd_size = MLX5_CAP_NVMF(mdev, max_ioccsz);
	caps->max_data_offset = MLX5_CAP_NVMF(mdev, max_icdoff);

	return;
}

static void set_nvmf_backend_ctrl_attrs(struct ib_nvmf_backend_ctrl_init_attr *attr,
					struct mlx5_be_ctrl_attr *in)
{
	in->cq_page_offset = attr->cq_page_offset;
	in->sq_page_offset = attr->sq_page_offset;
	in->cq_log_page_size = attr->cq_log_page_size;
	in->sq_log_page_size = attr->sq_log_page_size;
	in->initial_cqh_db_value = attr->initial_cqh_db_value;
	in->initial_sqt_db_value = attr->initial_sqt_db_value;
	in->cqh_dbr_addr = attr->cqh_dbr_addr;
	in->sqt_dbr_addr = attr->sqt_dbr_addr;
	in->cq_pas = attr->cq_pas;
	in->sq_pas = attr->sq_pas;
}

static void mlx5_ib_nvmf_backend_ctrl_event(struct mlx5_core_nvmf_be_ctrl *ctrl,
					    int event_type,
					    int error_type)
{
	struct ib_nvmf_ctrl *ibctrl = &to_mibctrl(ctrl)->ibctrl;
	struct mlx5_ib_dev *dev = to_mdev(ibctrl->srq->device);
	struct ib_event event;

	if (event_type != MLX5_EVENT_TYPE_XRQ_ERROR) {
		/* This is the only valid event type for nvmf backend ctrl */
		return;
	}

	if (ibctrl->event_handler) {
		event.device = ibctrl->srq->device;
		switch (error_type) {
		case MLX5_XRQ_ERROR_TYPE_BACKEND_CONTROLLER_ERROR:
			event.event = IB_EXP_EVENT_XRQ_NVMF_BACKEND_CTRL_ERR;
			break;
		default:
			mlx5_ib_warn(dev,
				     "Unexpected event error type %d on CTRL %06x\n",
				     error_type, ibctrl->id);
			return;
		}

		ibctrl->event_handler(&event, ibctrl->be_context);
	}
}

struct ib_nvmf_ctrl *mlx5_ib_create_nvmf_backend_ctrl(struct ib_srq *srq,
			struct ib_nvmf_backend_ctrl_init_attr *init_attr)
{
	struct mlx5_ib_dev *dev = to_mdev(srq->device);
	struct mlx5_ib_srq *msrq = to_msrq(srq);
	struct mlx5_ib_nvmf_be_ctrl *ctrl;
	struct mlx5_be_ctrl_attr in = {0};
	int err;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return ERR_PTR(-ENOMEM);

	set_nvmf_backend_ctrl_attrs(init_attr, &in);
	err = mlx5_core_create_nvmf_backend_ctrl(dev->mdev,
						 &msrq->msrq,
						 &ctrl->mctrl,
						 &in);
	if (err) {
		mlx5_ib_dbg(dev, "create NVMF backend ctrl failed, err %d\n", err);
		goto err_ctrl;
	}

	mlx5_ib_dbg(dev, "create NVMF backend ctrl with ctrlid 0x%x\n",
		    ctrl->mctrl.id);

	ctrl->ibctrl.id = ctrl->mctrl.id;
	ctrl->mctrl.event = mlx5_ib_nvmf_backend_ctrl_event;
	return &ctrl->ibctrl;

err_ctrl:
	kfree(ctrl);

	return ERR_PTR(err);

}

int mlx5_ib_destroy_nvmf_backend_ctrl(struct ib_nvmf_ctrl *ctrl)
{
	struct mlx5_ib_dev *dev = to_mdev(ctrl->srq->device);
	struct mlx5_ib_nvmf_be_ctrl *mctrl = to_mctrl(ctrl);
	struct mlx5_ib_srq *msrq = to_msrq(ctrl->srq);

	mlx5_core_destroy_nvmf_backend_ctrl(dev->mdev,
					    &msrq->msrq,
					    &mctrl->mctrl);

	kfree(mctrl);
	return 0;
}

static void set_nvmf_ns_attrs(struct ib_nvmf_ns_init_attr *attr,
			      struct mlx5_ns_attr *in)
{
	in->frontend_namespace = attr->frontend_namespace;
	in->backend_namespace = attr->backend_namespace;
	in->lba_data_size = attr->lba_data_size;
	in->backend_ctrl_id = attr->backend_ctrl_id;
}


struct ib_nvmf_ns *mlx5_ib_attach_nvmf_ns(struct ib_nvmf_ctrl *ctrl,
			struct ib_nvmf_ns_init_attr *init_attr)
{
	struct mlx5_ib_nvmf_be_ctrl *mctrl = to_mctrl(ctrl);
	struct mlx5_ib_dev *dev = to_mdev(ctrl->srq->device);
	struct mlx5_ib_srq *msrq = to_msrq(ctrl->srq);
	struct mlx5_ib_nvmf_ns *ns;
	struct mlx5_ns_attr in = {0};
	int err;

	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

	set_nvmf_ns_attrs(init_attr, &in);
	err = mlx5_core_attach_nvmf_ns(dev->mdev,
				       &msrq->msrq,
				       &mctrl->mctrl,
				       &ns->mns,
				       &in);
	if (err) {
		mlx5_ib_dbg(dev, "attach NVMF ns failed, err %d\n", err);
		goto err_ns;
	}

	mlx5_ib_dbg(dev, "NVMF ns %p was attached\n", ns);

	return &ns->ibns;

err_ns:
	kfree(ns);

	return ERR_PTR(err);

}

int mlx5_ib_detach_nvmf_ns(struct ib_nvmf_ns *ns)
{
	struct mlx5_ib_nvmf_ns *mns = to_mns(ns);
	struct mlx5_ib_nvmf_be_ctrl *mctrl = to_mctrl(ns->ctrl);
	struct mlx5_ib_dev *dev = to_mdev(ns->ctrl->srq->device);
	struct mlx5_ib_srq *msrq = to_msrq(ns->ctrl->srq);

	mlx5_core_detach_nvmf_ns(dev->mdev,
				 &msrq->msrq,
				 &mctrl->mctrl,
				 &mns->mns);

	kfree(mns);
	return 0;
}
