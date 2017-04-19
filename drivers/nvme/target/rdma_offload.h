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

#ifndef _RDMA_OFFLOAD_H
#define _RDMA_OFFLOAD_H

#include <rdma/ib_verbs.h>
#include "nvmet.h"

#define NVMET_MIN_DYNAMIC_STAGING_BUFFER_NUM_PAGES	0x1
#define NVMET_DYNAMIC_STAGING_BUFFER_PAGE_SIZE_MB	0x1

struct nvmet_rdma_xrq;
struct nvmet_rdma_device;
struct nvmet_rdma_cmd;
struct nvmet_rdma_queue queue;

struct nvmet_rdma_backend_ctrl {
	struct ib_nvmf_ctrl	  *ibctrl;
	struct ib_nvmf_ns	  *ibns;
	struct pci_dev		  *pdev;
	struct list_head	  entry;
	struct nvme_peer_resource *ofl;
};

struct nvmet_rdma_offload_ctrl {
	struct nvmet_ctrl	*ctrl;
	struct nvmet_rdma_xrq	*xrq;
	struct list_head	entry;
};

struct nvmet_rdma_staging_buf_pool {
	struct list_head	list;
	int			size;
};

struct nvmet_rdma_staging_buf {
	void			  **staging_pages;
	dma_addr_t		  *staging_dma_addrs;
	u16 			  num_pages;
	unsigned int		  page_size; // in Bytes
	struct list_head	  entry;
	bool 			  dynamic;
	struct nvmet_rdma_xrq	  *xrq;
};

struct nvmet_rdma_xrq {
	struct nvmet_rdma_device	*ndev;
	struct nvmet_port		*port;
	struct nvmet_subsys		*subsys;
	struct list_head		offload_ctrls_list;
	struct mutex			offload_ctrl_mutex;
	struct list_head		be_ctrls_list;
	struct mutex			be_mutex;
	struct ib_srq			*ofl_srq;
	struct ib_cq			*cq;
	struct nvmet_rdma_cmd		*ofl_srq_cmds;
	size_t				ofl_srq_size;
	struct nvmet_rdma_staging_buf	*st;
	struct kref			ref;
	struct list_head		entry;
};

static void nvmet_rdma_free_st_buff(struct nvmet_rdma_staging_buf *st);
static void nvmet_rdma_destroy_xrq(struct kref *ref);
static int nvmet_rdma_find_get_xrq(struct nvmet_rdma_device *ndev,
				   struct nvmet_rdma_queue *queue);
static int nvmet_rdma_install_offload_queue(struct nvmet_ctrl *ctrl,
					    u16 qid);
static int nvmet_rdma_create_offload_ctrl(struct nvmet_ctrl *ctrl);
static void nvmet_rdma_destroy_offload_ctrl(struct nvmet_ctrl *ctrl);
static bool nvmet_rdma_peer_to_peer_capable(struct nvmet_port *port);
static u8 nvmet_rdma_peer_to_peer_mdts(struct nvmet_port *port);
static int nvmet_rdma_init_st_pool(struct nvmet_rdma_staging_buf_pool *pool,
				   unsigned long long mem_start,
				   unsigned int mem_size,
				   unsigned int buffer_size);

#endif /* _RDMA_OFFLOAD_H */
