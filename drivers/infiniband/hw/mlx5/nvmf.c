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
