// SPDX-License-Identifier: GPL-2.0
/*
 * RPM over SMD communication wrapper for interconnects
 *
 * Copyright (C) 2018 Linaro Ltd
 * Author: Georgi Djakov <georgi.djakov@linaro.org>
 */

#include <linux/interconnect-provider.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/soc/qcom/smd-rpm.h>
#include "smd-rpm.h"

#define	RPM_KEY_BW	0x00007762

static struct qcom_icc_rpm {
	struct qcom_smd_rpm *rpm;
} icc_rpm_smd;

struct icc_rpm_smd_req {
	__le32 key;
	__le32 nbytes;
	__le32 value;
};

bool qcom_icc_rpm_smd_available(void)
{
	if (!icc_rpm_smd.rpm)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(qcom_icc_rpm_smd_available);

int qcom_icc_rpm_smd_send(int ctx, int rsc_type, int id, u32 val)
{
	struct icc_rpm_smd_req req = {
		.key = cpu_to_le32(RPM_KEY_BW),
		.nbytes = cpu_to_le32(sizeof(u32)),
		.value = cpu_to_le32(val),
	};

	return qcom_rpm_smd_write(icc_rpm_smd.rpm, ctx, rsc_type, id, &req,
				  sizeof(req));
}
EXPORT_SYMBOL_GPL(qcom_icc_rpm_smd_send);

static int qcom_icc_rpm_smd_probe(struct platform_device *pdev)
{
	icc_rpm_smd.rpm = dev_get_drvdata(pdev->dev.parent);
	if (!icc_rpm_smd.rpm) {
		dev_err(&pdev->dev, "unable to retrieve handle to RPM\n");
		return -ENODEV;
	}

	return 0;
}

static const struct of_device_id qcom_icc_rpm_smd_dt_match[] = {
	{ .compatible = "qcom,interconnect-smd-rpm", },
	{ },
};

MODULE_DEVICE_TABLE(of, qcom_icc_rpm_smd_dt_match);

static struct platform_driver qcom_interconnect_rpm_smd_driver = {
	.driver = {
		.name		= "qcom-interconnect-smd-rpm",
		.of_match_table	= qcom_icc_rpm_smd_dt_match,
	},
	.probe = qcom_icc_rpm_smd_probe,
};

static int __init rpm_smd_interconnect_init(void)
{
	return platform_driver_register(&qcom_interconnect_rpm_smd_driver);
}
subsys_initcall(rpm_smd_interconnect_init);

static void __exit rpm_smd_interconnect_exit(void)
{
	platform_driver_unregister(&qcom_interconnect_rpm_smd_driver);
}
module_exit(rpm_smd_interconnect_exit)

MODULE_AUTHOR("Georgi Djakov <georgi.djakov@linaro.org>");
MODULE_DESCRIPTION("Qualcomm SMD RPM interconnect driver");
MODULE_LICENSE("GPL v2");
