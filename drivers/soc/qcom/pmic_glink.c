// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021, Linaro Ltd
 */

#include <linux/auxiliary_bus.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/soc/qcom/pdr.h>
#include <linux/soc/qcom/pmic_glink.h>

struct pmic_glink {
	struct device *dev;
	struct pdr_handle *pdr;

	struct rpmsg_endpoint *ept;

	struct auxiliary_device altmode_aux;
	struct auxiliary_device ps_aux;
	struct auxiliary_device ucsi_aux;

	struct mutex lock;
	struct list_head owners;
};

struct pmic_glink_client {
	struct list_head node;

	struct pmic_glink *pmic;
	unsigned int id;

	void (*cb)(const void *, size_t, void *);
	void *priv;
};

static void _devm_pmic_glink_release_client(struct device *dev, void *res)
{
	struct pmic_glink_client *client = *(struct pmic_glink_client **)res;
	struct pmic_glink *pg = client->pmic;

	mutex_lock(&pg->lock);
	list_del(&client->node);
	mutex_unlock(&pg->lock);
}

struct pmic_glink_client *devm_pmic_glink_register_client(struct device *dev,
							  unsigned int id,
							  void (*cb)(const void *, size_t, void *),
							  void *priv)
{
	struct pmic_glink_client *client;
	struct pmic_glink *pg = dev_get_drvdata(dev->parent);

	client = devres_alloc(_devm_pmic_glink_release_client, sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	client->pmic = pg;
	client->id = id;
	client->cb = cb;
	client->priv = priv;

	mutex_lock(&pg->lock);
	list_add(&client->node, &pg->owners);
	mutex_unlock(&pg->lock);

	devres_add(dev, client);

	return client;
}
EXPORT_SYMBOL_GPL(devm_pmic_glink_register_client);

int pmic_glink_send(struct pmic_glink_client *client, void *data, size_t len)
{
	struct pmic_glink *pg = client->pmic;

	return rpmsg_send(pg->ept, data, len);
}
EXPORT_SYMBOL_GPL(pmic_glink_send);

static int pmic_glink_callback(struct rpmsg_device *rpdev, void *data,
			       int len, void *priv, u32 addr)
{
	struct pmic_glink_client *client;
	struct pmic_glink_hdr *hdr;
	struct pmic_glink *pg = dev_get_drvdata(&rpdev->dev);

	if (len < sizeof(*hdr)) {
		dev_warn(pg->dev, "ignoring truncated message\n");
		return 0;
	}

	hdr = data;

	list_for_each_entry(client, &pg->owners, node) {
		if (client->id == le32_to_cpu(hdr->owner))
			client->cb(data, len, client->priv);
	}

	return 0;
}

static void pmic_glink_aux_release(struct device *dev) {}

static int pmic_glink_add_aux_device(struct pmic_glink *pg,
				     struct auxiliary_device *aux,
				     const char *name)
{
	struct device *parent = pg->dev;
	int ret;

	aux->name = name;
	aux->dev.parent = parent;
	aux->dev.release = pmic_glink_aux_release;
	device_set_of_node_from_dev(&aux->dev, parent);
	ret = auxiliary_device_init(aux);
	if (ret)
		return ret;

	ret = auxiliary_device_add(aux);
	if (ret)
		auxiliary_device_uninit(aux);

	return ret;
}

static void pmic_glink_del_aux_device(struct pmic_glink *pg,
				      struct auxiliary_device *aux)
{
	auxiliary_device_delete(aux);
	auxiliary_device_uninit(aux);
}

static void pmic_glink_service_up(struct pmic_glink *pg)
{
	pmic_glink_add_aux_device(pg, &pg->altmode_aux, "altmode");
	pmic_glink_add_aux_device(pg, &pg->ps_aux, "power-supply");
	pmic_glink_add_aux_device(pg, &pg->ucsi_aux, "ucsi");
}

static void pmic_glink_service_down(struct pmic_glink *pg)
{
	pmic_glink_del_aux_device(pg, &pg->altmode_aux);
	pmic_glink_del_aux_device(pg, &pg->ps_aux);
	pmic_glink_del_aux_device(pg, &pg->ucsi_aux);
}

static void pmic_glink_pdr_callback(int state, char *svc_path, void *priv)
{
	struct pmic_glink *pg = priv;

	switch (state) {
	case SERVREG_SERVICE_STATE_UP:
		pmic_glink_service_up(pg);
		break;
	case SERVREG_SERVICE_STATE_DOWN:
		pmic_glink_service_down(pg);
		break;
	}
}

static int pmic_glink_probe(struct rpmsg_device *rpdev)
{
	struct pdr_service *service;
	struct pmic_glink *pg;

	pg = devm_kzalloc(&rpdev->dev, sizeof(*pg), GFP_KERNEL);
	if (!pg)
		return -ENOMEM;

	dev_set_drvdata(&rpdev->dev, pg);

	pg->dev = &rpdev->dev;
	pg->ept = rpdev->ept;

	INIT_LIST_HEAD(&pg->owners);
	mutex_init(&pg->lock);

	pg->pdr = pdr_handle_alloc(pmic_glink_pdr_callback, pg);
	if (IS_ERR(pg->pdr))
		dev_err_probe(&rpdev->dev, PTR_ERR(pg->pdr), "failed to initalize pdr\n");

	service = pdr_add_lookup(pg->pdr, "tms/servreg", "msm/adsp/charger_pd");
	if (IS_ERR(service))
		return dev_err_probe(&rpdev->dev, PTR_ERR(service),
				     "failed adding pdr lookup for charger_pd\n");

	return 0;
}

static void pmic_glink_remove(struct rpmsg_device *rpdev)
{
	struct pmic_glink *pg = dev_get_drvdata(&rpdev->dev);

	pdr_handle_release(pg->pdr);
}

static const struct of_device_id pmic_glink_of_match[] = {
	{ .compatible = "qcom,pmic-glink", },
	{}
};
MODULE_DEVICE_TABLE(of, pmic_glink_of_match);

static const struct rpmsg_device_id pmic_glink_id_match[] = {
	{ "PMIC_RTR_ADSP_APPS" },
	{}
};

static struct rpmsg_driver pmic_glink_driver = {
	.probe = pmic_glink_probe,
	.remove = pmic_glink_remove,
	.callback = pmic_glink_callback,
	.id_table = pmic_glink_id_match,
	.drv  = {
		.name  = "qcom_pmic_glink",
	},
};
module_rpmsg_driver(pmic_glink_driver);

MODULE_DESCRIPTION("Qualcomm PMIC GLINK driver");
MODULE_LICENSE("GPL v2");
