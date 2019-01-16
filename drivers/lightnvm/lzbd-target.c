// SPDX-License-Identifier: GPL-2.0
/*
 *
 * Zoned block device lightnvm target
 * Copyright (C) 2019 CNEX Labs
 *
 * Target handling: module boilerplate, init and remove
 */

#include <linux/module.h>

#include "lzbd.h"

struct bio_set lzbd_bio_set;

static sector_t lzbd_capacity(void *private)
{
	struct lzbd *lzbd = private;
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;

	return dl->capacity;
}

static void lzbd_free_chunks(struct lzbd *lzbd)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct lzbd_chunks *chunks = &lzbd->chunks;
	int parallel_units = geo->all_luns;
	int i;

	for (i = 0; i < parallel_units; i++) {
		struct lzbd_pu *pu = &chunks->pus[i];
		struct list_head *pos, *n;
		struct lzbd_chunk *chunk;

		mutex_destroy(&pu->lock);

		list_for_each_safe(pos, n, &pu->chk_list) {
			chunk = list_entry(pos, struct lzbd_chunk, list);

			list_del(pos);
			mutex_destroy(&chunk->wr_ctx.wr_lock);
			kfree(chunk);
		}
	}

	kfree(chunks->pus);
	vfree(chunks->meta);
}

/* Add chunk to chunklist in falling wi order */
void lzbd_add_chunk(struct lzbd_chunk *chunk,
		    struct list_head *head)
{
	struct lzbd_chunk *c = NULL;

	list_for_each_entry(c, head, list) {
		if (chunk->meta->wi < c->meta->wi)
			break;
	}

	list_add_tail(&chunk->list, &c->list);
}


static int lzbd_init_chunks(struct lzbd *lzbd)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct nvm_chk_meta *meta;
	struct lzbd_chunks *chunks = &lzbd->chunks;
	int parallel_units = geo->all_luns;
	struct ppa_addr ppa;
	int ret;
	int chk;
	int i;

	chunks->pus = kcalloc(parallel_units, sizeof(struct lzbd_pu),
				GFP_KERNEL);
	if (!chunks->pus)
		return -ENOMEM;

	meta = vzalloc(geo->all_chunks * sizeof(*meta));
	if (!meta) {
		kfree(chunks->pus);
		return -ENOMEM;
	}

	chunks->meta = meta;

	for (i = 0; i < parallel_units; i++) {
		struct lzbd_pu *lzbd_pu = &chunks->pus[i];

		INIT_LIST_HEAD(&lzbd_pu->chk_list);
		mutex_init(&lzbd_pu->lock);
	}

	ppa.ppa = 0; /* get all chunks */
	ret = nvm_get_chunk_meta(dev, ppa, geo->all_chunks, meta);
	if (ret) {
		lzbd_free_chunks(lzbd);
		return -EIO;
	}

	for (chk = 0; chk < geo->num_chk; chk++) {
		for (i = 0; i < parallel_units; i++) {
			struct lzbd_pu *lzbd_pu = &chunks->pus[i];
			struct nvm_chk_meta *chk_meta;
			int grp = i / geo->num_lun;
			int pu = i % geo->num_lun;
			int offset = 0;

			offset += grp * geo->num_lun * geo->num_chk;
			offset += pu * geo->num_chk;
			offset += chk;

			chk_meta = &meta[offset];

			if (!(chk_meta->state & NVM_CHK_ST_OFFLINE)) {
				struct lzbd_chunk *chunk;

				chunk = kzalloc(sizeof(*chunk), GFP_KERNEL);
				if (!chunk) {
					lzbd_free_chunks(lzbd);
					return -ENOMEM;
				}

				INIT_LIST_HEAD(&chunk->list);
				chunk->meta = chk_meta;
				chunk->ppa.m.grp = grp;
				chunk->ppa.m.pu = pu;
				chunk->ppa.m.chk = chk;
				chunk->pu = i;

				lzbd_add_chunk(chunk, &lzbd_pu->chk_list);

				mutex_init(&chunk->wr_ctx.wr_lock);
				chunk->wr_ctx.lzbd = lzbd;
			} else {
				lzbd_pu->offline_chks++;
			}
		}
	}

	return 0;
}

static struct lzbd_zone *lzbd_init_zones(struct lzbd *lzbd)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	int i;
	struct lzbd_zone *zones;
	u64 zone_offset = 0;

	zones = kmalloc_array(dl->zones, sizeof(*zones), GFP_KERNEL);
	if (!zones)
		return NULL;

	/* Sequential zones */
	for (i = 0; i < dl->zones; i++, zone_offset += dl->zone_size) {
		struct lzbd_zone *zone = &zones[i];
		struct blk_zone *bz = &zone->blk_zone;

		bz->start = zone_offset;
		bz->len = dl->zone_size;
		bz->wp = zone_offset + dl->zone_size;
		bz->type = BLK_ZONE_TYPE_SEQWRITE_REQ;
		bz->cond = BLK_ZONE_COND_FULL;

		bz->non_seq = 0;
		bz->reset = 1;

		/* zero-out reserved bytes to be forward-compatible */
		memset(bz->reserved, 0, sizeof(bz->reserved));

		zones[i].chunks = NULL;
		mutex_init(&zone->lock);

		zone->wr_align.buffer = NULL;
		mutex_init(&zone->wr_align.lock);
	}

	return zones;
}


static void lzbd_config_disk_queue(struct lzbd *lzbd)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct gendisk *disk = lzbd->disk;
	struct nvm_geo *geo = &dev->geo;
	struct request_queue *bqueue = dev->q;
	struct request_queue *dqueue = disk->queue;

	blk_queue_logical_block_size(dqueue, queue_physical_block_size(bqueue));
	blk_queue_max_hw_sectors(dqueue, queue_max_hw_sectors(bqueue));

	blk_queue_write_cache(dqueue, true, false);

	dqueue->limits.discard_granularity = geo->clba * geo->csecs;
	dqueue->limits.discard_alignment = 0;
	blk_queue_max_discard_sectors(dqueue, UINT_MAX >> 9);
	blk_queue_flag_set(QUEUE_FLAG_DISCARD, dqueue);

	dqueue->limits.zoned = BLK_ZONED_HM;
	dqueue->nr_zones = dl->zones;
	dqueue->limits.chunk_sectors = dl->zone_size;
}


static int lzbd_dev_is_supported(struct nvm_tgt_dev *dev)
{
	struct nvm_geo *geo = &dev->geo;

	if (geo->major_ver_id != 2) {
		pr_err("lzbd only supports Open Channel 2.x devices\n");
		return 0;
	}

	if (geo->csecs != LZBD_SECTOR_SIZE) {
		pr_err("lzbd: unsupported block size %d", geo->csecs);
		return 0;
	}

	/* We will need to check(some of) these parameters later on,
	 * but for now, just print them. TODO: check cunit, maxoc
	 */
	pr_info("lzbd: ws_min:%d ws_opt:%d cunits:%d maxoc:%d maxocpu:%d\n",
		geo->ws_min, geo->ws_opt, geo->mw_cunits,
		geo->maxoc, geo->maxocpu);

	return 1;
}


static const struct block_device_operations lzbd_fops = {
	.report_zones	= lzbd_report_zones,
	.owner		= THIS_MODULE,
};

static void lzbd_dump_geo(struct nvm_tgt_dev *dev)
{
	struct nvm_geo *geo = &dev->geo;

	pr_info("lzbd: target geo: num_grp: %d num_pu: %d num_chk: %d ws_opt: %d\n",
		geo->num_ch, geo->all_luns, geo->num_chk, geo->ws_opt);
}

static void lzbd_create_layout(struct lzbd *lzbd)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	int user_chunks;

	/* Default to 20% over-provisioning if not specified
	 * (better safe than sorry)
	 */
	if (geo->op == NVM_TARGET_DEFAULT_OP)
		dl->op = 20;
	else
		dl->op = geo->op;

	dl->meta_chunks = 4;
	dl->zone_chunks = geo->all_luns;
	dl->zone_size = (geo->clba * dl->zone_chunks) << 3;

	user_chunks = geo->all_chunks * (100 - dl->op);
	sector_div(user_chunks, 100);

	dl->zones = user_chunks / dl->zone_chunks;
	dl->capacity = dl->zones * dl->zone_size;
}

static void lzbd_dump_layout(struct lzbd *lzbd)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;

	pr_info("lzbd: layout: op: %d zones: %d per zone chks: %d secs: %llu\n",
		dl->op, dl->zones, dl->zone_chunks,
		(unsigned long long)dl->zone_size);
}

static void *lzbd_init(struct nvm_tgt_dev *dev, struct gendisk *tdisk,
		       int flags)
{
	struct lzbd *lzbd;

	lzbd_dump_geo(dev);

	if (!lzbd_dev_is_supported(dev))
		return ERR_PTR(-EINVAL);


	if (!(flags & NVM_TARGET_FACTORY)) {
		pr_err("lzbd: metadata not persisted, only factory init supported\n");
		return ERR_PTR(-EINVAL);
	}

	lzbd = kzalloc(sizeof(struct lzbd), GFP_KERNEL);
	if (!lzbd)
		return ERR_PTR(-ENOMEM);

	lzbd->dev = dev;
	lzbd->disk = tdisk;

	lzbd_create_layout(lzbd);
	lzbd_dump_layout(lzbd);

	lzbd->zones = lzbd_init_zones(lzbd);

	if (!lzbd->zones)
		goto err_free_lzbd;

	if (lzbd_init_chunks(lzbd))
		goto err_free_zones;
	lzbd_config_disk_queue(lzbd);

	/* Override the fops to enable zone reporting support */
	lzbd->disk->fops = &lzbd_fops;

	return lzbd;

err_free_zones:
	kfree(lzbd->zones);
err_free_lzbd:
	kfree(lzbd);

	return ERR_PTR(-ENOMEM);
}

static void lzbd_exit(void *private, bool graceful)
{
	struct lzbd *lzbd = private;

	lzbd_free_chunks(lzbd);
	kfree(lzbd->zones);
	kfree(lzbd);
}


static int lzbd_sysfs_init(struct gendisk *tdisk)
{
	/* Crickets */
	return 0;
}

static void lzbd_sysfs_exit(struct gendisk *tdisk)
{
	/* Tumbleweed */
}

static struct nvm_tgt_type tt_lzbd = {
	.name		= "lzbd",
	.version	= {0, 0, 1},

	.init		= lzbd_init,
	.exit		= lzbd_exit,

	.capacity	= lzbd_capacity,
	.make_rq	= lzbd_make_rq,

	.sysfs_init	= lzbd_sysfs_init,
	.sysfs_exit	= lzbd_sysfs_exit,

	.owner		= THIS_MODULE,
};

static int __init lzbd_module_init(void)
{
	int ret;

	ret = bioset_init(&lzbd_bio_set, BIO_POOL_SIZE, 0, 0);
	if (ret)
		return ret;

	return nvm_register_tgt_type(&tt_lzbd);
}

static void lzbd_module_exit(void)
{
	bioset_exit(&lzbd_bio_set);
	nvm_unregister_tgt_type(&tt_lzbd);
}

module_init(lzbd_module_init);
module_exit(lzbd_module_exit);
MODULE_AUTHOR("Hans Holmberg <hans.holmberg@cnexlabs.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Zoned Block-Device for Open-Channel SSDs");
