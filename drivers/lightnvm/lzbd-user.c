// SPDX-License-Identifier: GPL-2.0
/*
 *
 * Zoned block device lightnvm target
 * Copyright (C) 2019 CNEX Labs
 *
 * User interfacing code: read/write/reset requests
 */

#include "lzbd.h"

static void lzbd_fail_bio(struct bio *bio, char *op)
{
	pr_err("lzbd: failing %s. start lba: %lu  length: %lu\n", op,
		lzbd_get_bio_lba(bio), lzbd_get_bio_len(bio));

	bio_io_error(bio);
}

static struct lzbd_zone *lzbd_get_zone(struct lzbd *lzbd, sector_t sector)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	struct lzbd_zone *zone;
	struct blk_zone *bz;

	sector_div(sector, dl->zone_size);

	if (sector >= dl->zones)
		return NULL;

	zone = &lzbd->zones[sector];
	bz = &zone->blk_zone;

	return zone;
}

static int lzbd_write_rq(struct lzbd *lzbd, struct lzbd_zone *zone,
			  struct bio *bio)
{
	sector_t sector = bio->bi_iter.bi_sector;
	sector_t nr_secs = lzbd_get_bio_len(bio);
	struct blk_zone *bz;
	int left;

	mutex_lock(&zone->lock);

	bz = &zone->blk_zone;

	if (bz->cond == BLK_ZONE_COND_OFFLINE) {
		mutex_unlock(&zone->lock);
		return -EIO;
	}

	if (bz->cond == BLK_ZONE_COND_EMPTY)
		bz->cond = BLK_ZONE_COND_IMP_OPEN;

	if (sector != bz->wp) {
		if (sector == bz->start) {
			if (lzbd_zone_reset(lzbd, zone)) {
				pr_err("lzbd: zone reset failed");
				bz->cond = BLK_ZONE_COND_OFFLINE;
				mutex_unlock(&zone->lock);
				return -EIO;
			}
			bz->cond = BLK_ZONE_COND_IMP_OPEN;
			bz->wp = bz->start;
		} else {
			pr_err("lzbd: write pointer error");
			mutex_unlock(&zone->lock);
			return -EIO;
		}
	}

	left = lzbd_zone_write(lzbd, zone, bio);

	bz->wp += (nr_secs - left) << 3;
	if (bz->wp == (bz->start + bz->len)) {
		lzbd_zone_free_wr_buffer(zone);
		bz->cond = BLK_ZONE_COND_FULL;
	}

	mutex_unlock(&zone->lock);

	if (left > 0) {
		pr_err("lzbd: write did not complete");
		return -EIO;
	}

	return 0;
}

static int lzbd_read_rq(struct lzbd *lzbd, struct lzbd_zone *zone,
			 struct bio *bio)
{
	struct blk_zone *bz;
	sector_t read_end, data_end;
	sector_t data_start = bio->bi_iter.bi_sector;
	int ret;

	if (!zone) {
		lzbd_fail_bio(bio, "lzbd: no zone mapped to read sector");
		return -EIO;
	}

	bz = &zone->blk_zone;

	if (!zone->chunks || bz->cond == BLK_ZONE_COND_OFFLINE) {
		/* No valid data in this zone */
		zero_fill_bio(bio);
		bio_endio(bio);
		return 0;
	}

	if (data_start >= bz->wp) {
		zero_fill_bio(bio);
		bio_endio(bio);
		return 0;
	}

	read_end = bio_end_sector(bio);
	data_end = min_t(sector_t, bz->wp, read_end);

	if (read_end > data_end) {
		sector_t split_sz = data_end - data_start;
		struct bio *split;

		if (data_end <= data_start) {
			lzbd_fail_bio(bio, "internal error(read)");
			return -EIO;
		}

		split = bio_split(bio, split_sz,
				GFP_KERNEL, &lzbd_bio_set);

		ret = lzbd_zone_read(lzbd, zone, split);
		if (ret) {
			lzbd_fail_bio(bio, "split read");
			return -EIO;
		}

		zero_fill_bio(bio);
		bio_endio(bio);

	} else {
		lzbd_zone_read(lzbd, zone, bio);
	}

	return 0;
}

static void lzbd_zone_reset_rq(struct lzbd *lzbd, struct request_queue *q,
			     struct bio *bio)
{
	sector_t sector = bio->bi_iter.bi_sector;
	struct lzbd_zone *zone;

	zone = lzbd_get_zone(lzbd, sector);

	if (zone) {
		struct blk_zone *bz = &zone->blk_zone;
		int ret;

		mutex_lock(&zone->lock);

		ret = lzbd_zone_reset(lzbd, zone);
		if (ret) {
			bz->cond = BLK_ZONE_COND_OFFLINE;
			lzbd_fail_bio(bio, "zone reset");
			mutex_unlock(&zone->lock);
			return;
		}

		bz->cond = BLK_ZONE_COND_EMPTY;
		bz->wp = bz->start;

		mutex_unlock(&zone->lock);

		bio_endio(bio);
	} else {
		bio_io_error(bio);
	}
}

static void lzbd_discard_rq(struct lzbd *lzbd, struct request_queue *q,
			     struct bio *bio)
{
	/* TODO: Implement discard */
	bio_endio(bio);
}

static struct bio *lzbd_zplit(struct lzbd *lzbd, struct bio *bio,
			      struct lzbd_zone **first_zone)
{
	sector_t bio_start = bio->bi_iter.bi_sector;
	sector_t bio_end, zone_end;
	struct lzbd_zone *zone;
	struct blk_zone *bz;
	struct bio *zone_bio;

	zone = lzbd_get_zone(lzbd, bio_start);
	if (!zone)
		return NULL;

	bio_end = bio_end_sector(bio);
	bz = &zone->blk_zone;
	zone_end = bz->start + bz->len;

	if (bio_end > zone_end) {
		zone_bio = bio_split(bio, zone_end - bio_start,
				GFP_KERNEL, &lzbd_bio_set);
	} else {
		zone_bio = bio;
	}

	*first_zone = zone;
	return zone_bio;
}

blk_qc_t lzbd_make_rq(struct request_queue *q, struct bio *bio)
{
	struct lzbd *lzbd = q->queuedata;

	if (bio->bi_opf & REQ_PREFLUSH) {
		/* TODO: Implement syncs */
		pr_err("lzbd: ignoring sync!\n");
	}

	if (bio_op(bio) == REQ_OP_READ ||  bio_op(bio) == REQ_OP_WRITE) {
		struct bio *zplit;
		struct lzbd_zone *zone;

		if (!lzbd_get_bio_len(bio)) {
			bio_endio(bio);
			return BLK_QC_T_NONE;
		}

		do  {
			zplit = lzbd_zplit(lzbd, bio, &zone);
			if (!zplit || !zone) {
				lzbd_fail_bio(bio, "zone split");
				return BLK_QC_T_NONE;
			}

			if (op_is_write(bio_op(bio))) {
				if (lzbd_write_rq(lzbd, zone, zplit)) {
					lzbd_fail_bio(zplit, "write");
					if (zplit != bio)
						lzbd_fail_bio(bio,
							"write");

					return BLK_QC_T_NONE;
				}
			} else {
				if (lzbd_read_rq(lzbd, zone, zplit)) {
					lzbd_fail_bio(zplit, "read");
					if (zplit != bio)
						lzbd_fail_bio(bio,
							"read");
					return BLK_QC_T_NONE;
				}
			}
		} while (bio != zplit);

		return BLK_QC_T_NONE;
	}

	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
		lzbd_discard_rq(lzbd, q, bio);
		break;
	case REQ_OP_ZONE_RESET:
		lzbd_zone_reset_rq(lzbd, q, bio);
		break;
	default:
		pr_err("lzbd: unsupported operation: %d", bio_op(bio));
		bio_io_error(bio);
		break;
	}

	return BLK_QC_T_NONE;
}

int lzbd_report_zones(struct gendisk *disk, sector_t sector,
		      struct blk_zone *zones, unsigned int *nr_zones,
		      gfp_t gfp_mask)
{
	struct lzbd *lzbd = disk->private_data;
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	unsigned int max_zones = *nr_zones;
	unsigned int reported = 0;
	struct lzbd_zone *zone;

	sector_div(sector, dl->zone_size);

	while ((zone = lzbd_get_zone(lzbd, sector))) {
		struct blk_zone *bz = &zone->blk_zone;

		if (reported >= max_zones)
			break;

		memcpy(&zones[reported], bz, sizeof(*bz));

		sector = sector + dl->zone_size;
		reported++;
	}

	*nr_zones = reported;

	return 0;
}
