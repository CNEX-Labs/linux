// SPDX-License-Identifier: GPL-2.0
/*
 *
 * Zoned block device lightnvm target
 * Copyright (C) 2019 CNEX Labs
 *
 * Internal zone handling
 */

#include "lzbd.h"

static struct lzbd_chunk *lzbd_get_chunk(struct lzbd *lzbd, int pref_pu)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	int parallel_units = geo->all_luns;
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	struct lzbd_chunks *chunks = &lzbd->chunks;
	int i = pref_pu;
	int retries = dl->zone_chunks - 1;

	do {
		struct lzbd_pu *pu = &chunks->pus[i];
		struct list_head *chk_list = &pu->chk_list;

		mutex_lock(&pu->lock);

		if (!list_empty(&pu->chk_list)) {
			struct lzbd_chunk *chunk;

			chunk = list_first_entry(chk_list,
						 struct lzbd_chunk, list);
			list_del(&chunk->list);
			mutex_unlock(&pu->lock);
			return chunk;
		}
		mutex_unlock(&pu->lock);

		if (++i == parallel_units)
			i = 0;

	} while (retries--);

	return NULL;
}

void lzbd_zone_free_wr_buffer(struct lzbd_zone *zone)
{
	kfree(zone->wr_align.buffer);
	zone->wr_align.buffer = NULL;
	zone->wr_align.secs = 0;
}

static void lzbd_zone_deallocate(struct lzbd *lzbd, struct lzbd_zone *zone)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	struct lzbd_chunks *chunks = &lzbd->chunks;
	int i;

	if (!zone->chunks)
		return;

	for (i = 0; i < dl->zone_chunks; i++) {
		struct lzbd_chunk *chunk = zone->chunks[i];

		if (chunk) {
			struct lzbd_pu *pu = &chunks->pus[chunk->pu];

			mutex_lock(&pu->lock);

			/* TODO: implement proper wear leveling
			 * The wear indices do not get updated right now
			 * so just add the chunk at the bottom of the list
			 */
			list_add_tail(&chunk->list, &pu->chk_list);
			mutex_unlock(&pu->lock);
		}
	}

	lzbd_zone_free_wr_buffer(zone);
	kfree(zone->chunks);
	zone->chunks = NULL;
}

int lzbd_zone_allocate(struct lzbd *lzbd, struct lzbd_zone *zone)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	int to_allocate = dl->zone_chunks;
	int i;

	zone->chunks = kmalloc_array(to_allocate,
			sizeof(struct lzbd_chunk *),
			GFP_KERNEL | __GFP_ZERO);

	if (!zone->chunks)
		return -ENOMEM;

	zone->wr_align.secs = 0;

	zone->wr_align.buffer = kzalloc(geo->ws_opt << LZBD_SECTOR_BITS,
					GFP_KERNEL);
	if (!zone->wr_align.buffer) {
		kfree(zone->chunks);
		return -ENOMEM;
	}

	for (i = 0; i < to_allocate; i++) {
		struct lzbd_chunk *chunk = lzbd_get_chunk(lzbd, i);

		if (!chunk) {
			pr_err("failed to allocate zone!\n");
			lzbd_zone_deallocate(lzbd, zone);
			return -ENOSPC;
		}

		zone->chunks[i] = chunk;
	}

	return 0;
}

static int lzbd_zone_reset_chunks(struct lzbd *lzbd, struct lzbd_zone *zone)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	int i = 0;

	/* TODO: Do parallel resetting and handle reset failures */
	for (i = 0; i < dl->zone_chunks; i++) {
		struct lzbd_chunk *chunk = zone->chunks[i];
		int state = chunk->meta->state;
		int ret;

		if (state & (NVM_CHK_ST_CLOSED | NVM_CHK_ST_OPEN)) {
			ret = lzbd_reset_chunk(lzbd, chunk);
			if (ret) {
				pr_err("lzbd: reset failed!\n");
				return -EIO; /* Fail for now if reset fails */
			}
		}
	}

	return 0;
}

int lzbd_zone_reset(struct lzbd *lzbd, struct lzbd_zone *zone)
{
	int ret;

	lzbd_zone_deallocate(lzbd, zone);
	ret = lzbd_zone_allocate(lzbd, zone);
	if (ret)
		return ret;

	ret = lzbd_zone_reset_chunks(lzbd, zone);

	zone->wi = 0;
	atomic_set(&zone->s_wp, 0);

	return ret;
}


static void lzbd_add_to_align_buf(struct lzbd_wr_align *wr_align,
				   struct bio *bio, int secs)
{
	char *buffer = wr_align->buffer;

	buffer += (wr_align->secs * LZBD_SECTOR_SIZE);

	mutex_lock(&wr_align->lock);
	while (secs--) {
		char *data = bio_data(bio);

		memcpy(buffer, data, LZBD_SECTOR_SIZE);
		buffer += LZBD_SECTOR_SIZE;
		wr_align->secs++;
		bio_advance(bio, LZBD_SECTOR_SIZE);

	}

	mutex_unlock(&wr_align->lock);
}

static void lzbd_read_from_align_buf(struct lzbd_wr_align *wr_align,
				   struct bio *bio, int start, int secs)
{
	char *buffer = wr_align->buffer;

	buffer += (start * LZBD_SECTOR_SIZE);

	mutex_lock(&wr_align->lock);
	while (secs--) {
		char *data = bio_data(bio);

		memcpy(data, buffer, LZBD_SECTOR_SIZE);
		buffer += LZBD_SECTOR_SIZE;

		bio_advance(bio, LZBD_SECTOR_SIZE);
	}

	mutex_unlock(&wr_align->lock);
}

int lzbd_zone_write(struct lzbd *lzbd, struct lzbd_zone *zone, struct bio *bio)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	struct lzbd_wr_align *wr_align = &zone->wr_align;
	int sectors_left = lzbd_get_bio_len(bio);
	int ret;

	/* Unaligned write? */
	if (wr_align->secs) {
		int secs;

		secs = min_t(int, geo->ws_opt - wr_align->secs, sectors_left);
		lzbd_add_to_align_buf(wr_align, bio, secs);
		sectors_left -= secs;

		/* Time to flush the alignment buffer ? */
		if (wr_align->secs == geo->ws_opt) {
			struct bio *bio;

			bio = bio_map_kern(dev->q, wr_align->buffer,
					geo->ws_opt * LZBD_SECTOR_SIZE,
					GFP_KERNEL);
			if (!bio) {
				pr_err("lzbd: failed to map align bio\n");
				return -EIO;
			}

			ret = lzbd_write_to_chunk_user(lzbd,
				zone->chunks[zone->wi], bio);

			if (ret) {
				pr_err("lzbd: alignment write failed\n");
				return sectors_left;
			}

			wr_align->secs = 0;
			zone->wi = (zone->wi + 1) % dl->zone_chunks;
			atomic_add(geo->ws_opt, &zone->s_wp);
		}
	}

	if (sectors_left == 0) {
		bio_endio(bio);
		return 0;
	}

	while (sectors_left > geo->ws_opt) {
		struct bio *split;

		split = bio_split(bio, geo->ws_opt << 3,
				GFP_KERNEL, &lzbd_bio_set);

		if (split == NULL) {
			pr_err("lzbd: split failed!\n");
			return sectors_left;
		}

		ret = lzbd_write_to_chunk_user(lzbd,
				zone->chunks[zone->wi], split);

		if (ret)
			return sectors_left;

		zone->wi = (zone->wi + 1) % dl->zone_chunks;
		atomic_add(geo->ws_opt, &zone->s_wp);

		sectors_left -= geo->ws_opt;
	}

	if (sectors_left == geo->ws_opt) {
		ret = lzbd_write_to_chunk_user(lzbd,
				zone->chunks[zone->wi], bio);
		if (ret) {
			pr_err("lzbd: last aligned write failed\n");
			return sectors_left;
		}

		zone->wi = (zone->wi + 1) % dl->zone_chunks;
		atomic_add(geo->ws_opt, &zone->s_wp);
		sectors_left -= geo->ws_opt;
	} else {
		wr_align->secs = 0;
		lzbd_add_to_align_buf(wr_align, bio, sectors_left);
		bio_endio(bio);
		sectors_left = 0;
	}

	return sectors_left;
}

void lzbd_user_read_put(struct kref *ref)
{
	struct lzbd_user_read *read;

	read = container_of(ref, struct lzbd_user_read, ref);

	if (unlikely(read->error))
		bio_io_error(read->user_bio);
	else
		bio_endio(read->user_bio);

	kfree(read);
}


static struct lzbd_user_read *lzbd_init_user_read(struct bio *bio)
{
	struct lzbd_user_read *rd;

	rd = kmalloc(sizeof(struct lzbd_user_read), GFP_KERNEL);
	if (!rd)
		return NULL;

	rd->user_bio = bio;
	kref_init(&rd->ref);
	rd->error = false;

	return rd;
}


int lzbd_zone_read(struct lzbd *lzbd, struct lzbd_zone *zone, struct bio *bio)
{
	struct lzbd_disk_layout *dl = &lzbd->disk_layout;
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct blk_zone *bz = &zone->blk_zone;
	struct lzbd_chunk *read_chunk;
	sector_t lba = lzbd_get_bio_lba(bio);
	int to_read = lzbd_get_bio_len(bio);
	struct lzbd_user_read *read;
	int readsize;
	int zsi, zso, csi, co;
	int pu;
	int ret;

	read = lzbd_init_user_read(bio);
	if (!read) {
		pr_err("lzbd: failed to init read\n");
		bio_io_error(bio);
		return -EIO;
	}

	if (!zone->chunks) {
		/* No data has been written to this zone */
		zero_fill_bio(bio);
		bio_endio(bio);
		kfree(read);
		return 0;
	}

	lba -= bz->start >> 3;

	/* TODO: use sector_div instead */

	/* Zone stripe index and offset */
	zsi = lba / geo->ws_opt; /* zone stripe index */
	zso = lba % geo->ws_opt; /* zone stripe offset */

	pu = zsi % dl->zone_chunks;
	read_chunk = zone->chunks[pu];

	/* Chunk stripe index and chunk offset */
	csi = lba / (dl->zone_chunks * geo->ws_opt);
	co = csi * geo->ws_opt + zso;

	readsize = min_t(int, geo->ws_opt - zso, to_read);

	while (to_read > 0) {
		struct bio *rbio = bio;
		int s_wp = atomic_read(&zone->s_wp);

		if (lba >= s_wp) {
			/* Grab the write lock to prevent races
			 * with writes
			 */
			mutex_lock(&zone->lock);
			if (lba >= atomic_read(&zone->s_wp)) {
				lzbd_read_from_align_buf(&zone->wr_align, bio,
						zso, to_read);
				mutex_unlock(&zone->lock);
				ret = 0;
				goto done;
			}
			mutex_unlock(&zone->lock);
		}

		if ((zso + to_read) > geo->ws_opt) {

			rbio = bio_split(bio, readsize << 3, GFP_KERNEL,
					&lzbd_bio_set);

			if (!rbio) {
				read->error = true;
				ret = -EIO;
				goto done;
			}

		}

		if (lba + to_read >= s_wp)
			readsize = s_wp - lba;

		kref_get(&read->ref);
		ret = lzbd_read_from_chunk_user(lzbd, zone->chunks[pu],
						rbio, read, co);
		if (ret) {
			pr_err("lzbd: user disk read failed!\n");
			read->error = true;
			kref_put(&read->ref, lzbd_user_read_put);
			ret = -EIO;
			goto done;
		}

		lba += readsize;

		if (zso) {
			co -= zso;
			zso = 0;
		}

		if (++pu == dl->zone_chunks) {
			pu = 0;
			co += geo->ws_opt;
		}

		to_read -= readsize;
		readsize = min_t(int, geo->ws_opt, to_read);
		read_chunk = zone->chunks[pu];
	}

	ret = 0;
done:
	kref_put(&read->ref, lzbd_user_read_put);
	return ret;
}

