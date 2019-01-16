/* SPDX-License-Identifier: GPL-2.0 */
/*
 *
 * Zoned block device lightnvm target
 * Copyright (C) 2019 CNEX Labs
 *
 */

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/lightnvm.h>

#define LZBD_SECTOR_BITS (12) /* 4096 */
#define LZBD_SECTOR_SIZE (4096UL)

/* sector unit to lzbd sector shift*/
#define LZBD_SECTOR_SHIFT (3)

extern struct bio_set lzbd_bio_set;


/* Get length, in lzbd sectors, of bio */
static inline sector_t lzbd_get_bio_len(struct bio *bio)
{
	return bio->bi_iter.bi_size >> LZBD_SECTOR_BITS;
}

/* Get bio start lba in lzbd sectors */
static inline sector_t lzbd_get_bio_lba(struct bio *bio)
{
	return bio->bi_iter.bi_sector >> LZBD_SECTOR_SHIFT;
}

struct lzbd_wr_ctx {
	struct lzbd *lzbd;
	struct mutex wr_lock;		/* Max one outstanding write */

	void *private;
	/* bio completion list goes here, along with lock*/
};

struct lzbd_user_read {
	struct bio *user_bio;
	struct kref ref;
	bool error;
};

struct lzbd_rd_ctx {
	struct lzbd *lzbd;
	struct lzbd_user_read *read;
	struct nvm_rq rqd;
};

struct lzbd_chunk {
	struct nvm_chk_meta *meta;	/* Metadata for the chunk */
	struct ppa_addr ppa;		/* Start ppa */
	int pu;				/* Parallel unit */

	struct lzbd_wr_ctx wr_ctx;
	struct list_head list;		/* A chunk is offline or
					 * part of a PU free list or
					 * part of a zone chunk list or
					 * part of a metadata list
					 */

	/* a cuinits buffer should go here */
};

struct lzbd_pu {
	struct list_head chk_list;	/* One list per parallel unit */
	struct mutex lock;		/* Protecting list */
	int offline_chks;
};

struct lzbd_chunks {
	struct lzbd_pu *pus;		/* Chunks organized per parallel unit*/
	struct nvm_chk_meta *meta;	/* Metadata for all chunks */
};

struct lzbd_wr_align {
	void *buffer;		/* Buffer data */
	int secs;		/* Number of 4k secs in buffer */
	struct mutex lock;
};

struct lzbd_zone {
	struct blk_zone blk_zone;
	struct lzbd_chunk **chunks;

	int wi;				/* Write chunk index */
	atomic_t s_wp;			/* Sync write pointer */

	struct lzbd_wr_align wr_align;	/* Write alignment buffer */

	struct mutex lock;		/* Write lock */
};

struct lzbd_disk_layout {
	int		op;		/* Over provision ratio */
	int		meta_chunks;	/* Metadata chunks */

	int		zones;		/* Number of zones */
	int		zone_chunks;	/* Zone per chunk */
	sector_t	zone_size;	/* Number of 512b sectors per zone */

	sector_t	capacity;	/* Disk capacity in 512b sectors */
};

struct lzbd {
	struct nvm_tgt_dev *dev;
	struct gendisk *disk;

	struct lzbd_zone *zones;

	struct lzbd_chunks chunks;
	struct lzbd_disk_layout disk_layout;
};

blk_qc_t lzbd_make_rq(struct request_queue *q, struct bio *bio);

int lzbd_report_zones(struct gendisk *disk, sector_t sector,
			       struct blk_zone *zones, unsigned int *nr_zones,
			       gfp_t gfp_mask);

int lzbd_reset_chunk(struct lzbd *lzbd, struct lzbd_chunk *chunk);
int lzbd_write_to_chunk_sync(struct lzbd *lzbd, struct lzbd_chunk *chunk,
			     struct bio *bio);
int lzbd_write_to_chunk_user(struct lzbd *lzbd, struct lzbd_chunk *chunk,
			     struct bio *user_bio);
int lzbd_read_from_chunk_user(struct lzbd *lzbd, struct lzbd_chunk *chunk,
			 struct bio *bio, struct lzbd_user_read *user_read,
			 int start);
int lzbd_zone_reset(struct lzbd *lzbd, struct lzbd_zone *zone);
int lzbd_zone_write(struct lzbd *lzbd, struct lzbd_zone *zone, struct bio *bio);
int lzbd_zone_read(struct lzbd *lzbd, struct lzbd_zone *zone, struct bio *bio);
void lzbd_zone_free_wr_buffer(struct lzbd_zone *zone);
void lzbd_user_read_put(struct kref *ref);

