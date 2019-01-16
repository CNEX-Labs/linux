// SPDX-License-Identifier: GPL-2.0
/*
 *
 * Zoned block device lightnvm target
 * Copyright (C) 2019 CNEX Labs
 *
 * Disk I/O
 */

#include "lzbd.h"

static inline void lzbd_chunk_log(char *message, int err,
				  struct lzbd_chunk *lzbd_chunk)
{

	/* TODO: create trace points in stead */
	pr_err("lzbd: %s: err: %d grp: %d pu: %d chk: %d slba: %llu state: %d wp: %llu\n",
		message,
		err,
		lzbd_chunk->ppa.m.grp,
		lzbd_chunk->ppa.m.pu,
		lzbd_chunk->ppa.m.chk,
		lzbd_chunk->meta->slba,
		lzbd_chunk->meta->state,
		lzbd_chunk->meta->wp);
}

int lzbd_reset_chunk(struct lzbd *lzbd, struct lzbd_chunk *chunk)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_rq rqd = {NULL};
	int ret;

	if ((chunk->meta->state & (NVM_CHK_ST_FREE | NVM_CHK_ST_OFFLINE))) {
		pr_err("lzbd: reset of chunk in illegal state: %d\n",
				chunk->meta->state);
		return -EINVAL;
	}

	rqd.opcode = NVM_OP_ERASE;
	rqd.ppa_addr = chunk->ppa;
	rqd.nr_ppas = 1;
	rqd.is_seq = 1;

	ret = nvm_submit_io_sync(dev, &rqd);

	/* For now, set the chunk offline if the request fails
	 * TODO: Pass a buffer in the request so  we get a full
	 *       meta update from the device
	 */

	if (!ret) {
		if (rqd.error) {
			if ((rqd.error & 0xfff) == 0x2c0) {
				lzbd_chunk_log("chunk went offline", 0, chunk);
				chunk->meta->state = NVM_CHK_ST_OFFLINE;
			} else {
				if ((rqd.error & 0xfff) == 0x2c1) {
					lzbd_chunk_log("invalid reset",
						-EINVAL, chunk);
				} else {
					lzbd_chunk_log("unknown error",
						-EINVAL, chunk);
				}
				return -EINVAL;
			}
		} else {
			chunk->meta->state = NVM_CHK_ST_FREE;
			chunk->meta->wp = 0;
		}
	}

	return ret;
}

/* Prepare a write request to a chunk. If the function call succeeds
 * the call must be paired with a lzbd_free_wr_rq
 */
static int lzbd_init_wr_rq(struct lzbd *lzbd, struct lzbd_chunk *chunk,
			   struct bio *bio, struct nvm_rq *rq)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr ppa;
	struct ppa_addr *ppa_list;
	int metadata_sz = geo->sos * NVM_MAX_VLBA;
	int nr_ppas = geo->ws_opt;
	int i;

	memset(rq, 0, sizeof(struct nvm_rq));

	rq->bio = bio;
	rq->opcode = NVM_OP_PWRITE;
	rq->nr_ppas = nr_ppas;
	rq->is_seq = 1;
	rq->private = &chunk->wr_ctx;

	/* Do we respect the write size restrictions? */
	if (nr_ppas > geo->ws_opt || (nr_ppas % geo->ws_min)) {
		pr_err("lzbd: write size violation size: %d\n", nr_ppas);
		return -EINVAL;
	}

	/* Is the chunk in the right state? */
	if (!(chunk->meta->state & (NVM_CHK_ST_FREE | NVM_CHK_ST_OPEN))) {
		pr_err("lzbd: write to chunk in wrong state: %d\n",
				chunk->meta->state);
		return -EINVAL;
	}

	/* Do we have room for the write? */
	if ((chunk->meta->wp + nr_ppas) > geo->clba) {
		pr_err("lzbd: cant fit write into chunk size %d\n", nr_ppas);
		return -EINVAL;
	}

	rq->meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
						&rq->dma_meta_list);
	if (!rq->meta_list)
		return -ENOMEM;

	/* We don't care about metadata. yet. */
	memset(rq->meta_list, 42, metadata_sz);

	if (nr_ppas > 1) {
		rq->ppa_list = rq->meta_list + metadata_sz;
		rq->dma_ppa_list = rq->dma_meta_list + metadata_sz;
	}

	//pr_err("lzbd: writing %d sectors\n", nr_ppas);

	ppa.ppa = chunk->ppa.ppa;

	mutex_lock(&chunk->wr_ctx.wr_lock);

	ppa.m.sec = chunk->meta->wp;

	ppa_list = nvm_rq_to_ppa_list(rq);
	for (i = 0; i < nr_ppas; i++) {
		ppa_list[i].ppa = ppa.ppa;
		ppa.m.sec++;
	}

	return 0;
}

static void lzbd_free_wr_rq(struct lzbd *lzbd, struct nvm_rq *rq)
{
	struct lzbd_wr_ctx *wr_ctx = rq->private;
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct lzbd_chunk *chunk;

	chunk = container_of(wr_ctx, struct lzbd_chunk, wr_ctx);

	mutex_unlock(&chunk->wr_ctx.wr_lock);
	nvm_dev_dma_free(dev->parent, rq->meta_list, rq->dma_meta_list);
}

static inline void lzbd_wr_rq_post(struct nvm_rq *rq)
{
	struct lzbd_wr_ctx *wr_ctx = rq->private;
	struct lzbd *lzbd = wr_ctx->lzbd;
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct lzbd_chunk *chunk;

	chunk = container_of(wr_ctx, struct lzbd_chunk, wr_ctx);

	if (!rq->error) {
		if (chunk->meta->wp == 0)
			chunk->meta->state = NVM_CHK_ST_OPEN;

		chunk->meta->wp += rq->nr_ppas;
		if (chunk->meta->wp == geo->clba)
			chunk->meta->state = NVM_CHK_ST_CLOSED;
	}
}

int lzbd_write_to_chunk_sync(struct lzbd *lzbd, struct lzbd_chunk *chunk,
			     struct bio *bio)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_rq rq;
	int ret;

	ret = lzbd_init_wr_rq(lzbd, chunk, bio, &rq);
	if (ret)
		return ret;

	ret = nvm_submit_io_sync(dev, &rq);
	if (ret) {
		ret = rq.error;
		pr_err("lzbd: sync write request submit failed: %d\n", ret);
	} else {
		lzbd_wr_rq_post(&rq);
	}

	lzbd_free_wr_rq(lzbd, &rq);

	return ret;
}

static void lzbd_read_endio(struct nvm_rq *rq)
{
	struct lzbd_rd_ctx *rd_ctx = container_of(rq, struct lzbd_rd_ctx, rqd);
	struct lzbd *lzbd = rd_ctx->lzbd;
	struct lzbd_user_read *read = rd_ctx->read;
	struct nvm_tgt_dev *dev = lzbd->dev;

	if (unlikely(rq->error))
		read->error = true;

	if (rq->meta_list)
		nvm_dev_dma_free(dev->parent, rq->meta_list, rq->dma_meta_list);

	kref_put(&read->ref, lzbd_user_read_put);
	kfree(rd_ctx);
}

static int lzbd_read_from_chunk_async(struct lzbd *lzbd,
				      struct lzbd_chunk *chunk,
				      struct bio *bio,
				      struct lzbd_user_read *user_read,
				      int start)
{
	struct nvm_tgt_dev *dev = lzbd->dev;
	struct nvm_geo *geo = &dev->geo;
	struct lzbd_rd_ctx *rd_ctx;
	struct nvm_rq *rq;
	struct ppa_addr ppa;
	struct ppa_addr *ppa_list;
	int metadata_sz = geo->sos * NVM_MAX_VLBA;
	int nr_ppas = lzbd_get_bio_len(bio);
	int ret;
	int i;

	/* Do we respect the read size restrictions? */
	if (nr_ppas >= NVM_MAX_VLBA) {
		pr_err("lzbd: read size violation size: %d\n", nr_ppas);
		return -EINVAL;
	}

	/* Is the chunk in the right state? */
	if (!(chunk->meta->state & (NVM_CHK_ST_OPEN | NVM_CHK_ST_CLOSED))) {
		pr_err("lzbd: read from chunk in wrong state: %d\n",
				chunk->meta->state);
		return -EINVAL;
	}

	/*Are we reading within bounds? */
	if ((start + nr_ppas) > geo->clba) {
		pr_err("lzbd: read past the chunk size %d start: %d\n",
			nr_ppas, start);
		return -EINVAL;
	}

	rd_ctx = kzalloc(sizeof(struct lzbd_rd_ctx), GFP_KERNEL);
	if (!rd_ctx)
		return -ENOMEM;

	rd_ctx->read = user_read;
	rd_ctx->lzbd = lzbd;

	rq = &rd_ctx->rqd;
	rq->bio = bio;
	rq->opcode = NVM_OP_PREAD;
	rq->nr_ppas = nr_ppas;
	rq->end_io = lzbd_read_endio;
	rq->private = lzbd;
	rq->meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
					&rq->dma_meta_list);
	if (!rq->meta_list) {
		kfree(rd_ctx);
		return -ENOMEM;
	}

	if (nr_ppas > 1) {
		rq->ppa_list = rq->meta_list + metadata_sz;
		rq->dma_ppa_list = rq->dma_meta_list + metadata_sz;
	}

	ppa.ppa = chunk->ppa.ppa;
	ppa.m.sec = start;

	ppa_list = nvm_rq_to_ppa_list(rq);
	for (i = 0; i < nr_ppas; i++) {
		ppa_list[i].ppa = ppa.ppa;
		ppa.m.sec++;
	}

	ret = nvm_submit_io(dev, rq);

	if (ret) {
		pr_err("lzbd: read request submit failed: %d\n", ret);
		nvm_dev_dma_free(dev->parent, rq->meta_list, rq->dma_meta_list);
		kfree(rd_ctx);
	}

	return ret;
}

int lzbd_write_to_chunk_user(struct lzbd *lzbd, struct lzbd_chunk *chunk,
			     struct bio *user_bio)
{
	struct bio *write_bio;
	int ret = 0;

	write_bio = bio_clone_fast(user_bio, GFP_KERNEL, &lzbd_bio_set);
	if (!write_bio)
		return -ENOMEM;

	ret = lzbd_write_to_chunk_sync(lzbd, chunk, write_bio);
	if (ret) {
		ret = -EIO;
		bio_io_error(user_bio);
	} else {
		ret = 0;
		bio_endio(user_bio);
	}

	return ret;
}

int lzbd_read_from_chunk_user(struct lzbd *lzbd, struct lzbd_chunk *chunk,
			 struct bio *bio, struct lzbd_user_read *user_read,
			 int start)
{
	struct bio *read_bio;
	int ret = 0;

	read_bio = bio_clone_fast(bio, GFP_KERNEL, &lzbd_bio_set);
	if (!read_bio) {
		pr_err("lzbd: bio clone failed!\n");
		return -ENOMEM;
	}

	ret = lzbd_read_from_chunk_async(lzbd, chunk,
			read_bio, user_read, start);

	return ret;
}

