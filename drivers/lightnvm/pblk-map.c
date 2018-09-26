// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * pblk-map.c - pblk's lba-ppa mapping strategy
 *
 */

#include "pblk.h"

int pblk_line_map_init(struct pblk_line *line)
{
	struct pblk *pblk = line->pblk;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_map *map = line->map;
	u64 off;
	int bit = -1;

	line->map->bitmap = mempool_alloc(l_mg->bitmap_pool, GFP_KERNEL);
	if (!line->map->bitmap)
		return -ENOMEM;

	memset(map->bitmap, 0, lm->sec_bitmap_len);
	map->left_msecs = lm->sec_per_line;

	map->w_err_bitmap = kzalloc(lm->blk_bitmap_len, GFP_KERNEL);
	if (!map->w_err_bitmap)
		return -ENOMEM;

	/* Capture bad block information*/
	while ((bit = find_next_bit(line->blk_bitmap, lm->blk_per_line,
					bit + 1)) < lm->blk_per_line) {
		off = bit * geo->ws_opt;
		bitmap_shift_left(l_mg->bb_aux, l_mg->bb_template, off,
							lm->sec_per_line);
		bitmap_or(map->bitmap, map->bitmap, l_mg->bb_aux,
							lm->sec_per_line);
		map->left_msecs -= geo->clba;
	}

	if (map->left_msecs == 0)
		return -EINVAL;

	map->cur_sec = find_first_zero_bit(map->bitmap, lm->sec_per_line);
	map->cur_lun = find_first_zero_bit(line->blk_bitmap, lm->blk_per_line);

	map->cur_ppa.a.blk = line->id;
	map->cur_ppa.a.ch = pblk->luns[map->cur_lun].bppa.a.ch;
	map->cur_ppa.a.lun = pblk->luns[map->cur_lun].bppa.a.lun;

	pblk_set_dev_chunk_addr(pblk, &map->cur_ppa, 0);
	map->cur_stripe_off = 0;

	return 0;
}

unsigned int pblk_line_secs_left_to_map(struct pblk_line *line)
{
	return line->map->left_msecs;
}

unsigned int pblk_line_map_cur_sec(struct pblk_line *line)
{
	return line->map->cur_sec;
}

void pblk_line_map_free(struct pblk_line *line)
{
	struct pblk *pblk = line->pblk;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg;
	struct pblk_line_map *map = line->map;

	mempool_free(map->bitmap, l_mg->bitmap_pool);
	map->bitmap = NULL;

	kfree(map->w_err_bitmap);
	map->w_err_bitmap = NULL;
}

int pblk_line_map_is_full(struct pblk_line *line)
{
	struct pblk *pblk = line->pblk;
	struct pblk_line_meta *lm = &pblk->lm;

	return bitmap_full(line->map->bitmap, lm->sec_per_line);
}

void pblk_line_map_stop_writing_to_chk(struct pblk_line *line,
				       struct ppa_addr *ppa)
{
	struct pblk *pblk = line->pblk;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_map *map = line->map;
	struct ppa_addr map_ppa = *ppa;
	int done = 0;
	u64 paddr;
	int pos;

	pos = pblk_ppa_to_pos(geo, *ppa);
	set_bit(pos, map->w_err_bitmap);

	while (!done)  {
		paddr = pblk_dev_ppa_to_line_addr(pblk, map_ppa);

		if (!test_and_set_bit(paddr, map->bitmap))
			map->left_msecs--;

		done = nvm_next_ppa_in_chk(pblk->dev, &map_ppa);
	}

}

void pblk_dealloc_page(struct pblk *pblk, struct pblk_line *line, int nr_secs)
{
	struct pblk_line_map *map = line->map;
	u64 addr;
	int i;

	spin_lock(&line->lock);
	addr = find_next_zero_bit(map->bitmap,
					pblk->lm.sec_per_line, map->cur_sec);
	map->cur_sec = addr - nr_secs;

	for (i = 0; i < nr_secs; i++, map->cur_sec--)
		WARN_ON(!test_and_clear_bit(map->cur_sec, map->bitmap));
	spin_unlock(&line->lock);
}

u64 __pblk_alloc_page(struct pblk *pblk, struct pblk_line *line, int nr_secs)
{
	struct pblk_line_map *map = line->map;
	u64 addr;
	int i;

	lockdep_assert_held(&line->lock);

	/* logic error: ppa out-of-bounds. Prevent generating bad address */
	if (map->cur_sec + nr_secs > pblk->lm.sec_per_line) {
		WARN(1, "pblk: page allocation out of bounds\n");
		nr_secs = pblk->lm.sec_per_line - map->cur_sec;
	}

	map->cur_sec = addr = find_next_zero_bit(map->bitmap,
					pblk->lm.sec_per_line, map->cur_sec);
	for (i = 0; i < nr_secs; i++, map->cur_sec++)
		WARN_ON(test_and_set_bit(map->cur_sec, map->bitmap));

	return addr;
}

u64 pblk_alloc_page(struct pblk *pblk, struct pblk_line *line, int nr_secs)
{
	u64 addr;

	/* Lock needed in case a write fails and a recovery needs to remap
	 * failed write buffer entries
	 */
	spin_lock(&line->lock);
	addr = __pblk_alloc_page(pblk, line, nr_secs);
	line->map->left_msecs -= nr_secs;
	WARN(line->map->left_msecs < 0, "pblk: page allocation out of bounds\n");
	spin_unlock(&line->lock);

	return addr;
}


u64 pblk_lookup_page(struct pblk *pblk, struct pblk_line *line)
{
	struct pblk_line_map *map = line->map;
	u64 paddr;

	spin_lock(&line->lock);
	paddr = find_next_zero_bit(map->bitmap,
					pblk->lm.sec_per_line, map->cur_sec);
	spin_unlock(&line->lock);

	return paddr;
}

static void pblk_alloc_next_lun(struct pblk *pblk, struct pblk_line_map *map)
{
	struct pblk_line_meta *lm = &pblk->lm;
	unsigned int stripe_unit = pblk->min_write_pgs;

	map->cur_lun++;
	if (map->cur_lun == lm->blk_per_line) {
		map->cur_stripe_off += stripe_unit;
		map->cur_lun = 0;
	}
}

static int pblk_alloc_cur_lun_has_w_err(struct pblk_line_map *map)
{
	return map->w_err_bitmap && test_bit(map->cur_lun, map->w_err_bitmap);
}

static void pblk_alloc(struct pblk_line *line, struct ppa_addr *ppa)
{
	struct pblk_line_map *map = line->map;
	struct pblk *pblk = line->pblk;
	unsigned int stripe_unit = pblk->min_write_pgs;

	ppa->ppa = map->cur_ppa.ppa;

	map->cur_sec += stripe_unit;
	pblk_alloc_next_lun(pblk, map);

	while (test_bit(map->cur_lun, line->blk_bitmap) ||
			pblk_alloc_cur_lun_has_w_err(map)) {

		map->cur_sec += stripe_unit;
		pblk_alloc_next_lun(pblk, map);
	}

	map->cur_ppa.a.ch = pblk->luns[map->cur_lun].bppa.a.ch;
	map->cur_ppa.a.lun = pblk->luns[map->cur_lun].bppa.a.lun;

	pblk_set_dev_chunk_addr(pblk, &map->cur_ppa,
			map->cur_stripe_off);
}

u64 pblk_map_alloc_ppas(struct pblk *pblk, struct pblk_line *line,
			      int nr_secs, struct ppa_addr *start_ppa)
{
	struct pblk_line_map *map = line->map;
	u64 paddr;
	int i;

	if (pblk->min_write_pgs != nr_secs) {
		WARN(1, "pblk: unaligned allocation\n");
		return 0;
	}

	spin_lock(&line->lock);
	paddr = map->cur_sec;
	pblk_alloc(line, start_ppa);

	for (i = 0; i < nr_secs; i++)
		WARN_ON(test_and_set_bit(paddr+i, line->map->bitmap));

	line->map->left_msecs -= nr_secs;
	spin_unlock(&line->lock);

	return paddr;
}

static int pblk_map_page_data(struct pblk *pblk, unsigned int sentry,
			      struct ppa_addr *ppa_list,
			      unsigned long *lun_bitmap,
			      void *meta_list,
			      unsigned int valid_secs)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	struct pblk_emeta *emeta;
	struct pblk_w_ctx *w_ctx;
	__le64 *lba_list;
	u64 paddr;
	struct ppa_addr ppa;
	int nr_secs = pblk->min_write_pgs;
	int i;

	if (!line)
		return -ENOSPC;

	if (pblk_line_is_full(line)) {
		struct pblk_line *prev_line = line;

		/* If we cannot allocate a new line, make sure to store metadata
		 * on current line and then fail
		 */
		line = pblk_line_replace_data(pblk);
		pblk_line_close_meta(pblk, prev_line);

		if (!line) {
			pblk_pipeline_stop(pblk);
			return -ENOSPC;
		}

	}

	emeta = line->emeta;
	lba_list = emeta_to_lbas(pblk, emeta->buf);

	paddr = pblk_map_alloc_ppas(pblk, line, nr_secs, &ppa);

	for (i = 0; i < nr_secs; i++, paddr++) {
		struct pblk_sec_meta *meta = pblk_get_meta(pblk, meta_list, i);
		__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and a single writer thread have access to each specific entry
		 * at a time. Thus, it is safe to modify the context for the
		 * entry we are setting up for submission without taking any
		 * lock or memory barrier.
		 */
		if (i < valid_secs) {
			kref_get(&line->ref);
			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->ppa = ppa;
			meta->lba = cpu_to_le64(w_ctx->lba);
			lba_list[paddr] = cpu_to_le64(w_ctx->lba);
			if (lba_list[paddr] != addr_empty)
				line->nr_valid_lbas++;
			else
				atomic64_inc(&pblk->pad_wa);
		} else {
			lba_list[paddr] = addr_empty;
			meta->lba = addr_empty;
			__pblk_map_invalidate(pblk, line, paddr);
		}

		ppa_list[i] = ppa;
		nvm_next_ppa_in_chk(pblk->dev, &ppa);
	}

	pblk_down_rq(pblk, ppa_list[0], lun_bitmap);
	return 0;
}

int pblk_map_rq(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
		 unsigned long *lun_bitmap, unsigned int valid_secs,
		 unsigned int off)
{
	void *meta_list = pblk_get_meta_for_writes(pblk, rqd);
	void *meta_buffer;
	struct ppa_addr *ppa_list = nvm_rq_to_ppa_list(rqd);
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int i;
	int ret;

	for (i = off; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		meta_buffer = pblk_get_meta(pblk, meta_list, i);

		ret = pblk_map_page_data(pblk, sentry + i, &ppa_list[i],
					lun_bitmap, meta_buffer, map_secs);
		if (ret)
			return ret;
	}

	return 0;
}

/* only if erase_ppa is set, acquire erase semaphore */
int pblk_map_erase_rq(struct pblk *pblk, struct nvm_rq *rqd,
		       unsigned int sentry, unsigned long *lun_bitmap,
		       unsigned int valid_secs, struct ppa_addr *erase_ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	void *meta_list = pblk_get_meta_for_writes(pblk, rqd);
	void *meta_buffer;
	struct ppa_addr *ppa_list = nvm_rq_to_ppa_list(rqd);
	struct pblk_line *e_line, *d_line;
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int i, erase_lun;
	int ret;


	for (i = 0; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		meta_buffer = pblk_get_meta(pblk, meta_list, i);

		ret = pblk_map_page_data(pblk, sentry + i, &ppa_list[i],
					lun_bitmap, meta_buffer, map_secs);
		if (ret)
			return ret;

		erase_lun = pblk_ppa_to_pos(geo, ppa_list[i]);

		/* line can change after page map. We might also be writing the
		 * last line.
		 */
		e_line = pblk_line_get_erase(pblk);
		if (!e_line)
			return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
							valid_secs, i + min);

		spin_lock(&e_line->lock);
		if (!test_bit(erase_lun, e_line->erase_bitmap)) {
			set_bit(erase_lun, e_line->erase_bitmap);
			atomic_dec(&e_line->left_eblks);

			*erase_ppa = ppa_list[i];
			erase_ppa->a.blk = e_line->id;

			spin_unlock(&e_line->lock);

			/* Avoid evaluating e_line->left_eblks */
			return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
							valid_secs, i + min);
		}
		spin_unlock(&e_line->lock);
	}

	d_line = pblk_line_get_data(pblk);

	/* line can change after page map. We might also be writing the
	 * last line.
	 */
	e_line = pblk_line_get_erase(pblk);
	if (!e_line)
		return -ENOSPC;

	/* Erase blocks that are bad in this line but might not be in next */
	if (unlikely(pblk_ppa_empty(*erase_ppa)) &&
			bitmap_weight(d_line->blk_bitmap, lm->blk_per_line)) {
		int bit = -1;

retry:
		bit = find_next_bit(d_line->blk_bitmap,
						lm->blk_per_line, bit + 1);
		if (bit >= lm->blk_per_line)
			return 0;

		spin_lock(&e_line->lock);
		if (test_bit(bit, e_line->erase_bitmap)) {
			spin_unlock(&e_line->lock);
			goto retry;
		}
		spin_unlock(&e_line->lock);

		set_bit(bit, e_line->erase_bitmap);
		atomic_dec(&e_line->left_eblks);
		*erase_ppa = pblk->luns[bit].bppa; /* set ch and lun */
		erase_ppa->a.blk = e_line->id;
	}

	return 0;
}
