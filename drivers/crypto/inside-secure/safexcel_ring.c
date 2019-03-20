// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017 Marvell
 *
 * Antoine Tenart <antoine.tenart@free-electrons.com>
 */

#include <linux/dma-mapping.h>
#include <linux/spinlock.h>

#include "safexcel.h"

int safexcel_init_ring_descriptors(struct safexcel_crypto_priv *priv,
				   struct safexcel_desc_ring *cdr,
				   struct safexcel_desc_ring *rdr)
{
	cdr->base = dmam_alloc_coherent(priv->dev,
					priv->config.cd_offset *
					priv->config.ring_entries,
					&cdr->base_dma,
					GFP_KERNEL | __GFP_ZERO);
	if (!cdr->base)
		return -ENOMEM;
	cdr->write = cdr->base;
	cdr->base_end = cdr->base +
			(priv->config.cd_offset *
			 (priv->config.ring_entries - 1));
	cdr->read = cdr->base;

	rdr->base = dmam_alloc_coherent(priv->dev,
					(priv->config.rd_offset *
					 priv->config.ring_entries),
					 &rdr->base_dma,
					 GFP_KERNEL | __GFP_ZERO);
	if (!rdr->base)
		return -ENOMEM;
	rdr->write = rdr->base;
	rdr->base_end = rdr->base +
			(priv->config.rd_offset *
			 (priv->config.ring_entries - 1));
	rdr->read = rdr->base;

	return 0;
}

int safexcel_select_ring(struct safexcel_crypto_priv *priv)
{
	/* TBD: do load balancing based on ring fill level ... */
	return (atomic_inc_return(&priv->ring_used) % priv->config.rings);
}

static void *safexcel_cdr_next_wptr(struct safexcel_crypto_priv *priv,
				     struct safexcel_desc_ring *ring)
{
	void *ptr = ring->write;

	if (unlikely((ring->write == (ring->read - priv->config.cd_offset)) ||
		     ((ring->read == ring->base) &&
		      (ring->write == ring->base_end))))
		return ERR_PTR(-ENOMEM);

	/* Move to next desc in ring, wrapping as required */
	if (unlikely(ring->write == ring->base_end))
		ring->write = ring->base;
	else
		ring->write += priv->config.cd_offset;

	return ptr;
}

static void *safexcel_rdr_next_wptr(struct safexcel_crypto_priv *priv,
				     struct safexcel_desc_ring *ring)
{
	void *ptr = ring->write;

	if (unlikely((ring->write == (ring->read - priv->config.rd_offset)) ||
		     ((ring->read == ring->base) &&
		      (ring->write == ring->base_end))))
		return ERR_PTR(-ENOMEM);

	/* Move to next desc in ring, wrapping as required */
	if (unlikely(ring->write == ring->base_end))
		ring->write = ring->base;
	else
		ring->write += priv->config.rd_offset;

	return ptr;
}

void *safexcel_cdr_next_rptr(struct safexcel_crypto_priv *priv,
			     struct safexcel_desc_ring *ring)
{
	void *ptr = ring->read;

	/* Move to next desc in ring, wrapping as required */
	if (unlikely(ring->read == ring->base_end))
		ring->read = ring->base;
	else
		ring->read += priv->config.cd_offset;

	return ptr;
}

void *safexcel_rdr_next_rptr(struct safexcel_crypto_priv *priv,
			     struct safexcel_desc_ring *ring,
			     void **read)
{
	void *ptr = *read;

	/*
	 * If we have ownership words enabled, then use them to verify
	 * the hardware indeed wrote this result descriptor in full and,
	 * if not, wait a little while for this to happen.
	 */
	if (EIP197_RD_OWN_WORD) {
		int cnt;
		u32 *own = ptr + priv->config.own_offset;

		cnt = EIP197_OWN_POLL_COUNT;
		while ((--cnt) && (*own != EIP197_OWNERSHIP_MAGIC))
			cpu_relax();

		/* If polling failed then return a no entry error */
		if (unlikely(!cnt))
			return ERR_PTR(-ENOENT);

		/* Clear the ownership word to avoid biting our tail later! */
		*own = ~EIP197_OWNERSHIP_MAGIC;
	}

	/* Move to next desc in ring, wrapping as required */
	if (unlikely(ptr == ring->base_end))
		*read = ring->base;
	else
		*read += priv->config.rd_offset;

	return ptr;
}

/* Verify if next full packet is available already, using ownership words */
bool safexcel_rdr_scan_next(struct safexcel_crypto_priv *priv,
			    struct safexcel_desc_ring *ring)
{
	struct safexcel_result_desc *rdesc;
	u32 *own;

	rdesc = ring->read;
	own = (void *)rdesc + priv->config.own_offset;
	while (*own == EIP197_OWNERSHIP_MAGIC) {
		if (rdesc->last_seg)
			return true; /* Full packet found */

		/* Move to next desc in ring, wrapping as required */
		if (unlikely((void *)rdesc == ring->base_end)) {
			rdesc = ring->base;
			own   = ring->base + priv->config.own_offset;
		} else {
			rdesc = (void *)own + 4;
			own   = (void *)own + priv->config.rd_offset;
		}
	}
	return false; /* Full packet NOT found */
}

inline void *safexcel_ring_curr_rptr(struct safexcel_crypto_priv *priv,
				     int ring)
{
	struct safexcel_desc_ring *rdr = &priv->ring[ring].rdr;

	return rdr->read;
}

int safexcel_ring_first_rdr_index(struct safexcel_crypto_priv *priv,
				  int ring)
{
	struct safexcel_desc_ring *rdr = &priv->ring[ring].rdr;

	return (rdr->read - rdr->base) / priv->config.rd_offset;
}

int safexcel_ring_rdr_rdesc_index(struct safexcel_crypto_priv *priv,
				  int ring,
				  struct safexcel_result_desc *rdesc)
{
	struct safexcel_desc_ring *rdr = &priv->ring[ring].rdr;

	return ((void *)rdesc - rdr->base) / priv->config.rd_offset;
}

void safexcel_cdr_rollback_wptr(struct safexcel_crypto_priv *priv,
				struct safexcel_desc_ring *ring)
{
	if (ring->write == ring->read)
		return;

	if (unlikely(ring->write == ring->base))
		ring->write = ring->base_end;
	else
		ring->write -= priv->config.cd_offset;
}

void safexcel_rdr_rollback_wptr(struct safexcel_crypto_priv *priv,
				struct safexcel_desc_ring *ring)
{
	if (ring->write == ring->read)
		return;

	if (unlikely(ring->write == ring->base))
		ring->write = ring->base_end;
	else
		ring->write -= priv->config.rd_offset;
}

struct safexcel_command_desc *safexcel_add_cdesc(struct safexcel_crypto_priv *priv,
						 int ring_id,
						 bool first, bool last,
						 dma_addr_t data, u32 data_len,
						 u32 full_data_len,
						 dma_addr_t context) {
	struct safexcel_command_desc *cdesc;
	int i;

	cdesc = safexcel_cdr_next_wptr(priv, &priv->ring[ring_id].cdr);
	if (IS_ERR(cdesc))
		return cdesc;

	memset(cdesc, 0, sizeof(struct safexcel_command_desc));

	cdesc->first_seg = first;
	cdesc->last_seg = last;
	cdesc->particle_size = data_len;
	cdesc->data_lo = lower_32_bits(data);
	cdesc->data_hi = upper_32_bits(data);

	if (first && context) {
		struct safexcel_token *token =
			(struct safexcel_token *)cdesc->control_data.token;

		cdesc->control_data.packet_length = full_data_len;
		cdesc->control_data.options = EIP197_OPTION_MAGIC_VALUE |
					      EIP197_OPTION_64BIT_CTX |
					      EIP197_OPTION_CTX_CTRL_IN_CMD;
		cdesc->control_data.context_lo =
			(lower_32_bits(context) & GENMASK(31, 2)) >> 2;
		cdesc->control_data.context_hi = upper_32_bits(context);

		/* TODO: HMAC with SHA-384/512 uses large xform records*/
		cdesc->control_data.ptrtype = EIP197_PTRTYPE_XFORM_SMALL;

		for (i = 0; i < EIP197_MAX_TOKENS; i++)
			eip197_noop_token(&token[i]);
	}

	return cdesc;
}

struct safexcel_result_desc *safexcel_add_rdesc(struct safexcel_crypto_priv *priv,
						int ring_id,
						bool first, bool last,
						dma_addr_t data, u32 len)
{
	struct safexcel_result_desc *rdesc;

	rdesc = safexcel_rdr_next_wptr(priv, &priv->ring[ring_id].rdr);
	if (IS_ERR(rdesc))
		return rdesc;

	memset(rdesc, 0, sizeof(struct safexcel_result_desc));

	rdesc->first_seg = first;
	rdesc->last_seg = last;
	rdesc->particle_size = len;
	rdesc->data_lo = lower_32_bits(data);
	rdesc->data_hi = upper_32_bits(data);

	return rdesc;
}
