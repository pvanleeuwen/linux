// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017 Marvell
 *
 * Antoine Tenart <antoine.tenart@free-electrons.com>
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

#include <crypto/internal/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/skcipher.h>

#include "safexcel.h"

static u32 max_rings = 255; // Use HW max by default
module_param(max_rings, uint, 0644);
MODULE_PARM_DESC(max_rings, "Maximum number of rings to use, default 1. Use more rings to spread the load over multiple CPUs.");
static u32 ring_entries; // default=0=autoconfig
module_param(ring_entries, uint, 0644);
MODULE_PARM_DESC(ring_entries, "Number of entries per ring. 0(default)=auto-configure.");
static u32 queue_entries; // default=0=autoconfig
module_param(queue_entries, uint, 0644);
MODULE_PARM_DESC(queue_entries, "Number of entries per workqueue. 0(default)=auto-configure.");
/*
 * 2log of AXI burst size, platform dependent, 1-4 for AXI3, 1-8 for AXI4
 * Some platforms may require a lower value due to resource restrictions
 * Some platforms may support higher values (i.e. AXI4)
 * But in most cases 4 (16 beats) just works and is close to optimal.
 * i.e. only mess with this if instructed to do so by the device vendor!
 */
static u32 burst_size = 4;
module_param(burst_size, uint, 0644);
MODULE_PARM_DESC(burst_size, "2log of AXI burst size to use (1-8, 4 is default).");

static void eip197_trc_cache_init(struct safexcel_crypto_priv *priv)
{
	u32 val, htable_offset;
	int i, cs_rc_max, cs_ht_wc, cs_ht_sz;
	int maxbanks, actbank, curbank, lrgrecsz;
	u32 addrhi, addrlo, addrmid, dsize, asize;

	/*
	 *Enable the record cache memory access and
	 * probe the bank select width
	 */
	val = readl(priv->base + EIP197_CS_RAM_CTRL);
	val &= ~EIP197_TRC_ENABLE_MASK;
	val |= EIP197_TRC_ENABLE_0 | EIP197_CS_BANKSEL_MASK;
	writel(val, priv->base + EIP197_CS_RAM_CTRL);
	val = readl(priv->base + EIP197_CS_RAM_CTRL);
	maxbanks = ((val&EIP197_CS_BANKSEL_MASK)>>EIP197_CS_BANKSEL_OFS)+1;

	/* Clear all ECC errors */
	writel(0, priv->base + EIP197_TRC_ECCCTRL);

	/*
	 * Make sure the cache memory is accessible by taking record cache into
	 * reset. Need data memory access here, not admin access.
	 */
	val = readl(priv->base + EIP197_TRC_PARAMS);
	val |= EIP197_TRC_PARAMS_SW_RESET|EIP197_TRC_PARAMS_DATA_ACCESS;
	writel(val, priv->base + EIP197_TRC_PARAMS);

	/*
	 * And probe the actual size of the physically attached cache data RAM
	 * Using a binary subdivision algorithm downto 32 byte cache lines.
	 */
	addrhi = 1<<(16+maxbanks);
	addrlo = 0;
	actbank = maxbanks - 1;
	while ((addrhi-addrlo) > 32) {
		/* write marker to lowest address in top half */
		addrmid = (addrhi+addrlo)>>1;
		curbank = addrmid>>16;
		if (curbank != actbank) {
			val = readl(priv->base + EIP197_CS_RAM_CTRL);
			val = (val & ~EIP197_CS_BANKSEL_MASK) |
			      (curbank<<EIP197_CS_BANKSEL_OFS);
			writel(val, priv->base + EIP197_CS_RAM_CTRL);
			actbank = curbank;
		}
		writel((addrmid|(addrlo<<16)) & 0xffffffff,
			priv->base + EIP197_CLASSIFICATION_RAMS +
			(addrmid & 0xffff));

		/* write marker to lowest address in bottom half */
		curbank  = addrlo>>16;
		if (curbank != actbank) {
			val = readl(priv->base + EIP197_CS_RAM_CTRL);
			val = (val & ~EIP197_CS_BANKSEL_MASK) |
			      (curbank<<EIP197_CS_BANKSEL_OFS);
			writel(val, priv->base + EIP197_CS_RAM_CTRL);
			actbank = curbank;
		}
		writel((addrlo|(addrhi<<16)) & 0xffffffff,
			priv->base + EIP197_CLASSIFICATION_RAMS +
			(addrlo & 0xffff));

		/* read back marker from top half */
		curbank = addrmid>>16;
		if (curbank != actbank) {
			val = readl(priv->base + EIP197_CS_RAM_CTRL);
			val = (val & ~EIP197_CS_BANKSEL_MASK) |
			      (curbank<<EIP197_CS_BANKSEL_OFS);
			writel(val, priv->base + EIP197_CS_RAM_CTRL);
			actbank = curbank;
		}
		val = readl(priv->base + EIP197_CLASSIFICATION_RAMS +
			    (addrmid & 0xffff));

		if (val == ((addrmid|(addrlo<<16)) & 0xffffffff)) {
			/* read back correct, continue with top half */
			addrlo = addrmid;
		} else {
			/* not read back correct, continue with bottom half */
			addrhi = addrmid;
		}
	}
	dsize = addrhi; // probed data RAM size in bytes

	dev_info(priv->dev,
		"Probed %d bytes of transform record cache data RAM\n", dsize);

	/*
	 * Now probe the administration RAM size pretty much the same way
	 * Except that only the lower 30 bits are writable and we don't need
	 * bank selects
	 */
	val = readl(priv->base + EIP197_TRC_PARAMS);
	/* admin access now */
	val &= ~(EIP197_TRC_PARAMS_DATA_ACCESS|EIP197_CS_BANKSEL_MASK);
	writel(val, priv->base + EIP197_TRC_PARAMS);

	addrhi = 65536;
	addrlo = 0;
	while ((addrhi-addrlo) > 32) {
		/* write marker to lowest address in top half */
		addrmid = (addrhi+addrlo)>>1;
		writel((addrmid|(addrlo<<16)) & 0xbfffffff,
		       priv->base + EIP197_CLASSIFICATION_RAMS +
		       (addrmid & 0xffff));

		/* write marker to lowest address in bottom half */
		writel((addrlo|(addrhi<<16)) & 0xbfffffff,
			priv->base + EIP197_CLASSIFICATION_RAMS +
			(addrlo & 0xffff));

		/* read back marker from top half */
		val = readl(priv->base + EIP197_CLASSIFICATION_RAMS +
			    (addrmid & 0xffff));

		if (val == ((addrmid|(addrlo<<16)) & 0xbfffffff)) {
			/* read back correct, continue with top half */
			addrlo = addrmid;
		} else {
			/* not read back correct, continue with bottom half */
			addrhi = addrmid;
		}
	}
	asize = addrhi>>4; // probed admin RAM size in admin words

	dev_info(priv->dev,
		"Probed %d words of transform record cache admin RAM\n", asize);

	/*
	 * Determine optimal configuration from RAM sizes
	 * Note that we assume that the physical RAM configuration is sane
	 * Therefore, we don't do any parameter error checking here ...
	 */

	/* Only really need the large records if we support SHA2-512 */
	if (priv->algo_flags & ALGO_SHA2_512)
		lrgrecsz = EIP197_CS_TRC_LG_REC_WC;
	else
		lrgrecsz = EIP197_CS_TRC_REC_WC;
	/*
	 * Step #1: How many records will physically fit?
	 * Hard upper limit is 1023!
	 */
	cs_rc_max = min((int) ((dsize>>2) / lrgrecsz), 1023);
	/* Step #2: Need at least 2 words in the admin RAM per record */
	cs_rc_max = min(cs_rc_max, (int) (asize>>1));
	/* Step #3: Determine log2 of hash table size */
	cs_ht_sz = __fls(asize - cs_rc_max) - 2;
	cs_ht_wc = 16<<cs_ht_sz; // dwords, not admin words

	dev_info(priv->dev,
		"Initializing cache for %d records with %d hash table entries (%d/record)\n",
		cs_rc_max, cs_ht_wc+cs_ht_wc, ((cs_ht_wc+cs_ht_wc)/cs_rc_max));

	/* Clear all records in administration RAM */
	for (i = 0; i < cs_rc_max; i++) {
		u32 val;
		u32 offset = EIP197_CLASSIFICATION_RAMS + i * EIP197_CS_RC_SIZE;

		writel(EIP197_CS_RC_NEXT(EIP197_RC_NULL) |
		       EIP197_CS_RC_PREV(EIP197_RC_NULL),
		       priv->base + offset);

		val = EIP197_CS_RC_NEXT(i+1) | EIP197_CS_RC_PREV(i-1);
		if (i == 0)
			val |= EIP197_CS_RC_PREV(EIP197_RC_NULL);
		else if (i == cs_rc_max - 1)
			val |= EIP197_CS_RC_NEXT(EIP197_RC_NULL);
		writel(val, priv->base + offset + sizeof(u32));
	}

	/* Clear the hash table entries */
	htable_offset = cs_rc_max * EIP197_CS_RC_SIZE;
	for (i = 0; i < cs_ht_wc; i++)
		writel(GENMASK(29, 0),
		       priv->base + EIP197_CLASSIFICATION_RAMS +
		       htable_offset + i * sizeof(u32));

	/* Disable the record cache memory access */
	val = readl(priv->base + EIP197_CS_RAM_CTRL);
	val &= ~EIP197_TRC_ENABLE_MASK;
	writel(val, priv->base + EIP197_CS_RAM_CTRL);

	/* Write head and tail pointers of the record free chain */
	val = EIP197_TRC_FREECHAIN_HEAD_PTR(0) |
	      EIP197_TRC_FREECHAIN_TAIL_PTR(cs_rc_max - 1);
	writel(val, priv->base + EIP197_TRC_FREECHAIN);

	/* Configure the record cache #1 */
	val = EIP197_TRC_PARAMS2_RC_SZ_SMALL(EIP197_CS_TRC_REC_WC) |
	      EIP197_TRC_PARAMS2_HTABLE_PTR(cs_rc_max);
	writel(val, priv->base + EIP197_TRC_PARAMS2);

	/* Configure the record cache #2 */
	val = EIP197_TRC_PARAMS_RC_SZ_LARGE(lrgrecsz) |
	      EIP197_TRC_PARAMS_BLK_TIMER_SPEED(1) |
	      EIP197_TRC_PARAMS_HTABLE_SZ(cs_ht_sz);
	writel(val, priv->base + EIP197_TRC_PARAMS);
}

static void eip197_init_firmware(struct safexcel_crypto_priv *priv,
				 int numfw)
{
	int pe;
	u32 val;

	for (pe = 0; pe < priv->config.pes; pe++) {
		/* Configure the token FIFO's */
		writel(3, EIP197_PE(priv) + EIP197_PE_ICE_PUTF_CTRL(pe));
		writel(0, EIP197_PE(priv) + EIP197_PE_ICE_PPTF_CTRL(pe));

		/* Clear the ICE scratchpad memory */
		val = readl(EIP197_PE(priv) + EIP197_PE_ICE_SCRATCH_CTRL(pe));
		val |= EIP197_PE_ICE_SCRATCH_CTRL_CHANGE_TIMER |
		       EIP197_PE_ICE_SCRATCH_CTRL_TIMER_EN |
		       EIP197_PE_ICE_SCRATCH_CTRL_SCRATCH_ACCESS |
		       EIP197_PE_ICE_SCRATCH_CTRL_CHANGE_ACCESS;
		writel(val, EIP197_PE(priv) + EIP197_PE_ICE_SCRATCH_CTRL(pe));

		memset_io(EIP197_PE(priv) + EIP197_PE_ICE_SCRATCH_RAM(pe), 0,
			  EIP197_NUM_OF_SCRATCH_BLOCKS * sizeof(u32));

		/* Reset the IFPP engine to make its program mem accessible */
		writel(EIP197_PE_ICE_x_CTRL_SW_RESET |
		       EIP197_PE_ICE_x_CTRL_CLR_ECC_CORR |
		       EIP197_PE_ICE_x_CTRL_CLR_ECC_NON_CORR,
		       EIP197_PE(priv) + EIP197_PE_ICE_FPP_CTRL(pe));

		/* Reset the IPUE engine to make its program mem accessible */
		writel(EIP197_PE_ICE_x_CTRL_SW_RESET |
		       EIP197_PE_ICE_x_CTRL_CLR_ECC_CORR |
		       EIP197_PE_ICE_x_CTRL_CLR_ECC_NON_CORR,
		       EIP197_PE(priv) + EIP197_PE_ICE_PUE_CTRL(pe));

		if (numfw == 4) {
			/* Clear the OCE scratchpad memory */
			val = readl(EIP197_PE(priv) +
				    EIP197_PE_OCE_SCRATCH_CTRL(pe));
			val |= EIP197_PE_ICE_SCRATCH_CTRL_CHANGE_TIMER |
			       EIP197_PE_ICE_SCRATCH_CTRL_TIMER_EN |
			       EIP197_PE_ICE_SCRATCH_CTRL_SCRATCH_ACCESS |
			       EIP197_PE_ICE_SCRATCH_CTRL_CHANGE_ACCESS;
			writel(val,
			       EIP197_PE(priv) +
			       EIP197_PE_OCE_SCRATCH_CTRL(pe));

			memset_io(EIP197_PE(priv) +
				  EIP197_PE_OCE_SCRATCH_RAM(pe), 0,
				  EIP197_NUM_OF_SCRATCH_BLOCKS * sizeof(u32));

			/* Reset the OFPP to make its program mem accessible */
			writel(EIP197_PE_ICE_x_CTRL_SW_RESET |
			       EIP197_PE_ICE_x_CTRL_CLR_ECC_CORR |
			       EIP197_PE_ICE_x_CTRL_CLR_ECC_NON_CORR,
			       EIP197_PE(priv) + EIP197_PE_OCE_FPP_CTRL(pe));

			/* Reset the OPUE to make its program mem accessible */
			writel(EIP197_PE_ICE_x_CTRL_SW_RESET |
			       EIP197_PE_ICE_x_CTRL_CLR_ECC_CORR |
			       EIP197_PE_ICE_x_CTRL_CLR_ECC_NON_CORR,
			       EIP197_PE(priv) + EIP197_PE_OCE_PUE_CTRL(pe));
		}

		/* Enable access to all IFPP program memories */
		writel(EIP197_PE_ICE_RAM_CTRL_FPP_PROG_EN,
		       EIP197_PE(priv) + EIP197_PE_ICE_RAM_CTRL(pe));
	}

}

/*
 * If FW is actual production firmware, then poll for its initialization
 * to complete and check if it is good for the HW, otherwise just return OK.
 */
static bool poll_fw_ready(struct safexcel_crypto_priv *priv,
			  int prodfw, int oce, int fpp,
			  u32 *fwver, u32 *hwrel, u32 *hwminmax)
{
	int pe, pollcnt;
	u32 base, pollofs, fwverofs, hwverofs;

	if (fpp) {
		pollofs  = EIP197_FW_FPP_READY;
		fwverofs = EIP197_FW_FPP_FWVER;
		hwverofs = EIP197_FW_FPP_HWVER_REL;
	} else {
		pollofs  = EIP197_FW_PUE_READY;
		fwverofs = EIP197_FW_PUE_FWVER;
		hwverofs = EIP197_FW_PUE_HWVER_REL;
	}

	if (prodfw) {
		for (pe = 0; pe < priv->config.pes; pe++) {
			if (oce)
				base = EIP197_PE_OCE_SCRATCH_RAM(pe);
			else
				base = EIP197_PE_ICE_SCRATCH_RAM(pe);
			pollcnt = EIP197_FW_START_POLLCNT;
			while (pollcnt &&
			       (readl(EIP197_PE(priv) + base +
				      pollofs) != 1)) {
				pollcnt--;
				cpu_relax();
			}
			if (!pollcnt) {
				dev_err(priv->dev, "IPUE FW for PE %d failed to start.\n",
				pe);
				return false;
			}
		}
	}
	/* FW initialization done, extract FW info */
	*fwver = readl(EIP197_PE(priv) + base + fwverofs);
	if (*fwver >= 0x300) {
		/* For FW version 3.0 and above only */
		*hwrel    = readl(EIP197_PE(priv) + base + hwverofs);
		*hwminmax = readl(EIP197_PE(priv) + base + hwverofs + 4);
	} else {
		*hwrel    = 0;
		*hwminmax = 0;
	}
	return true;
}

static bool eip197_start_firmware(struct safexcel_crypto_priv *priv, int numfw,
				  int ipuesz, int ifppsz,
				  int opuesz, int ofppsz)
{
	int pe;
	u32 val, ipbsize, topver;
	u32 ipfwver, iffwver, opfwver, offwver;
	u32 iphwrver, ifhwrver, ophwrver, ofhwrver;
	u32 iphwmmver, ifhwmmver, ophwmmver, ofhwmmver;

	for (pe = 0; pe < priv->config.pes; pe++) {
		/* Disable all program memory access */
		writel(0, EIP197_PE(priv) + EIP197_PE_ICE_RAM_CTRL(pe));

		if (priv->feat_flags & EIP197_OCE) {
			/* Start OFPP microengines */
			val = ((ofppsz - 1) & 0x7ff0) << 16;
			if (ofppsz)
				val |= BIT(3); /* Run FW init */
			writel(val,
			       EIP197_PE(priv) + EIP197_PE_OCE_FPP_CTRL(pe));

			/* Start OPUE microengines */
			val = ((opuesz - 1) & 0x7ff0) << 16;
			if (opuesz)
				val |= BIT(3); /* Run FW init */
			writel(val,
			       EIP197_PE(priv) + EIP197_PE_OCE_PUE_CTRL(pe));
		}

		/* Start IFPP microengines */
		val = ((ifppsz - 1) & 0x7ff0) << 16;
		if (ifppsz)
			val |= BIT(3); /* Run FW init */
		writel(val, EIP197_PE(priv) + EIP197_PE_ICE_FPP_CTRL(pe));

		/* Start IPUE microengines */
		val = ((ipuesz - 1) & 0x7ff0) << 16;
		if (ipuesz)
			val |= BIT(3); /* Run FW init */
		writel(val, EIP197_PE(priv) + EIP197_PE_ICE_PUE_CTRL(pe));
	}

	/* For miniFW startup, there is no initialization, so always succeed */
	if ((!ipuesz) && (!ifppsz) && (!opuesz) && (!ofppsz))
		return true;

	/* Wait until all the firmwares have properly started up */
	if (priv->feat_flags & EIP197_OCE) {
		if (!poll_fw_ready(priv, ofppsz, 1, 1, &offwver,
				   &ofhwrver, &ofhwmmver))
			return false;
		if (!poll_fw_ready(priv, opuesz, 1, 0, &opfwver,
				   &ophwrver, &ophwmmver))
			return false;
		dev_info(priv->dev, "OPUE FW version %d.%d.%d(%d) for HW %d.%d.%d(%d, min %d.%d.%d max %d.%d.%d)\n",
			 ((opfwver>>8)&0xf), ((opfwver>>4)&0xf),
			 (opfwver&0xf), ((opfwver>>12)&0xf),
			 ((ophwrver>>8)&0xf), ((ophwrver>>4)&0xf),
			 (ophwrver&0xf), ((ophwrver>>12)&0xf),
			 ((ophwmmver>>8)&0xf), ((ophwmmver>>4)&0xf),
			 (ophwmmver&0xf),
			 ((ophwmmver>>24)&0xf), ((ophwmmver>>20)&0xf),
			 ((ophwmmver>>16)&0xf));
		dev_info(priv->dev, "OFPP FW version %d.%d.%d(%d) for HW %d.%d.%d(%d, min %d.%d.%d max %d.%d.%d)\n",
			 ((offwver>>8)&0xf), ((offwver>>4)&0xf),
			 (offwver&0xf), ((offwver>>12)&0xf),
			 ((ofhwrver>>8)&0xf), ((ofhwrver>>4)&0xf),
			 (ofhwrver&0xf), ((ofhwrver>>12)&0xf),
			 ((ofhwmmver>>8)&0xf), ((ofhwmmver>>4)&0xf),
			 (ofhwmmver&0xf),
			 ((ofhwmmver>>24)&0xf), ((ofhwmmver>>20)&0xf),
			 ((ofhwmmver>>16)&0xf));
		/* OCE FW set consistency check */
		if ((opfwver != offwver) || (ophwrver != ofhwrver) ||
		    (ophwmmver != ofhwmmver)) {
			dev_info(priv->dev, "OCE firmware versions do not match.\n");
			return false;
		}
	}

	if (!poll_fw_ready(priv, ifppsz, 0, 1, &iffwver,
			   &ifhwrver, &ifhwmmver))
		return false;
	if (!poll_fw_ready(priv, ipuesz, 0, 0, &ipfwver,
			   &iphwrver, &iphwmmver))
		return false;
	dev_info(priv->dev, "IPUE FW version %d.%d.%d(%d) for HW %d.%d.%d(%d, min %d.%d.%d max %d.%d.%d)\n",
		 ((ipfwver>>8)&0xf), ((ipfwver>>4)&0xf),
		 (ipfwver&0xf), ((ipfwver>>12)&0xf),
		 ((iphwrver>>8)&0xf), ((iphwrver>>4)&0xf),
		 (iphwrver&0xf), ((iphwrver>>12)&0xf),
		 ((iphwmmver>>8)&0xf), ((iphwmmver>>4)&0xf),
		 (iphwmmver&0xf),
		 ((iphwmmver>>24)&0xf), ((iphwmmver>>20)&0xf),
		 ((iphwmmver>>16)&0xf));
	dev_info(priv->dev, "IFPP FW version %d.%d.%d(%d) for HW %d.%d.%d(%d, min %d.%d.%d max %d.%d.%d)\n",
		 ((iffwver>>8)&0xf), ((iffwver>>4)&0xf),
		 (iffwver&0xf), ((iffwver>>12)&0xf),
		 ((ifhwrver>>8)&0xf), ((ifhwrver>>4)&0xf),
		 (ifhwrver&0xf), ((ifhwrver>>12)&0xf),
		 ((ifhwmmver>>8)&0xf), ((ifhwmmver>>4)&0xf),
		 (ifhwmmver&0xf),
		 ((ifhwmmver>>24)&0xf), ((ifhwmmver>>20)&0xf),
		 ((ifhwmmver>>16)&0xf));
	/* ICE FW set consistency check */
	if ((ipfwver != iffwver) || (iphwrver != ifhwrver) ||
	    (iphwmmver != ifhwmmver)) {
		dev_info(priv->dev, "ICE firmware versions do not match.\n");
		return false;
	}
	/* ICE vs OCE FW consistency check if applicable*/
	if (((ipfwver != opfwver) || (iphwrver != ophwrver) ||
	     (iphwmmver != ophwmmver)) && (priv->feat_flags & EIP197_OCE)) {
		dev_info(priv->dev, "ICE vs OCE firmware version mismatch.\n");
		return false;
	}
	priv->fwver = ipfwver & 0xfff;
	priv->fwctg = (ipfwver>>12) & 0xf;

	if (priv->fwver > 0x300) {
		/* Check if FW is supposed to run on this HW. */
		if ((priv->fwver > 0x300) && /* info not present in older FW */
		    /* min version check */
		    ((priv->hwver < (iphwmmver&0xfff)) ||
		    /* max version check */
		     (priv->hwver > ((iphwmmver>>16)&0xfff)))) {
			dev_info(priv->dev, "Firmware set is not intended for this hardware.\n");
			return false;
		}
		/* Parse HW info block for HW3.0+ */
		if (priv->hwver >= 0x300) {
			/* first check version tag presence */
			topver = readl(EIP197_PE(priv) +
				       EIP197_PE_ICE_SCRATCH_RAM(0) +
				       EIP197_FW_TOP_VERSION);
			ipbsize = readl(EIP197_PE(priv) +
					EIP197_PE_ICE_SCRATCH_RAM(0) +
					EIP197_FW_IPBSIZE);
			if ((topver & 0xffff) == EIP197_VERSION_LE) {
				if (((topver>>16)&0xfff) != priv->hwver) {
					dev_info(priv->dev, "Top version %x mismatches HW version %x.\n",
						 ((topver>>16) & 0xfff),
						 priv->hwver);
				} else if (((topver>>28) & 0xf) !=
					   priv->hwctg) {
					priv->hwctg = (topver>>28) & 0xf;
					dev_info(priv->dev, "(HW customization identifier updated to %d)\n",
						 priv->hwctg);
				}
				ipbsize &= 0xffffff;
				if ((ipbsize < priv->hwipbsize) ||
				    (ipbsize > (priv->hwipbsize<<1))) {
					dev_info(priv->dev, "Coarse (%d) vs fine (%d) input buffer size difference too large.\n",
						 priv->hwipbsize, ipbsize);
					return false;
				}
				priv->hwipbsize = ipbsize;
			} else if ((topver == 0) && (ipbsize == 0)) {
				/*
				 * Special case: possible reload/reinit
				 * HW info block only valid immediately after
				 * HW reset ...
				 * So don't give an error, just assume the
				 * ADAPT_CTRL reg was correctly written
				 * previously and also not reset since.
				 */
				dev_info(priv->dev, "Possible reinit detected, skipping IPBM config.\n");
				return true;
			} else {
				/* Anything else is just some error */
				dev_info(priv->dev, "Invalid HW info block found (read version=%x).\n",
					 (topver & 0xffff));
				return false;
			}
		}
	}

	/* Determine correct parsing depth based on FW version and buf size */
	if (priv->fwver >= 0x310)
		ipbsize = priv->hwipbsize - 2048;
	else
		ipbsize = (priv->hwipbsize * 3) >> 2;

	dev_info(priv->dev, "Packet input buffer size is %d bytes, max parsing depth set to %d.\n",
		 priv->hwipbsize, ipbsize);

	/* Program correct parsing depth threshold into the HW */
	for (pe = 0; pe < priv->config.pes; pe++) {
		writel(0xc0de0000 | ipbsize,
		       EIP197_PE(priv) + EIP197_PE_ICE_ADAPT_CTRL(pe));
	}

	return true;
}

static int eip197_write_firmware(struct safexcel_crypto_priv *priv,
				  const struct firmware *fw)
{
	const u32 *data = (const u32 *)fw->data;
	int i, nopcount;

	/* Write the firmware */
	if (priv->ctxt_flags & (MRVL_EIP197B | MRVL_EIP197D)) {
		/* Marvell Armada FW is distributed in big endian format? */
		for (i = 0; i < fw->size / sizeof(u32); i++)
			writel(be32_to_cpu(data[i]),
			       priv->base + EIP197_CLASSIFICATION_RAMS +
			       i * sizeof(u32));
		/* Scan for trailing NOPs */
		for (nopcount = 0; nopcount < i; nopcount++)
			if ((be32_to_cpu(data[i-nopcount-1]) |
			    EIP197_FW_INSTR_MASK) != EIP197_FW_INSTR_NOP)
				break;
	} else {
		/* Inside Secure distributes FW in little endian format! */
		for (i = 0; i < fw->size / sizeof(u32); i++)
			writel(data[i],
			       priv->base + EIP197_CLASSIFICATION_RAMS +
			       i * sizeof(u32));
		/* Scan for trailing NOPs */
		for (nopcount = 0; nopcount < i; nopcount++)
			if ((data[i-nopcount-1] | EIP197_FW_INSTR_MASK) !=
			    EIP197_FW_INSTR_NOP)
				break;
	}
	/*
	 * Ensure we pad with 2 NOPS in case the image did not include those
	 * (needed to ensure prefetching won't cause an ECC or parity error)
	 * Note: do NOT always pad with 2 NOPs as this may exceed the RAM size,
	 * wrap to 0 and overwrite the first words of the image ... (!!)
	 */
	if (nopcount < 2) {
		writel(EIP197_FW_INSTR_NOP,
			       priv->base + EIP197_CLASSIFICATION_RAMS +
			       i * sizeof(u32));
		if (nopcount < 1) {
			writel(EIP197_FW_INSTR_NOP,
				       priv->base + EIP197_CLASSIFICATION_RAMS +
				       (i+1) * sizeof(u32));
		}
	}

	/* Return effective image size, excluding any trailing NOPs */
	return i - nopcount;
}

static int eip197_load_firmwares(struct safexcel_crypto_priv *priv)
{
	static const char * const fw_name[] = {"ifpp.bin", "ipue.bin",
					       "ofpp.bin", "opue.bin"};
	/*
	 * The embedded one-size-fits-all MiniFW is just for handling TR
	 * prefetch & invalidate. It does not support any FW flows, effectively
	 * turning the EIP197 into a glorified EIP97
	 */
	const u32 ipue_minifw[] = {
		0x24808200, 0x2D008204, 0x2680E208, 0x2780E20C,
		0x2200F7FF, 0x38347000, 0x2300F000, 0x15200A80,
		0x01699003, 0x60038011, 0x38B57000, 0x0119F04C,
		0x01198548, 0x20E64000, 0x20E75000, 0x1E200000,
		0x30E11000, 0x103A93FF, 0x60830014, 0x5B8B0000,
		0xC0389000, 0x600B0018, 0x2300F000, 0x60800011,
		0x90800000, 0x10000000, 0x10000000};
	const u32 ifpp_minifw[] = {
		0x21008000, 0x260087FC, 0xF01CE4C0, 0x60830006,
		0x530E0000, 0x90800000, 0x23008004, 0x24808008,
		0x2580800C, 0x0D300000, 0x205577FC, 0x30D42000,
		0x20DAA7FC, 0x43107000, 0x42220004, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00060004, 0x20337004, 0x90800000, 0x10000000,
		0x10000000};
	const struct firmware *fw[FW_NB];
	char fw_path[31], *dir = NULL;
	int i, j, ret = 0, pe, numfw;
	int ipuesz, ifppsz, opuesz, ofppsz;

	if (!(priv->feat_flags & EIP197_ICE)) {
		/* No firmware is required */
		return 0;
	}

	/* Marvell Armada BW compatibility */
	if (priv->ctxt_flags & MRVL_EIP197B)
		dir = "eip197b";
	else if (priv->ctxt_flags & MRVL_EIP197D)
		dir = "eip197d";
	else
		dir = "eip197";

	if (priv->feat_flags & EIP197_OCE)
		numfw = 4;
	else
		numfw = 2;
	for (i = 0; i < numfw; i++) {
		snprintf(fw_path, 31, "inside-secure/%s/%s", dir, fw_name[i]);
		ret = firmware_request_nowarn(&fw[i], fw_path, priv->dev);
		if (ret) {
			if (!(priv->ctxt_flags & MRVL_EIP197B))
				goto release_fw;

			/* Fallback to the old firmware location for the
			 * Marvell Armada 8K (EIP197b).
			 */
			ret = firmware_request_nowarn(&fw[i], fw_name[i],
						      priv->dev);
			if (ret) {
				goto release_fw;
			}
		}
	}

download_fw:
	eip197_init_firmware(priv, numfw);

	/* Write IFPP firmware to all PE's in parallel */
	ifppsz = eip197_write_firmware(priv, fw[FW_IFPP]);

	for (pe = 0; pe < priv->config.pes; pe++) {
		/* Enable access to all IPUE program memories */
		writel(EIP197_PE_ICE_RAM_CTRL_PUE_PROG_EN,
		       EIP197_PE(priv) + EIP197_PE_ICE_RAM_CTRL(pe));
	}

	/* Write IPUE firmware to all PE's in parallel */
	ipuesz = eip197_write_firmware(priv, fw[FW_IPUE]);

	dev_info(priv->dev, "IPUE FW image is %d words, IFPP FW image is %d words.\n",
		 ipuesz, ifppsz);


	if (numfw == 4) {
		for (pe = 0; pe < priv->config.pes; pe++) {
			/* Enable access to all OFPP program memories */
			writel(EIP197_PE_ICE_RAM_CTRL_PUE_PROG_EN,
			       EIP197_PE(priv) + EIP197_PE_OCE_RAM_CTRL(pe));
		}

		/* Write OFPP firmware to all PE's in parallel */
		ofppsz = eip197_write_firmware(priv, fw[FW_OFPP]);

		for (pe = 0; pe < priv->config.pes; pe++) {
			/* Enable access to all OPUE program memories */
			writel(EIP197_PE_ICE_RAM_CTRL_PUE_PROG_EN,
			       EIP197_PE(priv) + EIP197_PE_OCE_RAM_CTRL(pe));
		}

		/* Write OPUE firmware to all PE's in parallel */
		opuesz = eip197_write_firmware(priv, fw[FW_OPUE]);

		dev_info(priv->dev, "OPUE FW image is %d words, OFPP FW image is %d words.\n",
			 opuesz, ofppsz);
	}

	if (eip197_start_firmware(priv, numfw, ipuesz, ifppsz,
				  opuesz, ofppsz)) {
		dev_info(priv->dev, "EIP197 firmware loaded successfully.\n");
		return 0;
	}
	// fallback to BCLA if FW start failed
	i = 0;

release_fw:
	/* Note that this functionality is formally for debugging only ... */
	if (priv->feat_flags & EIP197_OCE) {
		/* bypass the OCE for all pipes */
		for (pe = 0; pe < priv->config.pes; pe++)
			writel(0x2, EIP197_PE(priv) + EIP197_PE_DEBUG(pe));
	}

	if (i >= 2) {
		/* IPUE & IFPP firmwares found, try to run with only those */
		dev_info(priv->dev, "EIP197 OCE fw not present, falling back to non-OCE mode\n");
		numfw = 2;
		goto download_fw;
	}

	for (j = 0; j < i; j++)
		release_firmware(fw[j]);

	/*
	 * Firmware download failed, fall back to EIP97 BCLA mode
	 * Note that this is not a formally supported mode for the EIP197,
	 * so your mileage may vary
	 */
	dev_info(priv->dev, "EIP197 firmware set not (fully) present or init failed, falling back to EIP97 BCLA mode\n");

	eip197_init_firmware(priv, 2);

	for (i = 0; i < sizeof(ifpp_minifw)>>2; i++)
		writel(ifpp_minifw[i],
		       priv->base + EIP197_CLASSIFICATION_RAMS + (i<<2));

	for (pe = 0; pe < priv->config.pes; pe++) {
		/* Enable access to all IPUE program memories */
		writel(EIP197_PE_ICE_RAM_CTRL_PUE_PROG_EN,
		       EIP197_PE(priv) + EIP197_PE_ICE_RAM_CTRL(pe));
	}

	for (i = 0; i < sizeof(ipue_minifw)>>2; i++)
		writel(ipue_minifw[i],
		       priv->base + EIP197_CLASSIFICATION_RAMS + (i<<2));

	eip197_start_firmware(priv, numfw, 0, 0, 0, 0);
	return 0;
}

static int safexcel_hw_setup_cdesc_rings(struct safexcel_crypto_priv *priv)
{
	u32 cd_size_rnd, val;
	int i, cd_fetch_cnt;

	cd_size_rnd  = (priv->config.cd_size + (BIT(priv->hwdataw) - 1)) >>
		       priv->hwdataw;
	/* determine number of CD's we can fetch into the CD FIFO as 1 block */
	if (priv->feat_flags & HW_IS_EIP197) {
		/* EIP197: try to fetch enough in 1 go to keep all pipes busy */
		cd_fetch_cnt = (1 << priv->hwcfsize) / cd_size_rnd;
		cd_fetch_cnt = min(cd_fetch_cnt,
				   (priv->hwnumpes * EIP197_FETCH_DEPTH));
	} else {
		/* for the EIP97, just fetch all that fits minus 1 */
		cd_fetch_cnt = ((1 << priv->hwcfsize) / cd_size_rnd) - 1;
	}
	dev_info(priv->dev, "CDR init: size %d, offset %d, ring entries %d, queue entries %d, fetchcount %d\n",
		 priv->config.cd_size, (priv->config.cd_offset >> 2),
		 priv->config.ring_entries, priv->config.queue_entries,
		 cd_fetch_cnt);

	for (i = 0; i < priv->config.rings; i++) {
		/* ring base address */
		writel(lower_32_bits(priv->ring[i].cdr.base_dma),
		       EIP197_HIA_CDR(priv, i) +
		       EIP197_HIA_xDR_RING_BASE_ADDR_LO);
		writel(upper_32_bits(priv->ring[i].cdr.base_dma),
		       EIP197_HIA_CDR(priv, i) +
		       EIP197_HIA_xDR_RING_BASE_ADDR_HI);

		writel(EIP197_xDR_DESC_MODE_64BIT |
		       (priv->config.cd_offset << 14) |
		       priv->config.cd_size,
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_DESC_SIZE);
		writel(((cd_fetch_cnt * (cd_size_rnd << priv->hwdataw)) << 16) |
		       (cd_fetch_cnt * (priv->config.cd_offset >> 2)),
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_CFG);

		/* Configure DMA tx control */
		val = EIP197_HIA_xDR_DMA_CFG_WR_CACHE(WR_CACHE_3BITS);
		val |= EIP197_HIA_xDR_DMA_CFG_RD_CACHE(RD_CACHE_3BITS);
		writel(val, EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_DMA_CFG);

		/* clear any pending interrupt */
		writel(GENMASK(5, 0),
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_STAT);
	}

	return 0;
}

static int safexcel_hw_setup_rdesc_rings(struct safexcel_crypto_priv *priv)
{
	u32 val, rd_size_rnd;
	int i, rd_fetch_cnt;

	/* determine number of RD's we can fetch into the FIFO as one block */
	rd_size_rnd = (EIP197_RD64_FETCH_SIZE + BIT(priv->hwdataw) - 1) >>
		      priv->hwdataw;
	if (priv->feat_flags & HW_IS_EIP197) {
		/* EIP197: try to fetch enough in 1 go to keep all pipes busy */
		rd_fetch_cnt = (1 << priv->hwrfsize) / rd_size_rnd;
		rd_fetch_cnt = min(rd_fetch_cnt,
				   (priv->hwnumpes * EIP197_FETCH_DEPTH));
	} else {
		/* for the EIP97, just fetch all that fits minus 1 */
		rd_fetch_cnt = ((1 << priv->hwrfsize) / rd_size_rnd) - 1;
	}
	dev_info(priv->dev, "RDR init: size %d, offset %d, ring entries %d, fetchcount %d\n",
		 priv->config.rd_size, (priv->config.rd_offset >> 2),
		 priv->config.ring_entries, rd_fetch_cnt);

	for (i = 0; i < priv->config.rings; i++) {
		/* ring base address */
		writel(lower_32_bits(priv->ring[i].rdr.base_dma),
		       EIP197_HIA_RDR(priv, i) +
		       EIP197_HIA_xDR_RING_BASE_ADDR_LO);
		writel(upper_32_bits(priv->ring[i].rdr.base_dma),
		       EIP197_HIA_RDR(priv, i) +
		       EIP197_HIA_xDR_RING_BASE_ADDR_HI);

		writel(EIP197_xDR_DESC_MODE_64BIT |
		       (priv->config.rd_offset << 14) |
		       priv->config.rd_size,
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_DESC_SIZE);

		val = ((rd_fetch_cnt *
			(priv->config.rd_size -
			 EIP197_RD64_RESULT_SIZE)) << 16) |
		      (rd_fetch_cnt * (priv->config.rd_offset >> 2));
		/* Enable ownership word writes if configured */
		if (EIP197_RD_OWN_WORD)
			val |= EIP197_HIA_xDR_CFG_OWM_ENABLE;
		writel(val, EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_CFG);

		/* Configure DMA tx control */
		val = EIP197_HIA_xDR_DMA_CFG_WR_CACHE(WR_CACHE_3BITS);
		val |= EIP197_HIA_xDR_DMA_CFG_RD_CACHE(RD_CACHE_3BITS);
		/*
		 * If ownership words are enabled, then use the pad-to-offset
		 * feature to avoid separate writes for it. Also enable for PCI
		 * devices in order to pad to the cacheline size, avoiding
		 * read-modify-write operations.
		 */
		if (EIP197_RD_OWN_WORD || (priv->ctxt_flags & DEVICE_IS_PCI))
			val |= EIP197_HIA_xDR_DMA_CFG_PAD_TO_OFFSET;
		/*
		 * For HW newer than 2.6 the meaning of the below bits changed.
		 * Just keep bits 21:19 at zero to ensure bufferable transfers
		 * (for performance) and bits 24:22 at zero to ensure we wait
		 * for the interconnect acknowledge before updating status/
		 * asserting interrupts, for reliability.
		 */
		if (priv->hwver <= 0x260) {
			/*
			 * For performance, we want bufferable transfers, but
			 * this may not always be reliable depending on the
			 * system. Enabling ownership word polling should take
			 * care of that.
			 */
			val |= EIP197_HIA_xDR_WR_RES_BUF |
			       EIP197_HIA_xDR_WR_CTRL_BUF |
			       EIP197_HIA_xDR_WR_OWN_BUF;
		} else {
			/*
			 * We operate in full packet mode, so no need to wait
			 * for these as *last* descriptors will always use
			 * CTRL_NOWAIT/NONBUF
			 */
			val |= EIP197_HIA_xDR_WR_OWN_NOWAIT;
		}
		writel(val,
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_DMA_CFG);

		/* clear any pending interrupt */
		writel(GENMASK(7, 0),
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_STAT);

		/* enable ring interrupt */
		val = readl(EIP197_HIA_AIC_R(priv) +
			    EIP197_HIA_AIC_R_ENABLE_CTRL(i));
		val |= EIP197_RDR_IRQ(i);
		writel(val, EIP197_HIA_AIC_R(priv) +
			    EIP197_HIA_AIC_R_ENABLE_CTRL(i));
	}

	return 0;
}

static int safexcel_hw_init(struct safexcel_crypto_priv *priv)
{
	u32 val;
	int i, ret, pe, ctxalign;
	int ipbuflo, ipbufhi, opbuflo, opbufhi, itbuflo, itbufhi, ctxsize;
	u32 rnddwrds[12];

	/* Need to clip to 4 Kbyte max (AXI decode boundary) */
	burst_size = min_t(u32, (10 - priv->hwdataw), burst_size);
	/* And 256 beats max (AXI4 maximum) */
	burst_size = min_t(u32, 8, burst_size);

	dev_info(priv->dev, "EIP(1)97 HW init: burst size %d beats, using %d pipe(s) and %d ring(s)\n",
			(1<<burst_size), priv->config.pes, priv->config.rings);

	val = readl(EIP197_HIA_AIC(priv) + EIP197_HIA_MST_CTRL);
	if (priv->feat_flags & HW_IS_EIP197) {
		/*
		 * set EIP197 command queueing limits, not for EIP97
		 * clear limits - default should be 'unlimited'
		 */
		val &= ~(EIP197_HIA_MST_CTRL_RX_MAX_CMD(0xf) |
			 EIP197_HIA_MST_CTRL_TX_MAX_CMD(0xf));

		/* For Marvell set maximum number of TX commands to 2^5 = 32 */
		if (priv->ctxt_flags & (MRVL_EIP197B | MRVL_EIP197D))
			val |= EIP197_HIA_MST_CTRL_TX_MAX_CMD(5);
	}
	val &= ~(EIP197_HIA_MST_CTRL_RX_BURST(0xf) |
		 EIP197_HIA_MST_CTRL_TX_BURST(0xf)); // clear fields first
	if (priv->feat_flags & HW_IS_EIP197)
		val |= EIP197_HIA_MST_CTRL_RX_BURST(burst_size) |
		       EIP197_HIA_MST_CTRL_TX_BURST(burst_size);
	else
		val |= EIP197_HIA_MST_CTRL_TX_BURST(burst_size);
	/*
	 * Tell EIP(1)97 what our system cache line size is, so it can optimize
	 * transfers. This is beneficial for coherent PCIE.
	 * Not sure about other platforms ...
	 */
	if (priv->ctxt_flags & DEVICE_IS_PCI) {
		val |= EIP197_HIA_MST_CTRL_XFR_ALIGN(__fls(cache_line_size()));
		ctxalign = max_t(int, (__fls(cache_line_size()) - 5), 0);
		ctxalign = min_t(int, ctxalign, 3);
		dev_info(priv->dev, "EIP(1)97 HW init: align transfers to %d bytes, ctxt writes to %d bytes\n",
				cache_line_size(), (32<<ctxalign));
	} else {
		ctxalign = 0;
	}
	writel(val, EIP197_HIA_AIC(priv) + EIP197_HIA_MST_CTRL);

	/*
	 * Configure wr/rd cache values and context record alignment to
	 * system cacheline size
	 */
	writel(EIP197_MST_CTRL_RD_CACHE(RD_CACHE_4BITS) |
	       EIP197_MST_CTRL_WD_CACHE(WR_CACHE_4BITS) |
	       EIP197_MST_CTRL_CTXT_ALIGN(ctxalign),
	       EIP197_HIA_GEN_CFG(priv) + EIP197_MST_CTRL);

	/* Interrupts reset */

	/* Disable all global interrupts */
	writel(0, EIP197_HIA_AIC_G(priv) + EIP197_HIA_AIC_G_ENABLE_CTRL);

	/* Clear any pending interrupt */
	writel(GENMASK(31, 0), EIP197_HIA_AIC_G(priv) + EIP197_HIA_AIC_G_ACK);

	/* Determine optimal buffer threshold settings */
	ipbuflo = 6;
	ipbufhi = 9;
	itbuflo = 6;
	itbufhi = 7;
	if (priv->hwnumpes > 4) {
		/* Need higher thresholds for the high pipecount engines */
		opbuflo = 9;
		opbufhi = 10;
	} else {
		opbuflo = 7;
		opbufhi = 8;
	}

	/* Determine maximum context size required by EIP96 */
	if (priv->algo_flags & ALGO_SHA2_512) {
		if (priv->algo_flags & SEQMASK_384)
			ctxsize = 0x3e;
		else
			ctxsize = 0x35;
	} else {
		if (priv->algo_flags & SEQMASK_384)
			ctxsize = 0x2e;
		else
			ctxsize = 0x25;
	}

	/* Processing Engine configuration */
	for (pe = 0; pe < priv->config.pes; pe++) {
		if (priv->hwver >= 0x280) {
			/*
			 * These registers exist since EIP197 HW2.8
			 * This should be optimal then the (safe) reset values
			 */
			writel(EIP197_PIPE_ICE_COHERENCE_MAGIC,
			       priv->base + EIP197_PIPE_ICE_COHERENCE_CTRL(pe));
			if (priv->feat_flags & EIP197_OCE)
				writel(EIP197_PIPE_OCE_COHERENCE_MAGIC,
				       priv->base +
				       EIP197_PIPE_OCE_COHERENCE_CTRL(pe));
			/* just keep all pipes coherent with each other */
			writel(GENMASK(31, 0),
			       priv->base + EIP197_PIPE_COHERENT_WITH(pe));

		}

		/* Data Fetch Engine configuration */

		/* Reset all DFE threads */
		writel(EIP197_DxE_THR_CTRL_RESET_PE,
		       EIP197_HIA_DFE_THR(priv) + EIP197_HIA_DFE_THR_CTRL(pe));

		if (priv->feat_flags & EIP197_PE_ARB) {
			/* Reset HIA input interface arbiter */
			writel(EIP197_HIA_RA_PE_CTRL_RESET,
			       EIP197_HIA_AIC(priv) +
			       EIP197_HIA_RA_PE_CTRL(pe));
		}

		/* DMA transfer size to use */
		val = EIP197_HIA_DFE_CFG_DIS_DEBUG;
		val |= EIP197_HIA_DxE_CFG_MIN_DATA_SIZE(ipbuflo) |
		       EIP197_HIA_DxE_CFG_MAX_DATA_SIZE(ipbufhi);
		val |= EIP197_HIA_DxE_CFG_MIN_CTRL_SIZE(itbuflo) |
		       EIP197_HIA_DxE_CFG_MAX_CTRL_SIZE(itbufhi);
		val |= EIP197_HIA_DxE_CFG_DATA_CACHE_CTRL(RD_CACHE_3BITS);
		val |= EIP197_HIA_DxE_CFG_CTRL_CACHE_CTRL(RD_CACHE_3BITS);
		writel(val, EIP197_HIA_DFE(priv) + EIP197_HIA_DFE_CFG(pe));

		/* Leave the DFE threads reset state */
		writel(0,
		       EIP197_HIA_DFE_THR(priv) + EIP197_HIA_DFE_THR_CTRL(pe));

		/* Configure the processing engine thresholds */
		writel(EIP197_PE_IN_xBUF_THRES_MIN(ipbuflo) |
		       EIP197_PE_IN_xBUF_THRES_MAX(ipbufhi),
		       EIP197_PE(priv) + EIP197_PE_IN_DBUF_THRES(pe));
		writel(EIP197_PE_IN_xBUF_THRES_MIN(itbuflo) |
		       EIP197_PE_IN_xBUF_THRES_MAX(itbufhi),
		       EIP197_PE(priv) + EIP197_PE_IN_TBUF_THRES(pe));

		if (priv->feat_flags & EIP197_PE_ARB) {
			/* enable HIA input interface arbiter and rings */
			writel(EIP197_HIA_RA_PE_CTRL_EN |
			       GENMASK(priv->config.rings - 1, 0),
			       EIP197_HIA_AIC(priv) +
			       EIP197_HIA_RA_PE_CTRL(pe));
		}

		/* Data Store Engine configuration */

		/* Reset all DSE threads */
		writel(EIP197_DxE_THR_CTRL_RESET_PE,
		       EIP197_HIA_DSE_THR(priv) + EIP197_HIA_DSE_THR_CTRL(pe));

		/* Wait for all DSE threads to complete */
		while ((readl(EIP197_HIA_DSE_THR(priv) +
			      EIP197_HIA_DSE_THR_STAT(pe)) & GENMASK(15, 12)) !=
		       GENMASK(15, 12))
			cpu_relax();

		/* DMA transfer size to use */
		val = EIP197_HIA_DSE_CFG_DIS_DEBUG;
		val |= EIP197_HIA_DxE_CFG_MIN_DATA_SIZE(opbuflo) |
		       EIP197_HIA_DxE_CFG_MAX_DATA_SIZE(opbufhi);
		val |= EIP197_HIA_DxE_CFG_DATA_CACHE_CTRL(WR_CACHE_3BITS);
		/*
		 * Note: used to be combined bufferability & wait ctrl in HW2.6
		 * and before/ In HW2.8 and later the bufferability control was
		 * split off to bit 12 (allow_nonbuf).
		 */
		if (priv->hwver <= 0x260) {
			/*
			 * For performance we want bufferable transfers. This
			 * may not always be reliable though, depending on the
			 * system ...
			 * Enabling ownership words should take care of that.
			 */
			val |= EIP197_HIA_DSE_CFG_ALWAYS_BUF;
		} else {
			/*
			 * Wait for full packets only, so our packet data is
			 * guaranteed to be there once we received the packet
			 * threshold interrupt.
			 */
			val |= EIP197_HIA_DSE_CFG_WAIT_PKT;
		}

		if (priv->feat_flags & HW_IS_EIP197)
			val |= EIP197_HIA_DSE_CFG_EN_SINGLE_WR;
		writel(val, EIP197_HIA_DSE(priv) + EIP197_HIA_DSE_CFG(pe));

		/* Leave the DSE threads reset state */
		writel(0,
		       EIP197_HIA_DSE_THR(priv) + EIP197_HIA_DSE_THR_CTRL(pe));

		/* Configure the procesing engine thresholds */
		writel(EIP197_PE_OUT_DBUF_THRES_MIN(opbuflo) |
		       EIP197_PE_OUT_DBUF_THRES_MAX(opbufhi),
		       EIP197_PE(priv) + EIP197_PE_OUT_DBUF_THRES(pe));

		/* Processing Engine configuration */

		/* H/W capabilities selection */
		/* just enable all supported algorithms */
		writel(GENMASK(31, 0),
		       EIP197_PE(priv) + EIP197_PE_EIP96_FUNCTION_EN(pe));

		/* Enable optimal context updates and time-out counter */
		writel(EIP197_PE_EIP96_TOKEN_CTRL_MAGIC,
		       EIP197_PE(priv) + EIP197_PE_EIP96_TOKEN_CTRL_STAT(pe));

		/* Configure context fetch mode & size */
		writel(0x200 | ctxsize,
		       EIP197_PE(priv) + EIP197_PE_EIP96_CONTEXT_CTRL(pe));

		if (priv->feat_flags & EIP197_OCE) {
			/* OCE present, do not insert IP len delta */
			writel(0, EIP197_PE(priv) +
				  EIP197_PE_EIP96_OUT_BUF_CTRL(pe));
		} else {
			/* OCE not present, insert IP len delta */
			writel(BIT(30), EIP197_PE(priv) +
					EIP197_PE_EIP96_OUT_BUF_CTRL(pe));
		}

		if (priv->pever >= 0x420) { // new in this HW version!
			/* disable oversize check to allow for pad stripping */
			writel(3, EIP197_PE(priv) +
				  EIP197_PE_EIP96_TOKEN_CTRL2(pe));
			/* just enable all supported algorithms, part deux */
			writel(GENMASK(31, 0),
			       EIP197_PE(priv) +
			       EIP197_PE_EIP96_FUNCTION2_EN(pe));
		}

		/*
		 * If we don't have a central DRBG,
		 * then initialize the local PRNG
		 */
		if (!(priv->feat_flags & EIP197_DRBG)) {
			/* Seed with entropy */
			get_random_bytes(rnddwrds, 32);
			writel(rnddwrds[0], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_SEED_L(pe));
			writel(rnddwrds[1], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_SEED_H(pe));
			writel(rnddwrds[2], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_KEY_0_L(pe));
			writel(rnddwrds[3], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_KEY_0_H(pe));
			writel(rnddwrds[4], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_KEY_1_L(pe));
			writel(rnddwrds[5], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_KEY_1_H(pe));
			writel(rnddwrds[6], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_LFSR_L(pe));
			writel(rnddwrds[7], EIP197_PE(priv) +
					    EIP197_PE_EIP96_PRNG_LFSR_H(pe));
			/* Enable */
			writel(3,
			       EIP197_PE(priv) + EIP197_PE_EIP96_PRNG_CTRL(pe));
		}
	}

	/* Initialize central DRBG, if present */
	if (priv->feat_flags & EIP197_DRBG) {
		/* Ensure DRBG is idle */
		writel(0, priv->base + EIP197_DRBG_CONTROL);
		/*
		 * And wait until it's ready to accept PS_AI
		 * don't bother with jiffies, just timeout after 10 tries
		 * as this shouldn't take more than a few dozen device clocks
		 */
		i = 0;
		do {
			val = readl(priv->base + EIP197_DRBG_STATUS);
			i++;
		} while ((!(val & 2)) && (i < 10));
		if (!(val & 2)) {
			/*
			 * if we time-out, just print some warning about that,
			 * don't hard-fail
			 */
			dev_info(priv->dev, "WARNING: DRBG initialization failed due to time-out.\n");
		}

		/*
		 * Set generate blocksize to 64, for now
		 * This is the minimum allowed, providing maximum security.
		 * However, from a power and/or performance perspective,
		 * a lower value may be desired, sacrificing some security.
		 * Note that the DRBG is only used for IV's, so security is
		 * not a major concern anyway ...
		 */
		writel(64, priv->base + EIP197_DRBG_GEN_BLK_SIZE);

		/* Seed with entropy */
		get_random_bytes(rnddwrds, 48);
		for (i = 0; i < 12; i++)
			writel(rnddwrds[i],
			       EIP197_PE(priv) + EIP197_DRBG_PS_AI(i));
		/* Enable DRBG & stuck-out error IRQ */
		writel(0x404, EIP197_PE(priv) + EIP197_DRBG_CONTROL);
	}

	/* Command Descriptor Rings prepare */
	for (i = 0; i < priv->config.rings; i++) {
		/* Clear interrupts for this ring */
		writel(GENMASK(31, 0),
		       EIP197_HIA_AIC_R(priv) + EIP197_HIA_AIC_R_ENABLE_CLR(i));

		/* Disable external triggering */
		writel(0, EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_CFG);

		/* Clear the pending prepared counter */
		writel(EIP197_xDR_PREP_CLR_COUNT,
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_PREP_COUNT);

		/* Clear the pending processed counter */
		writel(EIP197_xDR_PROC_CLR_COUNT,
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_PROC_COUNT);

		writel(0,
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_PREP_PNTR);
		writel(0,
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_PROC_PNTR);

		writel(priv->config.ring_entries * priv->config.cd_offset,
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_RING_SIZE);
	}

	/* Result Descriptor Ring prepare */
	for (i = 0; i < priv->config.rings; i++) {
		/* Disable external triggering*/
		writel(0, EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_CFG);

		/* Clear the pending prepared counter */
		writel(EIP197_xDR_PREP_CLR_COUNT,
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_PREP_COUNT);

		/* Clear the pending processed counter */
		writel(EIP197_xDR_PROC_CLR_COUNT,
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_PROC_COUNT);

		writel(0,
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_PREP_PNTR);
		writel(0,
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_PROC_PNTR);

		/* Ring size */
		writel(priv->config.ring_entries * priv->config.rd_offset,
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_RING_SIZE);
	}

	for (pe = 0; pe < priv->config.pes; pe++) {
		/* Enable command descriptor rings */
		writel(EIP197_DxE_THR_CTRL_EN |
		       GENMASK(priv->config.rings - 1, 0),
		       EIP197_HIA_DFE_THR(priv) + EIP197_HIA_DFE_THR_CTRL(pe));

		/* Enable result descriptor rings */
		writel(EIP197_DxE_THR_CTRL_EN |
		       GENMASK(priv->config.rings - 1, 0),
		       EIP197_HIA_DSE_THR(priv) + EIP197_HIA_DSE_THR_CTRL(pe));
	}

	/* Clear any HIA interrupt */
	writel(GENMASK(30, 20), EIP197_HIA_AIC_G(priv) + EIP197_HIA_AIC_G_ACK);

	/* If we have a transform record cache, then initialize it */
	if (priv->feat_flags & EIP197_TRC_CACHE)
		eip197_trc_cache_init(priv);

	/* If we have a classifier present, then go load the firmware for it */
	if (priv->feat_flags & EIP197_ICE) {
		ret = eip197_load_firmwares(priv);
		if (ret)
			return ret;
	}

	/* Configure the rings */
	safexcel_hw_setup_cdesc_rings(priv);
	safexcel_hw_setup_rdesc_rings(priv);

	return 0;
}

/*
 * Called with ring's lock taken
 * Should not be called with zero requests remaining !
 */
static void safexcel_try_push_requests(struct safexcel_crypto_priv *priv,
				       int ring)
{
	int coal = min_t(int, priv->ring[ring].requests, EIP197_MAX_BATCH_SZ);

	/* Configure when we want an interrupt */
	writel(EIP197_HIA_RDR_THRESH_PKT_MODE |
	       EIP197_HIA_RDR_THRESH_PROC_PKT(coal),
	       EIP197_HIA_RDR(priv, ring) + EIP197_HIA_xDR_THRESH);

	if (EIP197_AVOID_DEV_READ && likely(!priv->ring[ring].busy)) {
		/* Remember threshold value last written */
		priv->ring[ring].thresh_written = coal;
	}
}

void safexcel_dequeue(struct safexcel_crypto_priv *priv, int ring)
{
	struct crypto_async_request *req, *backlog;
	struct safexcel_context *ctx;
	int ret, nreq = 0, cdesc = 0, rdesc = 0, commands, results;

	/*
	 * Expecting to add more requests, so disable threshold IRQ for now
	 * anticipating a threshold increment at the end of this function.
	 * Purpose being to maximize interrupt coalescing.
	 */
	writel(EIP197_HIA_RDR_THRESH_PKT_MODE,
	       EIP197_HIA_RDR(priv, ring) + EIP197_HIA_xDR_THRESH);

	/*
	 * If a request wasn't properly dequeued because of a lack of resources,
	 * proceeded it first,
	 */
	req = priv->ring[ring].req;
	backlog = priv->ring[ring].backlog;
	if (unlikely(req))
		goto handle_req;

	while (true) {
		spin_lock_bh(&priv->ring[ring].queue_lock);
		backlog = crypto_get_backlog(&priv->ring[ring].queue);
		req = crypto_dequeue_request(&priv->ring[ring].queue);
		spin_unlock_bh(&priv->ring[ring].queue_lock);

		if (!req) {
			priv->ring[ring].req = NULL;
			priv->ring[ring].backlog = NULL;
			goto finalize;
		}

handle_req:
		ctx = crypto_tfm_ctx(req->tfm);
		ret = ctx->send(req, ring, &commands, &results);
		if (unlikely(ret))
			goto request_failed;

		if (backlog)
			backlog->complete(backlog, -EINPROGRESS);

		/*
		 * In case the send() helper did not issue any command to push
		 * to the engine because the input data was cached, continue to
		 * dequeue other requests as this is valid and not an error.
		 */
		if (!commands && !results)
			continue;

		cdesc += commands;
		rdesc += results;
		nreq++;
	}

request_failed:
	/*
	 * Not enough resources to handle all the requests. Bail out and save
	 * the request and the backlog for the next dequeue call (per-ring).
	 */
	priv->ring[ring].req = req;
	priv->ring[ring].backlog = backlog;

finalize:
	/* let the CDR know we have pending descriptors */
	writel(cdesc * priv->config.cd_offset,
	       EIP197_HIA_CDR(priv, ring) + EIP197_HIA_xDR_PREP_COUNT);

	spin_lock_bh(&priv->ring[ring].lock);

	/*
	 * MUST increment requests *prior* to writing RDR_PREP_COUNT
	 * to avoid a race condition where the interrupt handling thread
	 * sees the result before we get here and decrements past zero.
	 */
	priv->ring[ring].requests += nreq;

	/* let the RDR know we have pending descriptors too */
	writel(rdesc * priv->config.rd_offset,
	       EIP197_HIA_RDR(priv, ring) + EIP197_HIA_xDR_PREP_COUNT);

	if (likely(priv->ring[ring].requests)) {
		/*
		 * No need to check for busy state here, HW allows updating
		 * the threshold. Interrupt handler will overwrite with lower
		 * value if this is now too high to handle.
		 */
		safexcel_try_push_requests(priv, ring);
		priv->ring[ring].busy = true;
	}

	spin_unlock_bh(&priv->ring[ring].lock);
}

inline int safexcel_rdesc_check_errors(struct safexcel_crypto_priv *priv,
				       void *rdesc)
{
	struct result_data_desc *result_data = rdesc + priv->config.res_offset;

	if (likely(!result_data->error_code))
		return 0;

	if (result_data->error_code & 0x407f) {
		/* Fatal error (bits 0-7, 14) */
		dev_err(priv->dev,
			"cipher: result: result descriptor error (%x)\n",
			result_data->error_code);
		return -EIO;
	} else if (result_data->error_code == BIT(9)) {
		/* Authentication failed */
		return -EBADMSG;
	}

	/* All other non-fatal errors */
	return -EINVAL;
}

inline void safexcel_rdr_req_set(struct safexcel_crypto_priv *priv,
				 int ring,
				 struct safexcel_result_desc *rdesc,
				 struct crypto_async_request *req)
{
	int i = safexcel_ring_rdr_rdesc_index(priv, ring, rdesc);

	priv->ring[ring].rdr_req[i] = req;
}

inline struct crypto_async_request *
safexcel_rdr_req_get(struct safexcel_crypto_priv *priv, int ring)
{
	int i = safexcel_ring_first_rdr_index(priv, ring);

	return priv->ring[ring].rdr_req[i];
}

void safexcel_complete(struct safexcel_crypto_priv *priv, int ring)
{
	struct safexcel_command_desc *cdesc;

	/* Acknowledge the command descriptors */
	do {
		cdesc = safexcel_cdr_next_rptr(priv, &priv->ring[ring].cdr);
	} while (!cdesc->last_seg);
}

void safexcel_inv_complete(struct crypto_async_request *req, int error)
{
	struct safexcel_inv_result *result = req->data;

	if (error == -EINPROGRESS)
		return;

	result->error = error;
	complete(&result->completion);
}

int safexcel_invalidate_cache(struct crypto_async_request *async,
			      struct safexcel_crypto_priv *priv,
			      dma_addr_t ctxr_dma, int ring)
{
	struct safexcel_command_desc *cdesc;
	struct safexcel_result_desc *rdesc;
	int ret = 0;

	/* Prepare command descriptor */
	cdesc = safexcel_add_cdesc(priv, ring, true, true, 0, 0, 0, ctxr_dma);
	if (IS_ERR(cdesc))
		return PTR_ERR(cdesc);

	cdesc->control_data.type = EIP197_TYPE_EXTENDED;
	cdesc->control_data.options = 0;
	cdesc->control_data.ptrtype = EIP197_PTRTYPE_NULL;
	cdesc->control_data.control0 = CONTEXT_CONTROL_INV_TR;

	/* Prepare result descriptor */
	rdesc = safexcel_add_rdesc(priv, ring, true, true, 0, 0);

	if (IS_ERR(rdesc)) {
		ret = PTR_ERR(rdesc);
		goto cdesc_rollback;
	}

	safexcel_rdr_req_set(priv, ring, rdesc, async);

	return ret;

cdesc_rollback:
	safexcel_cdr_rollback_wptr(priv, &priv->ring[ring].cdr);

	return ret;
}

static void safexcel_handle_result_descriptor(struct safexcel_crypto_priv *priv,
					      int ring)
{
	struct crypto_async_request *req;
	struct safexcel_context *ctx;
	int ret, i, nreq, ndesc, tot_descs, handled = 0;
	bool should_complete;
	u32 stat;

	stat = readl(EIP197_HIA_RDR(priv, ring) + EIP197_HIA_xDR_STAT);

	tot_descs = 0;

	/*
	 * In device read avoidance mode, we need to skip the desc handling
	 * part if we get e.g. an error interrupt instead since nreq will
	 * not be accurate then. If we read PROC_COUNT, this is not an issue.
	 */
	if (unlikely(EIP197_AVOID_DEV_READ && !(stat & EIP197_xDR_THRESH))) {
		goto no_thresh_irq;
	} else if (EIP197_AVOID_DEV_READ) {
		/*
		 * Just process what we know we queued (and is thus guaranteed
		 * to be available) and then wait for a new interrupt.
		 * Note: shared variable, but no need to acquire any locks here.
		 * Only updated if no thresh requests were pending.
		 */
		nreq = priv->ring[ring].thresh_written;
	} else {
		/*
		 * Read current processed status directly from the HW to get the
		 * most recent status at the expense of a (slow?) device read.
		 */
		nreq = readl(EIP197_HIA_RDR(priv, ring) +
			     EIP197_HIA_xDR_PROC_COUNT);
		nreq >>= EIP197_xDR_PROC_xD_PKT_OFFSET;
	}

	/* Always handling all, so save that amount */
	handled = nreq;
	while (nreq) {
one_more_req:
		req = safexcel_rdr_req_get(priv, ring);

		ctx = crypto_tfm_ctx(req->tfm);
		ndesc = ctx->handle_result(priv, ring, req,
					   &should_complete, &ret);

		if (likely(should_complete)) {
			local_bh_disable();
			req->complete(req, ret);
			local_bh_enable();
		} else if (unlikely(EIP197_RD_OWN_WORD && (!ndesc))) {
			/* RD not yet written, exit and retry on next IRQ */
			handled -= nreq;
			goto err_finish;
		}

		tot_descs += ndesc;
		nreq--;
	}

	/*
	 * If ownership words are enabled, then check if the next packet is
	 * already there. If so, go handle it immediately.
	 */
	if (EIP197_RD_OWN_WORD &&
	    safexcel_rdr_scan_next(priv, &priv->ring[ring].rdr)) {
		nreq = 1;
		handled++;
		goto one_more_req;
	}

err_finish:
	if (likely(handled)) {
		i = handled;
		if (EIP197_AVOID_DEV_READ) {
			/*
			 * Perform any full EIP197_xDR_PROC_xD_PKT_MASK
			 * decrements until we drop below
			 */
			while (i > EIP197_xDR_PROC_xD_PKT_MASK) {
				writel(EIP197_xDR_PROC_xD_PKT(EIP197_xDR_PROC_xD_PKT_MASK),
				       EIP197_HIA_RDR(priv, ring) +
				       EIP197_HIA_xDR_PROC_COUNT);
				i -= EIP197_xDR_PROC_xD_PKT_MASK;
			}
		}

		/* Ack remaining packets plus all handled descriptors */
		writel(EIP197_xDR_PROC_xD_PKT(i) |
		       (tot_descs * priv->config.rd_offset),
		       EIP197_HIA_RDR(priv, ring) + EIP197_HIA_xDR_PROC_COUNT);
	}

no_thresh_irq:
	/* Try to push any remaining requests BEFORE we ack the IRQ */
	spin_lock_bh(&priv->ring[ring].lock);

	priv->ring[ring].requests -= handled;
	priv->ring[ring].busy = false;

	/*
	 * And finally ack all RDR threshold IRQs
	 * Do this as late as possible, but before writing a new threshold value
	 */
	writel(0xff,
	       EIP197_HIA_RDR(priv, ring) + EIP197_HIA_xDR_STAT);

	if (priv->ring[ring].requests) {
		safexcel_try_push_requests(priv, ring);
		priv->ring[ring].busy = true;
	}

	spin_unlock_bh(&priv->ring[ring].lock);

	if (unlikely(stat & EIP197_xDR_ERR)) {
		/*
		 * Fatal error, the RDR is unusable and must be
		 * reinitialized. This should not happen under
		 * normal circumstances.
		 */
		dev_err(priv->dev, "RDR: fatal error.");
	}
}

static void safexcel_dequeue_work(struct work_struct *work)
{
	struct safexcel_work_data *data =
			container_of(work, struct safexcel_work_data, work);

	safexcel_dequeue(data->priv, data->ring);
}

struct safexcel_ring_irq_data {
	struct safexcel_crypto_priv *priv;
	int ring;
};

static irqreturn_t safexcel_irq_ring_thread(int irq, void *data)
{
	struct safexcel_ring_irq_data *irq_data = data;
	struct safexcel_crypto_priv *priv = irq_data->priv;
	int ring = irq_data->ring;

	safexcel_handle_result_descriptor(priv, ring);

	queue_work(priv->ring[ring].workqueue,
		   &priv->ring[ring].work_data.work);

	return IRQ_HANDLED;
}

static int safexcel_request_plf_ring_irq(struct platform_device *pdev,
					 const char *name,
					 irq_handler_t handler,
					 irq_handler_t threaded_handler,
					 struct safexcel_ring_irq_data *ring_irq_priv)
{
	int ret;
	int irq = platform_get_irq_byname(pdev, name);

	if (irq < 0) {
		dev_err(&pdev->dev, "unable to get IRQ '%s'\n", name);
		return irq;
	}

	ret = devm_request_threaded_irq(&pdev->dev, irq, handler,
					threaded_handler, IRQF_ONESHOT,
					dev_name(&pdev->dev), ring_irq_priv);
	if (ret) {
		dev_err(&pdev->dev, "unable to request IRQ %d\n", irq);
		return ret;
	}

	return irq;
}

static int safexcel_request_pci_ring_irq(struct pci_dev *pdev, int irqid,
				     irq_handler_t handler,
				     irq_handler_t threaded_handler,
				     struct safexcel_ring_irq_data *ring_irq_priv)
{
	int ret, irq = pci_irq_vector(pdev, irqid);

	if (irq < 0) {
		dev_err(&pdev->dev, "unable to get device MSI IRQ '%d'\n",
			irqid);
		return irq;
	}

	ret = devm_request_threaded_irq(&pdev->dev, irq, handler,
					threaded_handler, IRQF_ONESHOT,
					dev_name(&pdev->dev), ring_irq_priv);
	if (ret) {
		dev_err(&pdev->dev, "unable to request IRQ %d\n", irq);
		return ret;
	}

	return irq;
}

static struct safexcel_alg_template *safexcel_algs[] = {
	&safexcel_alg_ecb_des,
	&safexcel_alg_cbc_des,
	&safexcel_alg_ecb_des3_ede,
	&safexcel_alg_cbc_des3_ede,
	&safexcel_alg_ecb_aes,
	&safexcel_alg_cbc_aes,
	&safexcel_alg_md5,
	&safexcel_alg_sha1,
	&safexcel_alg_sha224,
	&safexcel_alg_sha256,
	&safexcel_alg_sha384,
	&safexcel_alg_sha512,
	&safexcel_alg_hmac_md5,
	&safexcel_alg_hmac_sha1,
	&safexcel_alg_hmac_sha224,
	&safexcel_alg_hmac_sha256,
	&safexcel_alg_hmac_sha384,
	&safexcel_alg_hmac_sha512,
	&safexcel_alg_authenc_hmac_sha1_cbc_aes,
	&safexcel_alg_authenc_hmac_sha224_cbc_aes,
	&safexcel_alg_authenc_hmac_sha256_cbc_aes,
	&safexcel_alg_authenc_hmac_sha384_cbc_aes,
	&safexcel_alg_authenc_hmac_sha512_cbc_aes,
};

static int safexcel_register_algorithms(struct safexcel_crypto_priv *priv)
{
	int i, j, ret = 0;

	for (i = 0; i < ARRAY_SIZE(safexcel_algs); i++) {
		safexcel_algs[i]->priv = priv;

		/* Do we have all required base algorithms available? */
		if ((safexcel_algs[i]->algo_mask & priv->algo_flags) !=
		    safexcel_algs[i]->algo_mask)
			/* No, so don't register this ciphersuite */
			continue;

		if (safexcel_algs[i]->type == SAFEXCEL_ALG_TYPE_SKCIPHER)
			ret = crypto_register_skcipher(&safexcel_algs[i]->alg.skcipher);
		else if (safexcel_algs[i]->type == SAFEXCEL_ALG_TYPE_AEAD)
			ret = crypto_register_aead(&safexcel_algs[i]->alg.aead);
		else
			ret = crypto_register_ahash(&safexcel_algs[i]->alg.ahash);

		if (ret)
			goto fail;
	}

	return 0;

fail:
	for (j = 0; j < i; j++) {
		/* Do we have all required base algorithms available? */
		if ((safexcel_algs[j]->algo_mask & priv->algo_flags) !=
		    safexcel_algs[j]->algo_mask)
			/* No, so don't register this ciphersuite */
			continue;

		if (safexcel_algs[j]->type == SAFEXCEL_ALG_TYPE_SKCIPHER)
			crypto_unregister_skcipher(&safexcel_algs[j]->alg.skcipher);
		else if (safexcel_algs[j]->type == SAFEXCEL_ALG_TYPE_AEAD)
			crypto_unregister_aead(&safexcel_algs[j]->alg.aead);
		else
			crypto_unregister_ahash(&safexcel_algs[j]->alg.ahash);
	}

	return ret;
}

static void safexcel_unregister_algorithms(struct safexcel_crypto_priv *priv)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(safexcel_algs); i++) {
		/* Do we have all required base algorithms available? */
		if ((safexcel_algs[i]->algo_mask & priv->algo_flags) !=
		    safexcel_algs[i]->algo_mask)
			/* No, so don't unregister this ciphersuite */
			continue;

		if (safexcel_algs[i]->type == SAFEXCEL_ALG_TYPE_SKCIPHER)
			crypto_unregister_skcipher(&safexcel_algs[i]->alg.skcipher);
		else if (safexcel_algs[i]->type == SAFEXCEL_ALG_TYPE_AEAD)
			crypto_unregister_aead(&safexcel_algs[i]->alg.aead);
		else
			crypto_unregister_ahash(&safexcel_algs[i]->alg.ahash);
	}
}

static void safexcel_configure(struct safexcel_crypto_priv *priv)
{
	u32 mask, pedepth;

	/* for now, just configure all PEs the HW has ... */
	priv->config.pes = priv->hwnumpes;

	if (max_rings < 0) {
		dev_err(priv->dev, "Param max_rings must be >1! Assuming minimum of 1.\n");
		max_rings = 1;
	}

	/* number of rings to use can be limited by param */
	priv->config.rings = min_t(u32, priv->hwnumrings, max_rings);
	/* and by the number of ring AIC's, as we need 1 per ring we manage! */
	priv->config.rings = min_t(u32, priv->config.rings, priv->hwnumraic);

	if (priv->feat_flags & EIP197_OCE)
		pedepth = EIP197_PKTS_PER_PE_OCE;
	else
		pedepth = EIP197_PKTS_PER_PE;
	if (ring_entries == 0) {
		/* Auto-configure */
		/* Total # of descr required divided by # of rings in use */
		priv->config.ring_entries =
		  ((EIP197_AVG_DESC_PER_PKT * pedepth) +
		   priv->config.rings - 1) /
		  priv->config.rings;
	} else {
		/* Take param override */
		priv->config.ring_entries = ring_entries;
	}
	if (queue_entries == 0) {
		/* Auto-configure */
		/* PE depth divided by # of rings in use */
		priv->config.queue_entries =
		  (pedepth + priv->config.rings - 1) /
		  priv->config.rings;
	} else {
		/* Take param override */
		priv->config.queue_entries = queue_entries;
	}

	mask = BIT(priv->hwdataw) - 1;

	priv->config.cd_size   = EIP197_CD64_FETCH_SIZE;
	/* round up offset to full interface words, then convert to bytes */
	priv->config.cd_offset = ((priv->config.cd_size + mask) & ~mask) << 2;

	/* res token is behind the descr, but ofs must be rounded to buswidth */
	priv->config.res_offset = (EIP197_RD64_FETCH_SIZE + mask) & ~mask;
	/* now the size of the descr is this 1st part plus the result struct */
	priv->config.rd_size    = priv->config.res_offset +
				  EIP197_RD64_RESULT_SIZE;
	/* round up offset, to full interface words */
	priv->config.rd_offset = (priv->config.rd_size + mask) & ~mask;
	if (EIP197_RD_OWN_WORD) {
		/* Another another *bus width*(!) word for the ownership word */
		priv->config.rd_offset += (mask + 1);
	}

	/* Need offset in bytes from here onwards */
	priv->config.rd_offset = priv->config.rd_offset << 2;
	if (priv->ctxt_flags & DEVICE_IS_PCI) {
		/*
		 * For PCI devices, round up offset further to the cacheline
		 * size to avoid expensive read-modify-write operations on the
		 * CPU cache when updating.
		 */
		mask = cache_line_size() - 1;
		priv->config.rd_offset = (priv->config.rd_offset + mask) &
					 ~mask;
	}
	/* Need result offset in bytes */
	priv->config.res_offset = priv->config.res_offset << 2;
	/* Ownership word is the last dword in the RD memory range (formally) */
	priv->config.own_offset = priv->config.rd_offset - 4;
}

static void safexcel_init_register_offsets(struct safexcel_crypto_priv *priv)
{
	struct safexcel_register_offsets *offsets = &priv->offsets;

	if (priv->feat_flags & HW_IS_EIP197) {
		offsets->hia_aic	= EIP197_HIA_AIC_BASE;
		offsets->hia_aic_g	= EIP197_HIA_AIC_G_BASE;
		offsets->hia_aic_r	= EIP197_HIA_AIC_R_BASE;
		offsets->hia_aic_xdr	= EIP197_HIA_AIC_xDR_BASE;
		offsets->hia_dfe	= EIP197_HIA_DFE_BASE;
		offsets->hia_dfe_thr	= EIP197_HIA_DFE_THR_BASE;
		offsets->hia_dse	= EIP197_HIA_DSE_BASE;
		offsets->hia_dse_thr	= EIP197_HIA_DSE_THR_BASE;
		offsets->hia_gen_cfg	= EIP197_HIA_GEN_CFG_BASE;
		offsets->pe		= EIP197_PE_BASE;
		offsets->global		= EIP197_GLOBAL_BASE;
	} else {
		offsets->hia_aic	= EIP97_HIA_AIC_BASE;
		offsets->hia_aic_g	= EIP97_HIA_AIC_G_BASE;
		offsets->hia_aic_r	= EIP97_HIA_AIC_R_BASE;
		offsets->hia_aic_xdr	= EIP97_HIA_AIC_xDR_BASE;
		offsets->hia_dfe	= EIP97_HIA_DFE_BASE;
		offsets->hia_dfe_thr	= EIP97_HIA_DFE_THR_BASE;
		offsets->hia_dse	= EIP97_HIA_DSE_BASE;
		offsets->hia_dse_thr	= EIP97_HIA_DSE_THR_BASE;
		offsets->hia_gen_cfg	= EIP97_HIA_GEN_CFG_BASE;
		offsets->pe		= EIP97_PE_BASE;
		offsets->global		= EIP97_GLOBAL_BASE;
	}
}

static void safexcel_hw_reset_rings(struct safexcel_crypto_priv *priv)
{
	int i;

	for (i = 0; i < priv->config.rings; i++) {
		/* clear any pending interrupt */
		writel(GENMASK(5, 0),
		       EIP197_HIA_CDR(priv, i) + EIP197_HIA_xDR_STAT);
		writel(GENMASK(7, 0),
		       EIP197_HIA_RDR(priv, i) + EIP197_HIA_xDR_STAT);

		/* Reset the CDR base address */
		writel(0, EIP197_HIA_CDR(priv, i) +
			  EIP197_HIA_xDR_RING_BASE_ADDR_LO);
		writel(0, EIP197_HIA_CDR(priv, i) +
			  EIP197_HIA_xDR_RING_BASE_ADDR_HI);

		/* Reset the RDR base address */
		writel(0, EIP197_HIA_RDR(priv, i) +
			  EIP197_HIA_xDR_RING_BASE_ADDR_LO);
		writel(0, EIP197_HIA_RDR(priv, i) +
			  EIP197_HIA_xDR_RING_BASE_ADDR_HI);
	}
}

/*
 * Generic part of probe routine, shared by platform and PCI driver
 *
 * Assumes IO resources have been mapped, private data mem has been allocated,
 * clocks have been enabled, device pointer has been assigned etc.
 *
 */
static int safexcel_probe_generic(struct safexcel_crypto_priv *priv)
{

	u32 version, val, mask, peid;
	u32 hwopt, hiaopt;

	/* Determine engine type & endianness and configure byte swap */

	dev_info(priv->dev, "Probing for EIP97/EIP197 at base address %p\n",
		 priv->base);

	/*
	 * First try the EIP97 HIA version regs
	 * For the EIP197, this is guaranteed to NOT return any of the test
	 * values
	 */

	priv->feat_flags = 0; /* Initialize feature flags, assuming EIP97 HW */

	version = readl(priv->base + EIP97_HIA_AIC_BASE + EIP197_HIA_VERSION);

	mask = 0;  /* do not swap */
	peid = 97;
	if ((version & 0xffff) == EIP197_HIA_VERSION_LE) {
		priv->hiaver = (version>>16)&0xfff;
		dev_info(priv->dev, "Detected EIP97 HIA, endianness is OK\n");
	} else if (((version >> 16) & 0xffff) == EIP197_HIA_VERSION_BE) {
		/* read back byte-swapped, so complement byte swap bits */
		mask = EIP197_MST_CTRL_BYTE_SWAP_BITS;
		priv->hiaver = ((version&0xf0)<<4)|((version>>4)&0xf0)|
			       ((version>>12)&0xf);
		dev_info(priv->dev, "Detected EIP97 HIA, endian swapped\n");
	} else {
		/* So it wasn't an EIP97 ... maybe it's an EIP197? */
		version = readl(priv->base + EIP197_HIA_AIC_BASE +
				EIP197_HIA_VERSION);
		if ((version & 0xffff) == EIP197_HIA_VERSION_LE) {
			priv->hiaver = (version>>16)&0xfff;
			priv->feat_flags = HW_IS_EIP197;
			peid = 197;
			dev_info(priv->dev, "Detected EIP197 HIA, endianness is OK\n");
		} else if (((version >> 16) & 0xffff) ==
			   EIP197_HIA_VERSION_BE) {
			/* read back byte-swapped, so complement swap bits */
			mask = EIP197_MST_CTRL_BYTE_SWAP_BITS;
			priv->hiaver = ((version&0xf0)<<4)|((version>>4)&0xf0)|
				       ((version>>12)&0xf);
			priv->feat_flags = HW_IS_EIP197;
			peid = 197;
			dev_info(priv->dev, "Detected EIP197 HIA, endian swapped\n");
		} else {
			dev_err(priv->dev, "Both EIP97 and EIP197 HIA not detected, probing failed\n");
			return -ENODEV;
		}
	}

	/* Now initialize the reg offsets based on the probing info so far */
	safexcel_init_register_offsets(priv);

	/*
	 * If the version info was read byte-swapped, we need to flip the device
	 * swapping Keep in mind here, though, that what we write will also be
	 * byte-swapped ...
	 */
	if (mask) {
		val = readl(EIP197_HIA_AIC(priv) + EIP197_HIA_MST_CTRL);
		val = val ^ (mask>>24); /* toggle byte swap bits if required */
		writel(val, EIP197_HIA_AIC(priv) + EIP197_HIA_MST_CTRL);
	}

	/*
	 * We're not done probing yet! We may fall through to here if no HIA was
	 * found at all/ So, with the endianness presumably correct now and the
	 * offsets setup, *really* probe for the EIP97/EIP197.
	 */
	version = readl(EIP197_GLOBAL(priv) + EIP197_VERSION);
	if (((priv->feat_flags & HW_IS_EIP197) &&
	     ((version & 0xffff) != EIP197_VERSION_LE)) ||
	    ((!(priv->feat_flags & HW_IS_EIP197) &&
	     ((version & 0xffff) != EIP97_VERSION_LE)))) {
		/*
		 * We did not find the device that matched our initial probing
		 * (or our initial probing failed) Report appropriate error.
		 */
		dev_err(priv->dev, "Probing for EIP97/EIP197 failed - no such device (read %08x)\n",
			version);
		return -ENODEV;
	}
	priv->hwver = (version>>16)&0xfff;
	priv->hwctg = version>>28;

	version = readl(EIP197_PE(priv) + EIP197_PE_EIP96_VERSION(0));
	if ((version & 0xffff) != EIP96_VERSION_LE) {
		dev_err(priv->dev, "Probing for EIP96 subsystem failed - no such device\n");
		return -ENODEV;
	}
	priv->pever = (version>>16)&0xfff;

	/* EIP197 only */
	if (priv->feat_flags & HW_IS_EIP197) {
		version = readl(priv->base + EIP197_CS_VERSION);
		if ((version & 0xffff) != EIP207_VERSION_LE) {
			dev_err(priv->dev, "Probing for EIP207 subsystem failed\n");
			return -ENODEV;
		}
		priv->csver = (version>>16)&0xfff;
	}

	/* Extract HW configuration options */
	hwopt = readl(EIP197_GLOBAL(priv) + EIP197_OPTIONS);
	hiaopt = readl(EIP197_HIA_AIC(priv) + EIP197_HIA_OPTIONS);

	priv->algo_flags = readl(EIP197_PE(priv) + EIP197_PE_EIP96_OPTIONS(0));
	priv->hwnumrings = hiaopt & 0xf;

	if (priv->feat_flags & HW_IS_EIP197) {
		priv->hwnumpes = (hiaopt>>4)&0x1f;
		/* Note: 0 means 32 ... */
		priv->hwnumpes = priv->hwnumpes+((priv->hwnumpes == 0)<<5);
		priv->hwdataw  = (hiaopt>>25)&7;
		priv->hwcfsize = ((hiaopt>>9)&7)+4;
		priv->hwrfsize = ((hiaopt>>12)&7)+4;

		if (hiaopt&EIP197_HIA_OPT_HAS_PE_ARB)
			priv->feat_flags |= EIP197_PE_ARB;
		if (hwopt&EIP197_OPT_HAS_ICE)
			priv->feat_flags |= EIP197_ICE;
		if (hwopt&EIP197_OPT_HAS_OCE)
			priv->feat_flags |= EIP197_OCE;
		if (hwopt&EIP197_OPT_HAS_HWTB)
			priv->feat_flags |= EIP197_HWTB;
		if (hwopt&EIP197_OPT_HAS_VIRT)
			priv->feat_flags |= EIP197_VIRT;
		if (hwopt&EIP197_OPT_HAS_DRBG)
			priv->feat_flags |= EIP197_DRBG;
		if (hwopt&EIP197_OPT_HAS_FRC)
			priv->feat_flags |= EIP197_FRC_CACHE;
		if (hwopt&EIP197_OPT_HAS_TRC) {
			priv->feat_flags |= EIP197_TRC_CACHE;
			/* cache really needs to be invalidated ...*/
			priv->feat_flags |= EIP197_NEED_INV;
		}
		/* Coarse value, may be too pessimistic ... */
		priv->hwipbsize = 4<<((hwopt>>9)&0xf);
	} else {
		priv->hwnumpes = 1; /* EIP97 always has just 1 pipe */
		priv->hwdataw  = (hiaopt>>25)&3;
		priv->hwcfsize = (hiaopt>>8)&0xf;
		priv->hwrfsize = (hiaopt>>12)&0xf;
	}

	/* Scan for ring AIC's */
	for (val = 0; val < EIP197_MAX_RING_AIC; val++) {
		version = readl(EIP197_HIA_AIC_R(priv) +
				EIP197_HIA_AIC_R_VERSION(val));
		if ((version & 0xffff) != EIP201_VERSION_LE)
			break;
	}
	priv->hwnumraic = val;

	/* Print some info to the system log */
	dev_info(priv->dev, "Successfully detected Inside Secure EIP%d packetengine HW%d.%d.%d(%d)\n",
		peid, (priv->hwver>>8), ((priv->hwver>>4)&0xf),
		(priv->hwver&0xf), priv->hwctg);
	dev_info(priv->dev, " EIP96 HW%d.%d.%d, EIP202 HW%d.%d.%d, EIP207 HW%d.%d.%d\n",
		(priv->pever>>8),  ((priv->pever>>4)&0xf),  (priv->pever&0xf),
		(priv->hiaver>>8), ((priv->hiaver>>4)&0xf), (priv->hiaver&0xf),
		(priv->csver>>8),  ((priv->csver>>4)&0xf),  (priv->csver&0xf));
	dev_info(priv->dev, " HW has %d processing pipes, %d rings and %d ring AICs, dwidth %d bits, cfsize %d words, rfsize %d words\n",
		priv->hwnumpes, priv->hwnumrings, priv->hwnumraic,
		(1<<(priv->hwdataw+5)), (1<<priv->hwcfsize),
		(1<<priv->hwrfsize));
	dev_info(priv->dev, " PEARB=%d, ICE=%d, OCE=%d, HWTB=%d, VIRT=%d, DRBG=%d, FRC=%d, TRC=%d\n",
		((priv->feat_flags&EIP197_PE_ARB) != 0),
		((priv->feat_flags&EIP197_ICE) != 0),
		((priv->feat_flags&EIP197_OCE) != 0),
		((priv->feat_flags&EIP197_HWTB) != 0),
		((priv->feat_flags&EIP197_VIRT) != 0),
		((priv->feat_flags&EIP197_DRBG) != 0),
		((priv->feat_flags&EIP197_FRC_CACHE) != 0),
		((priv->feat_flags&EIP197_TRC_CACHE) != 0));
	val = 0;
	if (hwopt&EIP197_OPT_HAS_OCE) {
		val = (hwopt>>20)&15;
		if (val)
			val = 1<<val;
		else
			val = 65536;
	}
	dev_info(priv->dev, " Buffers: itbuf %d, idbuf %d, mdbuf %d, otbuf %d, odbuf %d",
		 (1<<(((hwopt>>6)&7)+3)), (1<<((hwopt>>9)&15)),
		 val,
		 (1<<(((hwopt>>13)&7)+3)), (1<<((hwopt>>16)&15)));

	if (priv->algo_flags & ALGO_ARC4)
		dev_info(priv->dev, " HW supports ARC4 stream cipher\n");
	if (priv->algo_flags & ALGO_DES)
		dev_info(priv->dev, " HW supports DES & 3DES block ciphers\n");
	if (priv->algo_flags & ALGO_AES_XTS)
		dev_info(priv->dev, " HW supports AES block cipher, with XTS support\n");
	else if (priv->algo_flags && ALGO_AES)
		dev_info(priv->dev, " HW supports AES block cipher (no XTS)\n");
	if (priv->algo_flags & ALGO_CHACHA20)
		dev_info(priv->dev, " HW supports CHACHA20 stream cipher\n");
	if (priv->algo_flags & ALGO_SM4)
		dev_info(priv->dev, " HW supports SM4 block cipher\n");
	if (priv->algo_flags & ALGO_BC0)
		dev_info(priv->dev, " HW supports external block cipher\n");
	if (priv->algo_flags & ALGO_WIRELESS)
		dev_info(priv->dev, " HW supports SNOW3G, ZUC and Kasumi ciphers (incl. auth)\n");
	if (priv->algo_flags & ALGO_MD5)
		dev_info(priv->dev, " HW supports MD5 hash and HMAC\n");
	if (priv->algo_flags & ALGO_SHA1)
		dev_info(priv->dev, " HW supports SHA1 hash and HMAC\n");
	if (priv->algo_flags & ALGO_SHA2_256)
		dev_info(priv->dev, " HW supports SHA2-224 and SHA2-256 hash and HMAC\n");
	if (priv->algo_flags & ALGO_SHA2_512)
		dev_info(priv->dev, " HW supports SHA2-384 and SHA2-512 hash and HMAC\n");
	if (priv->algo_flags & ALGO_SHA3)
		dev_info(priv->dev, " HW supports SHA3 hash, KHASH and HMAC\n");
	if (priv->algo_flags & ALGO_XCBC_MAC)
		dev_info(priv->dev, " HW supports AES-XCBC-MAC, AES-CBC-MAC and AES-CMAC\n");
	if (priv->algo_flags & ALGO_GHASH)
		dev_info(priv->dev, " HW supports GHASH hash (i.e. for AES-GCM and AES-GMAC)\n");
	if (priv->algo_flags & ALGO_SM3)
		dev_info(priv->dev, " HW supports SM3 hash and HMAC\n");
	if (priv->algo_flags & ALGO_POLY1305)
		dev_info(priv->dev, " HW supports POLY1305 MAC (i.e. for Chacha20/Poly1305)\n");

	if (priv->hwnumraic < 1) {
		dev_err(priv->dev, "No ring AIC's found - this driver needs at least 1!\n");
		return -ENODEV;
	}

	priv->context_pool = dmam_pool_create("safexcel-context", priv->dev,
					      sizeof(struct safexcel_context_record),
					      1, 0);
	if (!priv->context_pool)
		return -ENOMEM;

	safexcel_configure(priv);

	/*
	 * Note: still need to register ring IRQ's (platform specific!)
	 *       also still need to init the EIP(1)97 and register algo's
	 *       (deferred until after IRQ registration)
	 */

	return 0;
}

/*
 *
 * for Device Tree platform driver
 *
 */

static int safexcel_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	struct safexcel_crypto_priv *priv;
	int i, ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;
	priv->ctxt_flags = (enum safexcel_eip_context)of_device_get_match_data(dev);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	priv->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(priv->base)) {
		dev_err(dev, "failed to get resource\n");
		return PTR_ERR(priv->base);
	}

	priv->clk = devm_clk_get(&pdev->dev, NULL);
	ret = PTR_ERR_OR_ZERO(priv->clk);
	/* The clock isn't mandatory */
	if  (ret != -ENOENT) {
		if (ret)
			return ret;

		ret = clk_prepare_enable(priv->clk);
		if (ret) {
			dev_err(dev, "unable to enable clk (%d)\n", ret);
			return ret;
		}
	}

	priv->reg_clk = devm_clk_get(&pdev->dev, "reg");
	ret = PTR_ERR_OR_ZERO(priv->reg_clk);
	/* The clock isn't mandatory */
	if  (ret != -ENOENT) {
		if (ret)
			goto err_core_clk;

		ret = clk_prepare_enable(priv->reg_clk);
		if (ret) {
			dev_err(dev, "unable to enable reg clk (%d)\n", ret);
			goto err_core_clk;
		}
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret)
		goto err_reg_clk;

	/* Generic EIP97/EIP197 device probing */
	ret = safexcel_probe_generic(priv);
	if (ret)
		goto err_reg_clk;

	/* Register the ring IRQ handlers and configure the rings */
	priv->ring = devm_kcalloc(dev, priv->config.rings,
				  sizeof(*priv->ring),
				  GFP_KERNEL);
	if (!priv->ring) {
		ret = -ENOMEM;
		goto err_reg_clk;
	}

	for (i = 0; i < priv->config.rings; i++) {
		char irq_name[6] = {0}; /* "ringX\0" */
		char wq_name[9] = {0}; /* "wq_ringX\0" */
		int irq;
		struct safexcel_ring_irq_data *ring_irq;

		ret = safexcel_init_ring_descriptors(priv,
						     &priv->ring[i].cdr,
						     &priv->ring[i].rdr);
		if (ret)
			goto err_reg_clk;

		priv->ring[i].rdr_req = devm_kcalloc(dev,
			priv->config.ring_entries,
			sizeof(priv->ring[i].rdr_req),
			GFP_KERNEL);
		if (!priv->ring[i].rdr_req) {
			ret = -ENOMEM;
			goto err_reg_clk;
		}

		ring_irq = devm_kzalloc(dev, sizeof(*ring_irq), GFP_KERNEL);
		if (!ring_irq) {
			ret = -ENOMEM;
			goto err_reg_clk;
		}

		ring_irq->priv = priv;
		ring_irq->ring = i;

		snprintf(irq_name, 6, "ring%d", i);
		irq = safexcel_request_plf_ring_irq(pdev, irq_name, NULL,
						    safexcel_irq_ring_thread,
						    ring_irq);
		if (irq < 0) {
			ret = irq;
			goto err_reg_clk;
		}

		priv->ring[i].work_data.priv = priv;
		priv->ring[i].work_data.ring = i;
		INIT_WORK(&priv->ring[i].work_data.work, safexcel_dequeue_work);

		snprintf(wq_name, 9, "wq_ring%d", i);
		priv->ring[i].workqueue = create_singlethread_workqueue(wq_name);
		if (!priv->ring[i].workqueue) {
			ret = -ENOMEM;
			goto err_reg_clk;
		}

		priv->ring[i].requests = 0;
		priv->ring[i].busy = false;

		crypto_init_queue(&priv->ring[i].queue,
				  priv->config.queue_entries);

		spin_lock_init(&priv->ring[i].lock);
		spin_lock_init(&priv->ring[i].queue_lock);
	}

	atomic_set(&priv->ring_used, 0);

	ret = safexcel_hw_init(priv);
	if (ret) {
		dev_err(dev, "EIP h/w init failed (%d)\n", ret);
		goto err_reg_clk;
	}

	ret = safexcel_register_algorithms(priv);
	if (ret) {
		dev_err(dev, "Failed to register algorithms (%d)\n", ret);
		goto err_reg_clk;
	}

	platform_set_drvdata(pdev, priv);

	return 0;

err_reg_clk:
	clk_disable_unprepare(priv->reg_clk);
err_core_clk:
	clk_disable_unprepare(priv->clk);
	return ret;
}

static int safexcel_remove(struct platform_device *pdev)
{
	struct safexcel_crypto_priv *priv = platform_get_drvdata(pdev);
	int i;

	safexcel_unregister_algorithms(priv);
	safexcel_hw_reset_rings(priv);

	clk_disable_unprepare(priv->clk);

	for (i = 0; i < priv->config.rings; i++)
		destroy_workqueue(priv->ring[i].workqueue);

	return 0;
}

static const struct of_device_id safexcel_of_match_table[] = {
	{
		.compatible = "inside-secure,safexcel-eip97ies",
		.data = (void *)MRVL_EIP97IES,
	},
	{
		.compatible = "inside-secure,safexcel-eip197b",
		.data = (void *)MRVL_EIP197B,
	},
	{
		.compatible = "inside-secure,safexcel-eip197d",
		.data = (void *)MRVL_EIP197D,
	},
	{
		/* Deprecated. Kept for backward compatibility. */
		.compatible = "inside-secure,safexcel-eip97",
		.data = (void *)MRVL_EIP97IES,
	},
	{
		/* Deprecated. Kept for backward compatibility. */
		.compatible = "inside-secure,safexcel-eip197",
		.data = (void *)MRVL_EIP197B,
	},
	{},
};


static struct platform_driver  crypto_safexcel = {
	.probe		= safexcel_probe,
	.remove		= safexcel_remove,
	.driver		= {
		.name	= "crypto-safexcel",
		.of_match_table = safexcel_of_match_table,
	},
};

/*
 *
 * PCIE devices - i.e. Inside Secure development boards
 *
 */

static int crypto_is_pci_probe(struct pci_dev *pdev,
	 const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct safexcel_crypto_priv *priv;
	void __iomem *pciebase;
	int rc, i, msibase;
	u32 val;

	dev_info(dev, "Probing PCIE device: vendor %04x, device %04x, subv %04x, subdev %04x, ctxt %lx\n",
			ent->vendor, ent->device, ent->subvendor,
			ent->subdevice, ent->driver_data);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		dev_err(dev, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	priv->dev = dev;
	priv->ctxt_flags = (enum safexcel_eip_context)ent->driver_data;

	pci_set_drvdata(pdev, priv);

	/* enable the device */
	rc = pcim_enable_device(pdev);
	if (rc) {
		dev_err(dev, "pci_enable_device() failed\n");
		return rc;
	}

	/* take ownership of PCI BAR0 */
	rc = pcim_iomap_regions(pdev, 1, "crypto_safexcel");
	if (rc) {
		dev_err(dev, "pcim_iomap_regions() failed for BAR0\n");
		return rc;
	}
	priv->base = pcim_iomap_table(pdev)[0];

	/* Assume we have separate MSI vectors for global and rings */
	msibase = 1;

	if (priv->ctxt_flags & XILINX_PCIE) {
		dev_info(dev, "Device identified as FPGA based development board - applying HW reset\n");

		msibase = 0; /* Older devboards map everything to MSI #0 ... */
		rc = pcim_iomap_regions(pdev, 4, "crypto_safexcel");
		if (!rc) {
			pciebase = pcim_iomap_table(pdev)[2];
			val = readl(pciebase + XILINX_IRQ_BLOCK_ID);
			if ((val >> 16) == 0x1fc2) {
				dev_info(dev, "Detected Xilinx PCIE IRQ block version %d, multiple MSI support enabled\n",
					 (val & 0xff));

				/* Setup identity map mapping irq #n to MSI#n */
				writel(0x03020100,
				       pciebase + XILINX_USER_VECT_LUT0);
				writel(0x07060504,
				       pciebase + XILINX_USER_VECT_LUT1);
				writel(0x0b0a0908,
				       pciebase + XILINX_USER_VECT_LUT2);
				writel(0x0f0e0d0c,
				       pciebase + XILINX_USER_VECT_LUT3);

				/* Enable all device interrupts */
				writel(GENMASK(31, 0),
				       pciebase + XILINX_USER_INT_ENB_MASK);
				/* We have unique MSI vecs for the rings now */
				msibase = 1;
			} else {
				dev_info(dev, "Unrecognised IRQ block identifier %x\n",
					 val);
			}
		}
		if (msibase == 0) {
			/*
			 * Older dev board. All interrupts mapped to MSI #0
			 * Therefore, we can only support 1 ring for now!
			 */
			dev_info(dev, "Xilinx PCIE IRQ block not detected, using only MSI #0 with 1 ring\n");
			max_rings = 1;
		}

		/* HW reset FPGA dev board */
		writel(1, priv->base + XILINX_GPIO_BASE); // assert reset
		wmb(); /* maintain strict ordering for accesses here */
		writel(0, priv->base + XILINX_GPIO_BASE); // deassert reset
		wmb(); /* maintain strict ordering for accesses here */
	}

	/* enable bus mastering */
	pci_set_master(pdev);

	/* Generic EIP97/EIP197 device probing */
	rc = safexcel_probe_generic(priv);
	if (rc)
		return rc;

	/*
	 * Request MSI vectors for global + 1 per ring -
	 * or just 1 for older dev images
	 */
	rc = pci_alloc_irq_vectors(pdev, msibase + priv->config.rings,
				   msibase + priv->config.rings,
				   PCI_IRQ_MSI|PCI_IRQ_MSIX);
	if (rc < 0) {
		dev_err(dev, "Failed to allocate PCI MSI interrupts\n");
		return rc;
	}

	/* Register the ring IRQ handlers and configure the rings */
	priv->ring = devm_kcalloc(dev, priv->config.rings,
				  sizeof(*priv->ring),
				  GFP_KERNEL);
	if (!priv->ring) {
		dev_err(dev, "Failed to allocate ring memory\n");
		return -ENOMEM;
	}

	for (i = 0; i < priv->config.rings; i++) {
		char wq_name[9] = {0};
		int irq;
		struct safexcel_ring_irq_data *ring_irq;

		rc = safexcel_init_ring_descriptors(priv,
						     &priv->ring[i].cdr,
						     &priv->ring[i].rdr);
		if (rc) {
			dev_err(dev, "Failed to initialize rings\n");
			return rc;
		}

		priv->ring[i].rdr_req = devm_kcalloc(dev,
			priv->config.ring_entries,
			sizeof(priv->ring[i].rdr_req),
			GFP_KERNEL);
		if (!priv->ring[i].rdr_req) {
			dev_err(dev, "Failed to allocate RDR async request queue for ring %d\n",
				i);
			return -ENOMEM;
		}

		ring_irq = devm_kzalloc(dev, sizeof(*ring_irq), GFP_KERNEL);
		if (!ring_irq) {
			dev_err(dev, "Failed to allocate IRQ data for ring %d\n",
				i);
			return -ENOMEM;
		}

		ring_irq->priv = priv;
		ring_irq->ring = i;

		irq = safexcel_request_pci_ring_irq(pdev, msibase + i, NULL,
						    safexcel_irq_ring_thread,
						    ring_irq);
		if (irq < 0) {
			dev_err(dev, "Failed to get IRQ ID for ring %d\n", i);
			return irq;
		}

		priv->ring[i].work_data.priv = priv;
		priv->ring[i].work_data.ring = i;
		INIT_WORK(&priv->ring[i].work_data.work, safexcel_dequeue_work);

		snprintf(wq_name, 9, "wq_ring%d", i);
		priv->ring[i].workqueue = create_singlethread_workqueue(wq_name);
		if (!priv->ring[i].workqueue) {
			dev_err(dev, "Failed to create work queue for ring %d\n",
				i);
			return -ENOMEM;
		}
		priv->ring[i].requests = 0;
		priv->ring[i].busy = false;
		crypto_init_queue(&priv->ring[i].queue,
				  priv->config.queue_entries);

		spin_lock_init(&priv->ring[i].lock);
		spin_lock_init(&priv->ring[i].queue_lock);
	}

	atomic_set(&priv->ring_used, 0);

	rc = safexcel_hw_init(priv);
	if (rc) {
		dev_err(dev, "EIP(1)97 h/w init failed (%d)\n", rc);
		return rc;
	}

	rc = safexcel_register_algorithms(priv);
	if (rc) {
		dev_err(dev, "Failed to register algorithms (%d)\n", rc);
		return rc;
	}

	return 0;
}

void crypto_is_pci_remove(struct pci_dev *pdev)
{
	struct safexcel_crypto_priv *priv = pci_get_drvdata(pdev);
	int i;

	safexcel_unregister_algorithms(priv);

	for (i = 0; i < priv->config.rings; i++)
		destroy_workqueue(priv->ring[i].workqueue);

	safexcel_hw_reset_rings(priv);
}

static const struct pci_device_id crypto_is_pci_ids[] = {
	{
		.vendor = 0x10ee,
		.device = 0x9038,
		.subvendor = 0x16ae,
		.subdevice = 0xc522,
		.class = 0x00000000,
		.class_mask = 0x00000000,
		.driver_data = XILINX_PCIE | DEVICE_IS_PCI,
	},
	{},
};

MODULE_DEVICE_TABLE(pci, crypto_is_pci_ids);

static struct pci_driver crypto_is_pci_driver = {
	.name          = "crypto-safexcel",
	.id_table      = crypto_is_pci_ids,
	.probe         = crypto_is_pci_probe,
	.remove        = crypto_is_pci_remove,
};

static int __init crypto_is_init(void)
{
	int rc;
	/* Register platform driver */
	platform_driver_register(&crypto_safexcel);

	/* Register PCI driver */
	rc = pci_register_driver(&crypto_is_pci_driver);
	return 0;
}

static void __exit crypto_is_exit(void)
{
	/* Unregister platform driver */
	platform_driver_unregister(&crypto_safexcel);

	/* Unregister PCI driver if successfully registered before */
	pci_unregister_driver(&crypto_is_pci_driver);
}

module_init(crypto_is_init);
module_exit(crypto_is_exit);

MODULE_AUTHOR("Antoine Tenart <antoine.tenart@free-electrons.com>");
MODULE_AUTHOR("Ofer Heifetz <oferh@marvell.com>");
MODULE_AUTHOR("Igal Liberman <igall@marvell.com>");
MODULE_AUTHOR("Pascal van Leeuwen <pvanleeuwen@insidesecure.com>");
MODULE_DESCRIPTION("Support for SafeXcel cryptographic engines: EIP97 & EIP197");
MODULE_LICENSE("GPL v2");
