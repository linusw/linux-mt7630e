/*	Copyright (C) 2009 - 2010 Ivo van Doorn <IvDoorn@gmail.com>
 *	Copyright (C) 2009 Alban Browaeys <prahal@yahoo.com>
 *	Copyright (C) 2009 Felix Fietkau <nbd@openwrt.org>
 *	Copyright (C) 2009 Luis Correia <luis.f.correia@gmail.com>
 *	Copyright (C) 2009 Mattias Nissler <mattias.nissler@gmx.de>
 *	Copyright (C) 2009 Mark Asselstine <asselsm@gmail.com>
 *	Copyright (C) 2009 Xose Vazquez Perez <xose.vazquez@gmail.com>
 *	Copyright (C) 2009 Bart Zolnierkiewicz <bzolnier@gmail.com>
 *	<http://rt2x00.serialmonkey.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*	Module: rt2800mmio
 *	Abstract: rt2800 MMIO device routines.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>

#include "rt2x00.h"
#include "rt2x00mmio.h"
#include "rt2800.h"
#include "rt2800lib.h"
#include "rt2800mmio.h"

void MT_2800pci_hex_dump(char *str, unsigned char *pSrcBufVA, u32 SrcBufLen);

/*
 * TX descriptor initialization
 */
__le32 *rt2800mmio_get_txwi(struct queue_entry *entry)
{
	return (__le32 *) entry->skb->data;
}
EXPORT_SYMBOL_GPL(rt2800mmio_get_txwi);

void rt2800mmio_write_tx_desc(struct queue_entry *entry,
			      struct txentry_desc *txdesc)
{
	struct skb_frame_desc *skbdesc = get_skb_frame_desc(entry->skb);
	struct queue_entry_priv_mmio *entry_priv = entry->priv_data;
	struct rt2x00_dev *rt2x00dev = entry->queue->rt2x00dev;
	__le32 *txd = entry_priv->desc;
	u32 word;
	const unsigned int txwi_size = entry->queue->winfo_size;
	TXD_STRUC *pTxD;
	TXINFO_STRUC *pTxInfo;
	//printk("==>rt2800pci_write_tx_desc\n");

	pTxD = (TXD_STRUC *) entry_priv->desc;
	pTxInfo = (TXINFO_STRUC *)(entry_priv->desc + sizeof(TXD_STRUC));
	memset(pTxD, 0, 16);

	/*
	 * The buffers pointed by SD_PTR0/SD_LEN0 and SD_PTR1/SD_LEN1
	 * must contains a TXWI structure + 802.11 header + padding + 802.11
	 * data. We choose to have SD_PTR0/SD_LEN0 only contains TXWI and
	 * SD_PTR1/SD_LEN1 contains 802.11 header + padding + 802.11
	 * data. It means that LAST_SEC0 is always 0.
	 */

	/*
	 * Initialize TX descriptor
	 */
	if (rt2x00_rt(rt2x00dev, MT7630))
	{
		struct _TXINFO_NMAC_PKT *nmac_info;

		pTxD->SDPtr0 = skbdesc->skb_dma;
		pTxD->SDLen0 = TXWI_DESC_SIZE_5WORDS;	/* include padding*/
		pTxD->SDPtr1 = skbdesc->skb_dma + TXWI_DESC_SIZE_5WORDS;
		pTxD->SDLen1 = entry->skb->len;
		pTxD->LastSec0 = 0;
		pTxD->LastSec1 =  !test_bit(ENTRY_TXD_MORE_FRAG, &txdesc->flags);
		//pTxD->DMADONE= 0;
		pTxD->Burst= test_bit(ENTRY_TXD_BURST, &txdesc->flags);
		nmac_info = (struct _TXINFO_NMAC_PKT *)pTxInfo;
		nmac_info->pkt_80211 = 1;
		nmac_info->info_type = 0;
		nmac_info->d_port = 0;
		pTxInfo->TxInfoWIV =  !test_bit(ENTRY_TXD_ENCRYPT_IV, &txdesc->flags);
		pTxInfo->TxInfoQSEL = 2;
		pTxD->DMADONE= 0;
		//return;
	} else {
	word = 0;
	rt2x00_set_field32(&word, TXD_W0_SD_PTR0, skbdesc->skb_dma);
	rt2x00_desc_write(txd, 0, word);

	word = 0;
	rt2x00_set_field32(&word, TXD_W1_SD_LEN1, entry->skb->len);
	rt2x00_set_field32(&word, TXD_W1_LAST_SEC1,
			   !test_bit(ENTRY_TXD_MORE_FRAG, &txdesc->flags));
	rt2x00_set_field32(&word, TXD_W1_BURST,
			   test_bit(ENTRY_TXD_BURST, &txdesc->flags));
	rt2x00_set_field32(&word, TXD_W1_SD_LEN0, txwi_size);
	rt2x00_set_field32(&word, TXD_W1_LAST_SEC0, 0);
	rt2x00_set_field32(&word, TXD_W1_DMA_DONE, 0);
	rt2x00_desc_write(txd, 1, word);

	word = 0;
	rt2x00_set_field32(&word, TXD_W2_SD_PTR1,
			   skbdesc->skb_dma + txwi_size);
	rt2x00_desc_write(txd, 2, word);

	word = 0;
	rt2x00_set_field32(&word, TXD_W3_WIV,
			   !test_bit(ENTRY_TXD_ENCRYPT_IV, &txdesc->flags));
	rt2x00_set_field32(&word, TXD_W3_QSEL, 2);
	rt2x00_desc_write(txd, 3, word);
	}
	/*
	 * Register descriptor details in skb frame descriptor.
	 */
	skbdesc->desc = txd;
	skbdesc->desc_len = TXD_DESC_SIZE;
}
EXPORT_SYMBOL_GPL(rt2800mmio_write_tx_desc);

void MT_2800pci_hex_dump(char *str, unsigned char *pSrcBufVA, u32 SrcBufLen)
{
	unsigned char *pt;
	int x;
	pt = pSrcBufVA;
	printk("%s: %p, len = %d\n", str, pSrcBufVA, SrcBufLen);
	for (x = 0; x < SrcBufLen; x++) {
		if (x % 16 == 0)
			printk("0x%04x : ", x);
		printk("%02x ", ((unsigned char)pt[x]));
		if (x % 16 == 15)
			printk("\n");
	}
	printk("\n");
}

/*
 * RX control handlers
 */
void rt2800mmio_fill_rxdone(struct queue_entry *entry,
			    struct rxdone_entry_desc *rxdesc)
{
	struct queue_entry_priv_mmio *entry_priv = entry->priv_data;
	__le32 *rxd = entry_priv->desc;
	u32 word;
	struct data_queue *queue;
	struct rt2x00_dev *rt2x00dev;
	RXINFO_STRUC *pRxInfo;
	RXFCE_INFO *pRxFceInfo;
	//printk("===>%s:MT7630\n", __FUNCTION__);
	queue = entry->queue;
	rt2x00dev = queue->rt2x00dev;

	if (rt2x00_rt(rt2x00dev, MT7630))
	{
			//MT_2800pci_hex_dump("rxd", rxd, 16);
			unsigned char hw_rx_info[16];
			//unsigned char hw_fce[4];
			//__le32 *destrxd = NULL;

			//memcpy(&hw_rx_info[0], rxd,12);
			memcpy(&hw_rx_info[0], rxd,16);
			//memcpy(&hw_fce[0], rxd+12,4);
			pRxFceInfo = (RXFCE_INFO *) &hw_rx_info[12];
			//destrxd = (__le32 *) entry->skb->data; 	//woody
			//memcpy(&hw_rx_info[12], destrxd,4);
			pRxInfo = (RXINFO_STRUC *) entry->skb->data;

			//rxd = &hw_rx_info[0];
			//MT_2800pci_hex_dump("rxd", rxd, 16);
			//MT_2800pci_hex_dump("skb->data(0)", entry->skb->data, 64);
			//rt2x00_desc_read(hw_rx_info, 0, &word);
			//rt2x00_desc_read(rxd, 3, &word);

			//MT_2800pci_hex_dump("skb->data(1)", entry->skb->data, entry->skb->len);

	} else {
		rt2x00_desc_read(rxd, 3, &word);
	}

	if (rt2x00_rt(rt2x00dev, MT7630))
	{
		if (pRxInfo->Crc)
		{
			printk("crc error\n");
			rxdesc->flags |= RX_FLAG_FAILED_FCS_CRC;
		}
		rxdesc->cipher_status = pRxInfo->CipherErr;//rt2x00_get_field32(word, RXD_W3_CIPHER_ERROR);
		if (rxdesc->cipher_status)
			printk("crc RXD_W3_CIPHER_ERROR\n");

		if (pRxInfo->Decrypted) {
			vend_dbg("Decrypted\n");
			/*
			 * Hardware has stripped IV/EIV data from 802.11 frame during
			 * decryption. Unfortunately the descriptor doesn't contain
			 * any fields with the EIV/IV data either, so they can't
			 * be restored by rt2x00lib.
			 */
			rxdesc->flags |= RX_FLAG_IV_STRIPPED;
			/*
			 * The hardware has already checked the Michael Mic and has
			 * stripped it from the frame. Signal this to mac80211.
			 */
			rxdesc->flags |= RX_FLAG_MMIC_STRIPPED;

			if (rxdesc->cipher_status == RX_CRYPTO_SUCCESS)
				rxdesc->flags |= RX_FLAG_DECRYPTED;
			else if (rxdesc->cipher_status == RX_CRYPTO_FAIL_MIC)
				rxdesc->flags |= RX_FLAG_MMIC_ERROR;
		}

		if (pRxInfo->MyBss)
		{
			rxdesc->dev_flags |= RXDONE_MY_BSS;
			//printk("crc RXDONE_MY_BSS\n");
		}
		if (pRxInfo->L2PAD)
		{
			rxdesc->dev_flags |= RXDONE_L2PAD;
			//printk("crc RXDONE_L2PAD\n");
		}
		pRxInfo = NULL;
		skb_pull(entry->skb, 4);
		pRxInfo = NULL;
	}  else {
	if (rt2x00_get_field32(word, RXD_W3_CRC_ERROR))
		rxdesc->flags |= RX_FLAG_FAILED_FCS_CRC;

	/*
	 * Unfortunately we don't know the cipher type used during
	 * decryption. This prevents us from correct providing
	 * correct statistics through debugfs.
	 */
	rxdesc->cipher_status = rt2x00_get_field32(word, RXD_W3_CIPHER_ERROR);

	if (rt2x00_get_field32(word, RXD_W3_DECRYPTED)) {
		/*
		 * Hardware has stripped IV/EIV data from 802.11 frame during
		 * decryption. Unfortunately the descriptor doesn't contain
		 * any fields with the EIV/IV data either, so they can't
		 * be restored by rt2x00lib.
		 */
		rxdesc->flags |= RX_FLAG_IV_STRIPPED;

		/*
		 * The hardware has already checked the Michael Mic and has
		 * stripped it from the frame. Signal this to mac80211.
		 */
		rxdesc->flags |= RX_FLAG_MMIC_STRIPPED;

		if (rxdesc->cipher_status == RX_CRYPTO_SUCCESS)
			rxdesc->flags |= RX_FLAG_DECRYPTED;
		else if (rxdesc->cipher_status == RX_CRYPTO_FAIL_MIC)
			rxdesc->flags |= RX_FLAG_MMIC_ERROR;
	}

	if (rt2x00_get_field32(word, RXD_W3_MY_BSS))
		rxdesc->dev_flags |= RXDONE_MY_BSS;

	if (rt2x00_get_field32(word, RXD_W3_L2PAD))
		rxdesc->dev_flags |= RXDONE_L2PAD;
	}
	/*
	 * Process the RXWI structure that is at the start of the buffer.
	 */
	rt2800_process_rxwi(entry, rxdesc);
}
EXPORT_SYMBOL_GPL(rt2800mmio_fill_rxdone);

/*
 * Interrupt functions.
 */
static void rt2800mmio_wakeup(struct rt2x00_dev *rt2x00dev)
{
	struct ieee80211_conf conf = { .flags = 0 };
	struct rt2x00lib_conf libconf = { .conf = &conf };

	rt2800_config(rt2x00dev, &libconf, IEEE80211_CONF_CHANGE_PS);
}

static bool rt2800mmio_txdone_entry_check(struct queue_entry *entry, u32 status)
{
	__le32 *txwi;
	u32 word;
	int wcid, tx_wcid;

	wcid = rt2x00_get_field32(status, TX_STA_FIFO_WCID);

	txwi = rt2800_drv_get_txwi(entry);
	rt2x00_desc_read(txwi, 1, &word);
	tx_wcid = rt2x00_get_field32(word, TXWI_W1_WIRELESS_CLI_ID);

	return (tx_wcid == wcid);
}

static bool rt2800mmio_txdone_find_entry(struct queue_entry *entry, void *data)
{
	u32 status = *(u32 *)data;

	/*
	 * rt2800pci hardware might reorder frames when exchanging traffic
	 * with multiple BA enabled STAs.
	 *
	 * For example, a tx queue
	 *    [ STA1 | STA2 | STA1 | STA2 ]
	 * can result in tx status reports
	 *    [ STA1 | STA1 | STA2 | STA2 ]
	 * when the hw decides to aggregate the frames for STA1 into one AMPDU.
	 *
	 * To mitigate this effect, associate the tx status to the first frame
	 * in the tx queue with a matching wcid.
	 */
	if (rt2800mmio_txdone_entry_check(entry, status) &&
	    !test_bit(ENTRY_DATA_STATUS_SET, &entry->flags)) {
		/*
		 * Got a matching frame, associate the tx status with
		 * the frame
		 */
		entry->status = status;
		set_bit(ENTRY_DATA_STATUS_SET, &entry->flags);
		return true;
	}

	/* Check the next frame */
	return false;
}

static bool rt2800mmio_txdone_match_first(struct queue_entry *entry, void *data)
{
	u32 status = *(u32 *)data;

	/*
	 * Find the first frame without tx status and assign this status to it
	 * regardless if it matches or not.
	 */
	if (!test_bit(ENTRY_DATA_STATUS_SET, &entry->flags)) {
		/*
		 * Got a matching frame, associate the tx status with
		 * the frame
		 */
		entry->status = status;
		set_bit(ENTRY_DATA_STATUS_SET, &entry->flags);
		return true;
	}

	/* Check the next frame */
	return false;
}
static bool rt2800mmio_txdone_release_entries(struct queue_entry *entry,
					      void *data)
{
	if (test_bit(ENTRY_DATA_STATUS_SET, &entry->flags)) {
		rt2800_txdone_entry(entry, entry->status,
				    rt2800mmio_get_txwi(entry));
		return false;
	}

	/* No more frames to release */
	return true;
}

static bool rt2800mmio_txdone(struct rt2x00_dev *rt2x00dev)
{
	struct data_queue *queue;
	u32 status;
	u8 qid;
	int max_tx_done = 16;
	TX_STA_FIFO_STRUC StaFifo;

	while (kfifo_get(&rt2x00dev->txstatus_fifo, &status)) {
		vend_dbg("rt2800pci_txdone status = 0x%x\n",status);
		StaFifo.word = status;
		qid =  (UCHAR)StaFifo.field.PidType;//rt2x00_get_field32(status, TX_STA_FIFO_PID_QUEUE);
		//qid = rt2x00_get_field32(status, TX_STA_FIFO_PID_QUEUE);

		if (unlikely(qid >= QID_RX)) {
			/*
			 * Unknown queue, this shouldn't happen. Just drop
			 * this tx status.
			 */
			rt2x00_warn(rt2x00dev, "Got TX status report with unexpected pid %u, dropping\n",
				    qid);
			break;
		}

		vend_dbg("rt2800pci_txdone qid = 0x%x\n",qid);
		queue = rt2x00queue_get_tx_queue(rt2x00dev, qid);
		if (unlikely(queue == NULL)) {
			/*
			 * The queue is NULL, this shouldn't happen. Stop
			 * processing here and drop the tx status
			 */
			rt2x00_warn(rt2x00dev, "Got TX status for an unavailable queue %u, dropping\n",
				    qid);
			break;
		}

		if (unlikely(rt2x00queue_empty(queue))) {
			/*
			 * The queue is empty. Stop processing here
			 * and drop the tx status.
			 */
			rt2x00_warn(rt2x00dev, "Got TX status for an empty queue %u, dropping\n",
				    qid);
			break;
		}

		status = StaFifo.word;
		/*
		 * Let's associate this tx status with the first
		 * matching frame.
		 */
		if (!rt2x00queue_for_each_entry(queue, Q_INDEX_DONE,
						Q_INDEX, &status,
						rt2800mmio_txdone_find_entry)) {
			/*
			 * We cannot match the tx status to any frame, so just
			 * use the first one.
			 */
			if (!rt2x00queue_for_each_entry(queue, Q_INDEX_DONE,
							Q_INDEX, &status,
							rt2800mmio_txdone_match_first)) {
				rt2x00_warn(rt2x00dev, "No frame found for TX status on queue %u, dropping\n",
					    qid);
				break;
			}
		}

		/*
		 * Release all frames with a valid tx status.
		 */
		rt2x00queue_for_each_entry(queue, Q_INDEX_DONE,
					   Q_INDEX, NULL,
					   rt2800mmio_txdone_release_entries);

		if (--max_tx_done == 0)
			break;
	}

	return !max_tx_done;
}

static inline void rt2800mmio_enable_interrupt(struct rt2x00_dev *rt2x00dev,
					       struct rt2x00_field32 irq_field)
{
	u32 reg;

	/*
	 * Enable a single interrupt. The interrupt mask register
	 * access needs locking.
	 */
	spin_lock_irq(&rt2x00dev->irqmask_lock);
	rt2x00mmio_register_read(rt2x00dev, INT_MASK_CSR, &reg);
	rt2x00_set_field32(&reg, irq_field, 1);
	rt2x00mmio_register_write(rt2x00dev, INT_MASK_CSR, reg);
	spin_unlock_irq(&rt2x00dev->irqmask_lock);
}

void rt2800mmio_txstatus_tasklet(unsigned long data)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *)data;
	if (rt2800mmio_txdone(rt2x00dev))
		tasklet_schedule(&rt2x00dev->txstatus_tasklet);

	/*
	 * No need to enable the tx status interrupt here as we always
	 * leave it enabled to minimize the possibility of a tx status
	 * register overflow. See comment in interrupt handler.
	 */
}
EXPORT_SYMBOL_GPL(rt2800mmio_txstatus_tasklet);

void rt2800mmio_tx8damdone_tasklet(unsigned long data)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *)data;

	if (RTMPHandleTxRing8DmaDoneInterrupt(rt2x00dev))
		tasklet_schedule(&rt2x00dev->tx8damdone_tasklet);
	else if (test_bit(DEVICE_STATE_ENABLED_RADIO, &rt2x00dev->flags)) {
		rt2800mmio_enable_interrupt(rt2x00dev, INT_SOURCE_CSR_7630_HCCA_DMA_DONE);
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_tx8damdone_tasklet);

void rt2800mmio_pretbtt_tasklet(unsigned long data)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *)data;
	rt2x00lib_pretbtt(rt2x00dev);
	if (test_bit(DEVICE_STATE_ENABLED_RADIO, &rt2x00dev->flags)) {
		if (!rt2x00_rt(rt2x00dev, MT7630))
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_PRE_TBTT);
		else
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_7630_PRE_TBTT);
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_pretbtt_tasklet);

void rt2800mmio_tbtt_tasklet(unsigned long data)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *)data;
	struct rt2800_drv_data *drv_data = rt2x00dev->drv_data;
	u32 reg;

	rt2x00lib_beacondone(rt2x00dev);

	if (rt2x00dev->intf_ap_count) {
		/*
		 * The rt2800pci hardware tbtt timer is off by 1us per tbtt
		 * causing beacon skew and as a result causing problems with
		 * some powersaving clients over time. Shorten the beacon
		 * interval every 64 beacons by 64us to mitigate this effect.
		 */
		if (drv_data->tbtt_tick == (BCN_TBTT_OFFSET - 2)) {
			rt2x00mmio_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
			rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_INTERVAL,
					   (rt2x00dev->beacon_int * 16) - 1);
			rt2x00mmio_register_write(rt2x00dev, BCN_TIME_CFG, reg);
		} else if (drv_data->tbtt_tick == (BCN_TBTT_OFFSET - 1)) {
			rt2x00mmio_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
			rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_INTERVAL,
					   (rt2x00dev->beacon_int * 16));
			rt2x00mmio_register_write(rt2x00dev, BCN_TIME_CFG, reg);
		}
		drv_data->tbtt_tick++;
		drv_data->tbtt_tick %= BCN_TBTT_OFFSET;
	}

	if (test_bit(DEVICE_STATE_ENABLED_RADIO, &rt2x00dev->flags)) {
		if (rt2x00_rt(rt2x00dev, MT7630))
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_7630_TBTT);
		else
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_TBTT);
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_tbtt_tasklet);

void rt2800mmio_rxdone_tasklet(unsigned long data)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *)data;
	if (rt2x00mmio_rxdone(rt2x00dev))
		tasklet_schedule(&rt2x00dev->rxdone_tasklet);
	else if (test_bit(DEVICE_STATE_ENABLED_RADIO, &rt2x00dev->flags))
	{
		if (rt2x00_rt(rt2x00dev, MT7630))
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_7630_RX_DONE);
		else
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_RX_DONE);
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_rxdone_tasklet);

void rt2800mmio_autowake_tasklet(unsigned long data)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *)data;
	rt2800mmio_wakeup(rt2x00dev);
	if (test_bit(DEVICE_STATE_ENABLED_RADIO, &rt2x00dev->flags)) {
		if (rt2x00_rt(rt2x00dev, MT7630))
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_7630_AUTO_WAKEUP);
		else
			rt2800mmio_enable_interrupt(rt2x00dev, INT_MASK_CSR_AUTO_WAKEUP);
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_autowake_tasklet);

static void rt2800mmio_txstatus_interrupt(struct rt2x00_dev *rt2x00dev)
{
	u32 status;
	int i;
	TX_STA_FIFO_EXT_STRUC Fifi_Status_ext;
	TX_STA_FIFO_STRUC Fifi_Status;

	/*
	 * The TX_FIFO_STATUS interrupt needs special care. We should
	 * read TX_STA_FIFO but we should do it immediately as otherwise
	 * the register can overflow and we would lose status reports.
	 *
	 * Hence, read the TX_STA_FIFO register and copy all tx status
	 * reports into a kernel FIFO which is handled in the txstatus
	 * tasklet. We use a tasklet to process the tx status reports
	 * because we can schedule the tasklet multiple times (when the
	 * interrupt fires again during tx status processing).
	 *
	 * Furthermore we don't disable the TX_FIFO_STATUS
	 * interrupt here but leave it enabled so that the TX_STA_FIFO
	 * can also be read while the tx status tasklet gets executed.
	 *
	 * Since we have only one producer and one consumer we don't
	 * need to lock the kfifo.
	 */
	for (i = 0; i < rt2x00dev->tx->limit; i++) {
		rt2x00mmio_register_read(rt2x00dev, TX_STA_FIFO_EXT, &Fifi_Status_ext.word);
		rt2x00mmio_register_read(rt2x00dev, TX_STA_FIFO, &Fifi_Status.word);
		//if (!rt2x00_get_field32(status, TX_STA_FIFO_VALID))
		if (!Fifi_Status.field.bValid)
		{
			//printk("!rt2x00_get_field32(TX_STA_FIFO, TX_STA_FIFO_VALID)\n");
			break;
		}
		Fifi_Status.field.PidType = (Fifi_Status_ext.field.TX_PKT_ID == 5)? 0:Fifi_Status_ext.field.TX_PKT_ID;
		vend_dbg("0x%x (status)\n",Fifi_Status.word);
		status = Fifi_Status.word;

		//woody_kfifo_put(&rt2x00dev->txstatus_fifo, &status);
		if (!kfifo_put(&rt2x00dev->txstatus_fifo, status)) {
			WARNING(rt2x00dev, "TX status FIFO overrun,"
				"drop tx status report.\n");
			printk("TX status FIFO overrun, drop tx status report\n");
			break;
		}
	}

	/* Schedule the tasklet for processing the tx status. */
	tasklet_schedule(&rt2x00dev->txstatus_tasklet);
}

irqreturn_t rt2800mmio_interrupt(int irq, void *dev_instance)
{
	struct rt2x00_dev *rt2x00dev = dev_instance;
	u32 reg, mask;

	/* Read status and ACK all interrupts */
	rt2x00mmio_register_read(rt2x00dev, INT_SOURCE_CSR, &reg);
	rt2x00mmio_register_write(rt2x00dev, INT_SOURCE_CSR, reg);

	if (!reg)
		return IRQ_NONE;

	if (!test_bit(DEVICE_STATE_ENABLED_RADIO, &rt2x00dev->flags))
		return IRQ_HANDLED;

	/*
	 * Since INT_MASK_CSR and INT_SOURCE_CSR use the same bits
	 * for interrupts and interrupt masks we can just use the value of
	 * INT_SOURCE_CSR to create the interrupt mask.
	 */
	mask = ~reg;
	if (rt2x00_rt(rt2x00dev, MT7630))
	{
		if (rt2x00_get_field32(reg, INT_SOURCE_CSR_7630_TX_FIFO_STATUS)) {
			rt2800mmio_txstatus_interrupt(rt2x00dev);
			/*
			 * Never disable the TX_FIFO_STATUS interrupt.
			 */
			rt2x00_set_field32(&mask, INT_SOURCE_CSR_7630_TX_FIFO_STATUS, 1);
		}

		if (rt2x00_get_field32(reg, INT_SOURCE_CSR_7630_PRE_TBTT))
			tasklet_hi_schedule(&rt2x00dev->pretbtt_tasklet);

		if (rt2x00_get_field32(reg, INT_SOURCE_CSR_7630_TBTT))
			tasklet_hi_schedule(&rt2x00dev->tbtt_tasklet);

		if (rt2x00_get_field32(reg, INT_SOURCE_CSR_7630_RX_DONE))
		{
			tasklet_schedule(&rt2x00dev->rxdone_tasklet);
		}
		if (rt2x00_get_field32(reg, INT_SOURCE_CSR_7630_AUTO_WAKEUP))
			tasklet_schedule(&rt2x00dev->autowake_tasklet);
		if (rt2x00_get_field32(reg, INT_SOURCE_CSR_7630_HCCA_DMA_DONE)) {
			printk("==>INT_SOURCE_CSR_7630_HCCA_DMA_DONE\n");
			tasklet_schedule(&rt2x00dev->tx8damdone_tasklet);
			//return IRQ_HANDLED;
		}
	} else {
	if (rt2x00_get_field32(reg, INT_SOURCE_CSR_TX_FIFO_STATUS)) {
		rt2800mmio_txstatus_interrupt(rt2x00dev);
		/*
		 * Never disable the TX_FIFO_STATUS interrupt.
		 */
		rt2x00_set_field32(&mask, INT_MASK_CSR_TX_FIFO_STATUS, 1);
	}

	if (rt2x00_get_field32(reg, INT_SOURCE_CSR_PRE_TBTT))
		tasklet_hi_schedule(&rt2x00dev->pretbtt_tasklet);

	if (rt2x00_get_field32(reg, INT_SOURCE_CSR_TBTT))
		tasklet_hi_schedule(&rt2x00dev->tbtt_tasklet);

	if (rt2x00_get_field32(reg, INT_SOURCE_CSR_RX_DONE))
		tasklet_schedule(&rt2x00dev->rxdone_tasklet);

	if (rt2x00_get_field32(reg, INT_SOURCE_CSR_AUTO_WAKEUP))
		tasklet_schedule(&rt2x00dev->autowake_tasklet);
	}
	/*
	 * Disable all interrupts for which a tasklet was scheduled right now,
	 * the tasklet will reenable the appropriate interrupts.
	 */
	spin_lock(&rt2x00dev->irqmask_lock);
	rt2x00mmio_register_read(rt2x00dev, INT_MASK_CSR, &reg);
	reg &= mask;
	rt2x00mmio_register_write(rt2x00dev, INT_MASK_CSR, reg);
	spin_unlock(&rt2x00dev->irqmask_lock);

	return IRQ_HANDLED;
}
EXPORT_SYMBOL_GPL(rt2800mmio_interrupt);

void rt2800mmio_toggle_irq(struct rt2x00_dev *rt2x00dev,
			   enum dev_state state)
{
	u32 reg;
	unsigned long flags;

	/*
	 * When interrupts are being enabled, the interrupt registers
	 * should clear the register to assure a clean state.
	 */
	if (state == STATE_RADIO_IRQ_ON) {
		if (rt2x00_rt(rt2x00dev, MT7630))
			rt2x00mmio_register_write(rt2x00dev, INT_SOURCE_CSR, 0xffffffff);
		else
		{
			rt2x00mmio_register_read(rt2x00dev, INT_SOURCE_CSR, &reg);
			rt2x00mmio_register_write(rt2x00dev, INT_SOURCE_CSR, reg);
		}
	}

	spin_lock_irqsave(&rt2x00dev->irqmask_lock, flags);
	reg = 0;
	if (state == STATE_RADIO_IRQ_ON) {
		if (rt2x00_rt(rt2x00dev, MT7630))
		{
			rt2x00_set_field32(&reg, INT_MASK_CSR_7630_RX_DONE, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_7630_TBTT, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_7630_PRE_TBTT, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_7630_TX_FIFO_STATUS, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_7630_AUTO_WAKEUP, 1);
		} else {
			rt2x00_set_field32(&reg, INT_MASK_CSR_RX_DONE, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_TBTT, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_PRE_TBTT, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_TX_FIFO_STATUS, 1);
			rt2x00_set_field32(&reg, INT_MASK_CSR_AUTO_WAKEUP, 1);
		}
	}
	if (rt2x00_rt(rt2x00dev, MT7630))
		reg = ((DELAYINTMASK) |(RxINT|TxDataInt|TxMgmtInt));
	rt2x00mmio_register_write(rt2x00dev, INT_MASK_CSR, reg);
	rt2x00dev->int_enable_reg = reg;
	spin_unlock_irqrestore(&rt2x00dev->irqmask_lock, flags);

	if (state == STATE_RADIO_IRQ_ON && rt2x00_rt(rt2x00dev, MT7630)) {
		printk("set INT_MASK_CSR = 0x%x\n",reg);

		RTMPEnableRxTx(rt2x00dev);

		rt2x00mmio_register_read(rt2x00dev, 0x1300, &reg);  /* clear garbage interrupts*/
		printk("0x1300 = %08x\n", reg);

		printk("%s(1):Check if PDMA is idle!\n", __FUNCTION__);
		AsicWaitPDMAIdle(rt2x00dev, 5, 10);

		printk("%s(2):Check if PDMA is idle!\n", __FUNCTION__);
		AsicWaitPDMAIdle(rt2x00dev, 5, 10);
	}

	if (state == STATE_RADIO_IRQ_OFF) {
		/*
		 * Wait for possibly running tasklets to finish.
		 */
		tasklet_kill(&rt2x00dev->tx8damdone_tasklet);
		tasklet_kill(&rt2x00dev->txstatus_tasklet);
		tasklet_kill(&rt2x00dev->rxdone_tasklet);
		tasklet_kill(&rt2x00dev->autowake_tasklet);
		tasklet_kill(&rt2x00dev->tbtt_tasklet);
		tasklet_kill(&rt2x00dev->pretbtt_tasklet);
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_toggle_irq);

/*
 * Queue handlers.
 */
void rt2800mmio_start_queue(struct data_queue *queue)
{
	struct rt2x00_dev *rt2x00dev = queue->rt2x00dev;
	u32 reg;

	switch (queue->qid) {
	case QID_RX:
		rt2x00mmio_register_read(rt2x00dev, MAC_SYS_CTRL, &reg);
		rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_RX, 1);
		rt2x00mmio_register_write(rt2x00dev, MAC_SYS_CTRL, reg);
		break;
	case QID_BEACON:
		rt2x00mmio_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_TSF_TICKING, 1);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_TBTT_ENABLE, 1);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_GEN, 1);
		rt2x00mmio_register_write(rt2x00dev, BCN_TIME_CFG, reg);

		rt2x00mmio_register_read(rt2x00dev, INT_TIMER_EN, &reg);
		rt2x00_set_field32(&reg, INT_TIMER_EN_PRE_TBTT_TIMER, 1);
		rt2x00mmio_register_write(rt2x00dev, INT_TIMER_EN, reg);
		break;
	default:
		break;
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_start_queue);

void rt2800mmio_kick_queue(struct data_queue *queue)
{
	struct rt2x00_dev *rt2x00dev = queue->rt2x00dev;
	struct queue_entry *entry;

	rt2x00dev->TxCount++;
	switch (queue->qid) {
	case QID_AC_VO:
	case QID_AC_VI:
	case QID_AC_BE:
	case QID_AC_BK:
		entry = rt2x00queue_get_entry(queue, Q_INDEX);
		if (rt2x00_rt(rt2x00dev, MT7630))
			rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX_7630(queue->qid),
						 entry->entry_idx);
		else
			rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX(queue->qid),
					  entry->entry_idx);
		break;
	case QID_MGMT:
		entry = rt2x00queue_get_entry(queue, Q_INDEX);
		if (rt2x00_rt(rt2x00dev, MT7630))
			rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX_7630(5),
						 entry->entry_idx);
		else
			rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX(5),
					 	 entry->entry_idx);
		break;
	default:
		break;
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_kick_queue);

void rt2800mmio_stop_queue(struct data_queue *queue)
{
	struct rt2x00_dev *rt2x00dev = queue->rt2x00dev;
	u32 reg;

	switch (queue->qid) {
	case QID_RX:
#if 0
		rt2x00mmio_register_read(rt2x00dev, MAC_SYS_CTRL, &reg);
		rt2x00_set_field32(&reg, MAC_SYS_CTRL_ENABLE_RX, 0);
		rt2x00mmio_register_write(rt2x00dev, MAC_SYS_CTRL, reg);
#endif
		break;
	case QID_BEACON:
		rt2x00mmio_register_read(rt2x00dev, BCN_TIME_CFG, &reg);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_TSF_TICKING, 0);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_TBTT_ENABLE, 0);
		rt2x00_set_field32(&reg, BCN_TIME_CFG_BEACON_GEN, 0);
		rt2x00mmio_register_write(rt2x00dev, BCN_TIME_CFG, reg);

		rt2x00mmio_register_read(rt2x00dev, INT_TIMER_EN, &reg);
		rt2x00_set_field32(&reg, INT_TIMER_EN_PRE_TBTT_TIMER, 0);
		rt2x00mmio_register_write(rt2x00dev, INT_TIMER_EN, reg);

		/*
		 * Wait for current invocation to finish. The tasklet
		 * won't be scheduled anymore afterwards since we disabled
		 * the TBTT and PRE TBTT timer.
		 */
		tasklet_kill(&rt2x00dev->tbtt_tasklet);
		tasklet_kill(&rt2x00dev->pretbtt_tasklet);

		break;
	default:
		break;
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_stop_queue);

void rt2800mmio_queue_init(struct data_queue *queue)
{
	struct rt2x00_dev *rt2x00dev = queue->rt2x00dev;
	unsigned short txwi_size, rxwi_size;

	rt2800_get_txwi_rxwi_size(rt2x00dev, &txwi_size, &rxwi_size);

	switch (queue->qid) {
	case QID_RX:
		queue->limit = 128;
		queue->data_size = AGGREGATION_SIZE;
		queue->desc_size = RXD_DESC_SIZE;
		queue->winfo_size = rxwi_size;
		queue->priv_size = sizeof(struct queue_entry_priv_mmio);
		break;

	case QID_AC_VO:
	case QID_AC_VI:
	case QID_AC_BE:
	case QID_AC_BK:
		queue->limit = 64;
		queue->data_size = AGGREGATION_SIZE;
		queue->desc_size = TXD_DESC_SIZE;
		queue->winfo_size = txwi_size;
		queue->priv_size = sizeof(struct queue_entry_priv_mmio);
		break;

	case QID_BEACON:
		queue->limit = 8;
		queue->data_size = 0; /* No DMA required for beacons */
		queue->desc_size = TXD_DESC_SIZE;
		queue->winfo_size = txwi_size;
		queue->priv_size = sizeof(struct queue_entry_priv_mmio);
		break;

	case QID_ATIM:
		/* fallthrough */
	default:
		BUG();
		break;
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_queue_init);

/*
 * Initialization functions.
 */
bool rt2800mmio_get_entry_state(struct queue_entry *entry)
{
	struct queue_entry_priv_mmio *entry_priv = entry->priv_data;
	u32 word;

	if (entry->queue->qid == QID_RX) {
		rt2x00_desc_read(entry_priv->desc, 1, &word);

		return (!rt2x00_get_field32(word, RXD_W1_DMA_DONE));
	} else {
		rt2x00_desc_read(entry_priv->desc, 1, &word);

		return (!rt2x00_get_field32(word, TXD_W1_DMA_DONE));
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_get_entry_state);

typedef	struct  __attribute__ ((packed)) _RXD_STRUC{
	/* Word	0 */
	UINT32		SDP0;
	/* Word	1 */
	UINT32		SDL1:14;
	UINT32		LS1:1;
	UINT32		BURST:1;
	UINT32		SDL0:14;
	UINT32		LS0:1;
	UINT32		DDONE:1;
	/* Word	2 */
	UINT32		SDP1;
}RXD_STRUC, *PRXD_STRUC;

void rt2800mmio_clear_entry(struct queue_entry *entry)
{
	struct queue_entry_priv_mmio *entry_priv = entry->priv_data;
	struct skb_frame_desc *skbdesc = get_skb_frame_desc(entry->skb);
	struct rt2x00_dev *rt2x00dev = entry->queue->rt2x00dev;
	u32 word;

	if (entry->queue->qid == QID_RX) {
		if (rt2x00_rt(rt2x00dev, MT7630))
		{

			rt2x00_desc_read(entry_priv->desc, 0, &word);
			rt2x00_set_field32(&word, RXD_W0_7630_SDP0, skbdesc->skb_dma);
			rt2x00_desc_write(entry_priv->desc, 0, word);

			rt2x00_desc_read(entry_priv->desc, 1, &word);
			rt2x00_set_field32(&word, RXD_W1_7630_DMA_DONE, 0);
			rt2x00_set_field32(&word, RXD_W1_7630_SDL0, entry->skb->len);
			rt2x00_desc_write(entry_priv->desc, 1, word);
			/*
			 * Set RX IDX in register to inform hardware that we have
			 * handled this entry and it is available for reuse again.
			 */

			rt2x00mmio_register_write(rt2x00dev, RX_RING_CIDX,
					      entry->entry_idx);
		} else {
		rt2x00_desc_read(entry_priv->desc, 0, &word);
		rt2x00_set_field32(&word, RXD_W0_SDP0, skbdesc->skb_dma);
		rt2x00_desc_write(entry_priv->desc, 0, word);

		rt2x00_desc_read(entry_priv->desc, 1, &word);
		rt2x00_set_field32(&word, RXD_W1_DMA_DONE, 0);
		rt2x00_desc_write(entry_priv->desc, 1, word);

		/*
		 * Set RX IDX in register to inform hardware that we have
		 * handled this entry and it is available for reuse again.
		 */
		rt2x00mmio_register_write(rt2x00dev, RX_CRX_IDX,
					  entry->entry_idx);
		}
	} else {
		rt2x00_desc_read(entry_priv->desc, 1, &word);
		rt2x00_set_field32(&word, TXD_W1_DMA_DONE, 1);
		rt2x00_desc_write(entry_priv->desc, 1, word);
	}
}
EXPORT_SYMBOL_GPL(rt2800mmio_clear_entry);

int rt2800mmio_init_queues(struct rt2x00_dev *rt2x00dev)
{
	struct queue_entry_priv_mmio *entry_priv;
	u32 i, offset;
	int ret = 0;

	/*
	 * Initialize registers.
	 */
	if (rt2x00_rt(rt2x00dev, MT7630))
	{
		for (i = 0 ; i < 4; i++)
		{
			offset = i * 0x10;

			entry_priv = rt2x00dev->tx[i].entries[0].priv_data;
			rt2x00mmio_register_write(rt2x00dev, TX_RING_BASE + offset, entry_priv->desc_dma);
			rt2x00mmio_register_write(rt2x00dev, TX_RING_CNT + offset, rt2x00dev->tx[i].limit);
			rt2x00mmio_register_write(rt2x00dev, TX_RING_CIDX + offset, 0);
			printk("-->TX_RING: Base=0x%pad, Cnt=%d\n", &entry_priv->desc_dma,rt2x00dev->tx[i].limit);
		}

		offset = 4 * 0x10;
		rt2x00mmio_register_write(rt2x00dev, TX_RING_BASE + offset, 0);
		rt2x00mmio_register_write(rt2x00dev, TX_RING_CNT + offset, 0);
		rt2x00mmio_register_write(rt2x00dev, TX_RING_CIDX + offset, 0);

		rt2x00mmio_register_write(rt2x00dev, TX_MGMT_BASE, 0);
		rt2x00mmio_register_write(rt2x00dev, TX_MGMT_CNT, 0);
		rt2x00mmio_register_write(rt2x00dev, TX_MGMT_CIDX, 0);

		entry_priv = rt2x00dev->rx->entries[0].priv_data;
		rt2x00mmio_register_write(rt2x00dev, RX_RING_BASE, entry_priv->desc_dma);
		rt2x00mmio_register_write(rt2x00dev, RX_RING_CNT, rt2x00dev->rx[0].limit);
		rt2x00mmio_register_write(rt2x00dev, RX_RING_CIDX, rt2x00dev->rx[0].limit - 1);

		rt2x00mmio_register_write(rt2x00dev, RX_RING_CIDX + 0x10, rt2x00dev->rx[0].limit - 1);

		printk("-->RX_RING: Base=0x%pad, Cnt=%d\n", &entry_priv->desc_dma,rt2x00dev->rx[0].limit);

		/*
			Reset DMA Index
		*/
		rt2x00mmio_register_write(rt2x00dev, WPDMA_RST_IDX, 0xFFFFFFFF);

		ret = rt2800_wait_wpdma_ready(rt2x00dev);
		if (ret != 0)
			printk("DMA busy\n");

		rt2800_disable_wpdma(rt2x00dev);
		rt2x00mmio_register_write(rt2x00dev, DELAY_INT_CFG, 0);

	}
	else {
	entry_priv = rt2x00dev->tx[0].entries[0].priv_data;
	rt2x00mmio_register_write(rt2x00dev, TX_BASE_PTR0,
				  entry_priv->desc_dma);
	rt2x00mmio_register_write(rt2x00dev, TX_MAX_CNT0,
				  rt2x00dev->tx[0].limit);
	rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX0, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_DTX_IDX0, 0);

	entry_priv = rt2x00dev->tx[1].entries[0].priv_data;
	rt2x00mmio_register_write(rt2x00dev, TX_BASE_PTR1,
				  entry_priv->desc_dma);
	rt2x00mmio_register_write(rt2x00dev, TX_MAX_CNT1,
				  rt2x00dev->tx[1].limit);
	rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX1, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_DTX_IDX1, 0);

	entry_priv = rt2x00dev->tx[2].entries[0].priv_data;
	rt2x00mmio_register_write(rt2x00dev, TX_BASE_PTR2,
				  entry_priv->desc_dma);
	rt2x00mmio_register_write(rt2x00dev, TX_MAX_CNT2,
				  rt2x00dev->tx[2].limit);
	rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX2, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_DTX_IDX2, 0);

	entry_priv = rt2x00dev->tx[3].entries[0].priv_data;
	rt2x00mmio_register_write(rt2x00dev, TX_BASE_PTR3,
				  entry_priv->desc_dma);
	rt2x00mmio_register_write(rt2x00dev, TX_MAX_CNT3,
				  rt2x00dev->tx[3].limit);
	rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX3, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_DTX_IDX3, 0);

	rt2x00mmio_register_write(rt2x00dev, TX_BASE_PTR4, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_MAX_CNT4, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX4, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_DTX_IDX4, 0);

	rt2x00mmio_register_write(rt2x00dev, TX_BASE_PTR5, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_MAX_CNT5, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_CTX_IDX5, 0);
	rt2x00mmio_register_write(rt2x00dev, TX_DTX_IDX5, 0);

	entry_priv = rt2x00dev->rx->entries[0].priv_data;
	rt2x00mmio_register_write(rt2x00dev, RX_BASE_PTR,
				  entry_priv->desc_dma);
	rt2x00mmio_register_write(rt2x00dev, RX_MAX_CNT,
				  rt2x00dev->rx[0].limit);
	rt2x00mmio_register_write(rt2x00dev, RX_CRX_IDX,
				  rt2x00dev->rx[0].limit - 1);
	rt2x00mmio_register_write(rt2x00dev, RX_DRX_IDX, 0);

	rt2800_disable_wpdma(rt2x00dev);

	rt2x00mmio_register_write(rt2x00dev, DELAY_INT_CFG, 0);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(rt2800mmio_init_queues);

int rt2800mmio_init_registers(struct rt2x00_dev *rt2x00dev)
{
	u32 reg;

	/*
	 * Reset DMA indexes
	 */
	if (!rt2x00_rt(rt2x00dev, MT7630))
	{
	rt2x00mmio_register_read(rt2x00dev, WPDMA_RST_IDX, &reg);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX0, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX1, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX2, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX3, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX4, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DTX_IDX5, 1);
	rt2x00_set_field32(&reg, WPDMA_RST_IDX_DRX_IDX0, 1);
	rt2x00mmio_register_write(rt2x00dev, WPDMA_RST_IDX, reg);
	}
	rt2x00mmio_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00000e1f);
	rt2x00mmio_register_write(rt2x00dev, PBF_SYS_CTRL, 0x00000e00);

	if (rt2x00_is_pcie(rt2x00dev) &&
	    (rt2x00_rt(rt2x00dev, RT3090) ||
	     rt2x00_rt(rt2x00dev, RT3390) ||
	     rt2x00_rt(rt2x00dev, RT3572) ||
	     rt2x00_rt(rt2x00dev, RT3593) ||
	     rt2x00_rt(rt2x00dev, RT5390) ||
	     rt2x00_rt(rt2x00dev, RT5392) ||
	     rt2x00_rt(rt2x00dev, RT5592))) {
		rt2x00mmio_register_read(rt2x00dev, AUX_CTRL, &reg);
		rt2x00_set_field32(&reg, AUX_CTRL_FORCE_PCIE_CLK, 1);
		rt2x00_set_field32(&reg, AUX_CTRL_WAKE_PCIE_EN, 1);
		rt2x00mmio_register_write(rt2x00dev, AUX_CTRL, reg);
	}

	if (!rt2x00_rt(rt2x00dev, MT7630))
		rt2x00mmio_register_write(rt2x00dev, PWR_PIN_CFG, 0x00000003);

	reg = 0;
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_RESET_CSR, 1);
	rt2x00_set_field32(&reg, MAC_SYS_CTRL_RESET_BBP, 1);
	rt2x00mmio_register_write(rt2x00dev, MAC_SYS_CTRL, reg);

	rt2x00mmio_register_write(rt2x00dev, MAC_SYS_CTRL, 0x00000000);

	return 0;
}
EXPORT_SYMBOL_GPL(rt2800mmio_init_registers);

/*
 * Device state switch handlers.
 */
int rt2800mmio_enable_radio(struct rt2x00_dev *rt2x00dev)
{
	/* Wait for DMA, ignore error until we initialize queues. */
	rt2800_wait_wpdma_ready(rt2x00dev);

	if (!rt2x00_rt(rt2x00dev, MT7630))
	{
		if (unlikely(rt2800mmio_init_queues(rt2x00dev)))
			return -EIO;
	}
	return rt2800_enable_radio(rt2x00dev);
}
EXPORT_SYMBOL_GPL(rt2800mmio_enable_radio);

MODULE_AUTHOR(DRV_PROJECT);
MODULE_VERSION(DRV_VERSION);
MODULE_DESCRIPTION("rt2800 MMIO library");
MODULE_LICENSE("GPL");
