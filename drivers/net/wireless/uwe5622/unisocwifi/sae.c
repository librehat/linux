// SPDX-License-Identifier: GPL-2.0
/*
 * STA WPA3-SAE offload and 4-way/GTK handshake support for Unisoc UWE5622.
 */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <net/cfg80211.h>

#include "sprdwl.h"
#include "cfg80211.h"
#include "cmdevt.h"
#include "sae.h"

#define UNISOC_OUI_0			0x40
#define UNISOC_OUI_1			0x45
#define UNISOC_OUI_2			0xda
#define UNISOC_SAE_IE_TYPE_PARAM	0x02
#define UNISOC_SAE_IE_TYPE_PMK		0x03

#define UNISOC_SAE_SUBTLV_PWD		0x00
#define UNISOC_SAE_SUBTLV_GROUPS	0x01
#define UNISOC_SAE_GROUP_P256		19

#define IEEE8021X_TYPE_EAPOL_KEY	3
#define EAPOL_KEY_DESC_RSN		2

#define WPA_KEY_INFO_TYPE_MASK		0x0007
#define WPA_KEY_INFO_KEY_TYPE		BIT(3)
#define WPA_KEY_INFO_INSTALL		BIT(6)
#define WPA_KEY_INFO_ACK		BIT(7)
#define WPA_KEY_INFO_MIC		BIT(8)
#define WPA_KEY_INFO_SECURE		BIT(9)
#define WPA_KEY_INFO_ERROR		BIT(10)
#define WPA_KEY_INFO_REQUEST		BIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA	BIT(12)

#define WPA_KDE_TYPE_GTK		0x01
#define WPA_KDE_TYPE_IGTK		0x09
#define WPA_KDE_TYPE_TD			0x0c

#define SAE_KCK_LEN			16
#define SAE_KEK_LEN			16
#define SAE_TK_LEN			16
#define SAE_MIC_LEN			16

struct sprdwl_eapol_key {
	u8 version;
	u8 type;
	__be16 length;
	u8 descriptor_type;
	__be16 key_info;
	__be16 key_length;
	u8 replay_counter[8];
	u8 key_nonce[32];
	u8 key_iv[16];
	u8 key_rsc[8];
	u8 key_id[8];
	u8 key_mic[16];
	__be16 key_data_length;
	u8 key_data[];
} __packed;

static void sprdwl_sae_clear_secrets(struct sprdwl_sae_ctx *sae)
{
	sae->connecting = false;
	sae->tptk_valid = false;
	sae->ptk_valid = false;
	sae->authorized = false;
	sae->replay_valid = false;
	sae->rsn_ies_len = 0;
	sae->grp_cipher = SPRDWL_CIPHER_CCMP;
	sae->eapol_version = 1;

	memzero_explicit(sae->aa, sizeof(sae->aa));
	memzero_explicit(sae->spa, sizeof(sae->spa));
	memzero_explicit(sae->pmk, sizeof(sae->pmk));
	memzero_explicit(sae->pmkid, sizeof(sae->pmkid));
	memzero_explicit(sae->anonce, sizeof(sae->anonce));
	memzero_explicit(sae->snonce, sizeof(sae->snonce));
	memzero_explicit(sae->tptk_kck, sizeof(sae->tptk_kck));
	memzero_explicit(sae->tptk_kek, sizeof(sae->tptk_kek));
	memzero_explicit(sae->tptk_tk, sizeof(sae->tptk_tk));
	memzero_explicit(sae->kck, sizeof(sae->kck));
	memzero_explicit(sae->kek, sizeof(sae->kek));
	memzero_explicit(sae->tk, sizeof(sae->tk));
	memzero_explicit(sae->last_replay, sizeof(sae->last_replay));
	memzero_explicit(sae->rsn_ies, sizeof(sae->rsn_ies));
}

void sprdwl_sae_reset(struct sprdwl_vif *vif)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;
	unsigned long flags;

	mutex_lock(&sae->mutex);
	spin_lock_irqsave(&sae->lock, flags);
	sae->active = false;
	spin_unlock_irqrestore(&sae->lock, flags);

	skb_queue_purge(&sae->rx_queue);
	sprdwl_sae_clear_secrets(sae);
	mutex_unlock(&sae->mutex);
}

static void sprdwl_sae_work(struct work_struct *work);

void sprdwl_sae_init(struct sprdwl_vif *vif)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;

	spin_lock_init(&sae->lock);
	mutex_init(&sae->mutex);
	INIT_WORK(&sae->work, sprdwl_sae_work);
	skb_queue_head_init(&sae->rx_queue);
	sae->active = false;
	sprdwl_sae_clear_secrets(sae);
}

void sprdwl_sae_deinit(struct sprdwl_vif *vif)
{
	sprdwl_sae_reset(vif);
	cancel_work_sync(&vif->sae.work);
}

int sprdwl_sae_send_ie(struct sprdwl_vif *vif, const u8 *pwd, size_t pwd_len)
{
	u8 buf[2 + 4 + 2 + SPRDWL_SAE_MAX_PWD_LEN + 3];
	size_t pos = 0;
	int ret;

	if (!pwd || !pwd_len || pwd_len > SPRDWL_SAE_MAX_PWD_LEN) {
		wl_ndev_log(L_ERR, vif->ndev,
			    "%s invalid SAE password length %zu\n",
			    __func__, pwd_len);
		return -EINVAL;
	}

	/*
	 * Unisoc vendor IE 40:45:DA type 0x02 carrying SAE sub-TLVs:
	 *   sub_type 0: passphrase
	 *   sub_type 1: supported ECC group IDs as u8[] (NIST P-256 = 19)
	 */
	buf[pos++] = WLAN_EID_VENDOR_SPECIFIC;
	buf[pos++] = 4 + (2 + pwd_len) + 3;
	buf[pos++] = UNISOC_OUI_0;
	buf[pos++] = UNISOC_OUI_1;
	buf[pos++] = UNISOC_OUI_2;
	buf[pos++] = UNISOC_SAE_IE_TYPE_PARAM;

	buf[pos++] = UNISOC_SAE_SUBTLV_PWD;
	buf[pos++] = (u8)pwd_len;
	memcpy(&buf[pos], pwd, pwd_len);
	pos += pwd_len;

	buf[pos++] = UNISOC_SAE_SUBTLV_GROUPS;
	buf[pos++] = 1;
	buf[pos++] = UNISOC_SAE_GROUP_P256;

	ret = sprdwl_set_ie(vif->priv, vif->ctx_id, SPRDWL_IE_SAE, buf, pos);
	memzero_explicit(buf, sizeof(buf));
	return ret;
}

static void sprdwl_sae_copy_rsn_ies(struct sprdwl_sae_ctx *sae,
				    const u8 *ies, size_t ies_len)
{
	size_t pos = 0;
	u16 out_len = 0;

	if (!ies || ies_len < 2)
		return;

	while (pos + 2 <= ies_len) {
		u8 id = ies[pos];
		u8 len = ies[pos + 1];
		size_t tlv_len = 2 + len;

		if (pos + tlv_len > ies_len)
			break;

		if ((id == WLAN_EID_RSN || id == WLAN_EID_RSNX) &&
		    out_len + tlv_len <= sizeof(sae->rsn_ies)) {
			memcpy(&sae->rsn_ies[out_len], &ies[pos], tlv_len);
			out_len += tlv_len;
		}
		pos += tlv_len;
	}

	if (out_len > 0)
		sae->rsn_ies_len = out_len;
}

void sprdwl_sae_save_req_ies(struct sprdwl_vif *vif, const u8 *ies,
			     size_t ies_len)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;

	mutex_lock(&sae->mutex);
	sae->rsn_ies_len = 0;
	sprdwl_sae_copy_rsn_ies(sae, ies, ies_len);
	mutex_unlock(&sae->mutex);
}

bool sprdwl_sae_extract_pmk_ie(u8 *resp_ie, u16 *resp_ie_len,
			       u8 pmk[SPRDWL_SAE_PMK_LEN],
			       u8 pmkid[SPRDWL_SAE_PMKID_LEN])
{
	size_t pos = 0;
	size_t total;

	if (!resp_ie || !resp_ie_len)
		return false;

	total = *resp_ie_len;
	while (pos + 2 <= total) {
		u8 id = resp_ie[pos];
		u8 len = resp_ie[pos + 1];
		size_t tlv_len = 2 + len;

		if (pos + tlv_len > total)
			break;

		if (id == WLAN_EID_VENDOR_SPECIFIC &&
		    len == 4 + SPRDWL_SAE_PMK_LEN + SPRDWL_SAE_PMKID_LEN &&
		    resp_ie[pos + 2] == UNISOC_OUI_0 &&
		    resp_ie[pos + 3] == UNISOC_OUI_1 &&
		    resp_ie[pos + 4] == UNISOC_OUI_2 &&
		    resp_ie[pos + 5] == UNISOC_SAE_IE_TYPE_PMK) {
			memcpy(pmk, &resp_ie[pos + 6], SPRDWL_SAE_PMK_LEN);
			memcpy(pmkid, &resp_ie[pos + 6 + SPRDWL_SAE_PMK_LEN],
			       SPRDWL_SAE_PMKID_LEN);
			if (pos + tlv_len < total)
				memmove(&resp_ie[pos],
					&resp_ie[pos + tlv_len],
					total - (pos + tlv_len));
			*resp_ie_len = total - tlv_len;
			return true;
		}
		pos += tlv_len;
	}

	return false;
}

void sprdwl_sae_start_4way(struct sprdwl_vif *vif, const u8 *bssid,
			   const u8 pmk[SPRDWL_SAE_PMK_LEN],
			   const u8 pmkid[SPRDWL_SAE_PMKID_LEN],
			   const u8 *req_ie, u16 req_ie_len)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;
	unsigned long flags;

	mutex_lock(&sae->mutex);
	skb_queue_purge(&sae->rx_queue);

	sae->connecting = false;
	sae->tptk_valid = false;
	sae->ptk_valid = false;
	sae->authorized = false;
	sae->replay_valid = false;
	sae->eapol_version = 1;

	ether_addr_copy(sae->aa, bssid);
	ether_addr_copy(sae->spa, vif->ndev->dev_addr);
	memcpy(sae->pmk, pmk, SPRDWL_SAE_PMK_LEN);
	memcpy(sae->pmkid, pmkid, SPRDWL_SAE_PMKID_LEN);
	memzero_explicit(sae->last_replay, sizeof(sae->last_replay));

	sprdwl_sae_copy_rsn_ies(sae, req_ie, req_ie_len);

	spin_lock_irqsave(&sae->lock, flags);
	sae->active = true;
	spin_unlock_irqrestore(&sae->lock, flags);
	mutex_unlock(&sae->mutex);

	wl_ndev_log(L_INFO, vif->ndev,
		    "SAE PMK received from firmware for %pM (rsn_ies=%u)\n",
		    sae->aa, sae->rsn_ies_len);
}

bool sprdwl_sae_rx_eapol(struct sprdwl_vif *vif, struct sk_buff *skb)
{
	const struct ethhdr *eth;
	const struct sprdwl_eapol_key *ek;
	struct sprdwl_sae_ctx *sae = &vif->sae;
	unsigned long flags;
	bool handled = false;

	if (!skb || skb->len < sizeof(*eth) + sizeof(*ek))
		return false;

	eth = (const struct ethhdr *)skb->data;
	if (eth->h_proto != htons(ETH_P_PAE))
		return false;

	ek = (const struct sprdwl_eapol_key *)(skb->data + sizeof(*eth));
	if (ek->type != IEEE8021X_TYPE_EAPOL_KEY ||
	    ek->descriptor_type != EAPOL_KEY_DESC_RSN)
		return false;

	spin_lock_irqsave(&sae->lock, flags);
	if (sae->active) {
		skb_queue_tail(&sae->rx_queue, skb);
		handled = true;
	}
	spin_unlock_irqrestore(&sae->lock, flags);

	if (handled)
		schedule_work(&sae->work);

	return handled;
}

/*
 * IEEE 802.11-2020 §12.7.1.7.2 KDF-HMAC-SHA256-384 for AKM 00-0F-AC:8 (SAE).
 * Label = "Pairwise key expansion" (22 bytes, no NUL).
 * Context = min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce).
 * Total PTK = 384 bits = 48 bytes (KCK[16] || KEK[16] || TK[16]).
 */
static void sprdwl_sae_derive_ptk(const u8 pmk[32],
				  const u8 aa[ETH_ALEN],
				  const u8 spa[ETH_ALEN],
				  const u8 anonce[32],
				  const u8 snonce[32],
				  u8 kck[16], u8 kek[16], u8 tk[16])
{
	static const char label[] = "Pairwise key expansion";
	u8 input[2 + 22 + 2 * ETH_ALEN + 2 * 32 + 2];
	u8 digest[SHA256_DIGEST_SIZE];
	size_t pos = 2;

	memcpy(&input[pos], label, sizeof(label) - 1);
	pos += sizeof(label) - 1;

	if (memcmp(aa, spa, ETH_ALEN) < 0) {
		memcpy(&input[pos], aa, ETH_ALEN);
		memcpy(&input[pos + ETH_ALEN], spa, ETH_ALEN);
	} else {
		memcpy(&input[pos], spa, ETH_ALEN);
		memcpy(&input[pos + ETH_ALEN], aa, ETH_ALEN);
	}
	pos += 2 * ETH_ALEN;

	if (memcmp(anonce, snonce, 32) < 0) {
		memcpy(&input[pos], anonce, 32);
		memcpy(&input[pos + 32], snonce, 32);
	} else {
		memcpy(&input[pos], snonce, 32);
		memcpy(&input[pos + 32], anonce, 32);
	}
	pos += 64;

	put_unaligned_le16(384, &input[pos]);
	pos += 2;

	/* Iteration 1 -> 32 bytes: KCK[16] || KEK[16] */
	put_unaligned_le16(1, input);
	hmac_sha256_usingrawkey(pmk, SPRDWL_SAE_PMK_LEN, input, pos, digest);
	memcpy(kck, digest, SAE_KCK_LEN);
	memcpy(kek, digest + SAE_KCK_LEN, SAE_KEK_LEN);

	/* Iteration 2 -> first 16 bytes: TK[16] */
	put_unaligned_le16(2, input);
	hmac_sha256_usingrawkey(pmk, SPRDWL_SAE_PMK_LEN, input, pos, digest);
	memcpy(tk, digest, SAE_TK_LEN);

	memzero_explicit(input, sizeof(input));
	memzero_explicit(digest, sizeof(digest));
}

static int sprdwl_sae_cmac_mic(const u8 kck[SAE_KCK_LEN], const u8 *frame,
			       size_t frame_len, u8 mic[SAE_MIC_LEN])
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("cmac(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_shash_setkey(tfm, kck, SAE_KCK_LEN);
	if (!ret) {
		SHASH_DESC_ON_STACK(desc, tfm);

		desc->tfm = tfm;
		ret = crypto_shash_digest(desc, frame, frame_len, mic);
		shash_desc_zero(desc);
	}

	crypto_free_shash(tfm);
	return ret;
}

static int sprdwl_sae_verify_mic(const u8 kck[SAE_KCK_LEN],
				 const struct sprdwl_eapol_key *ek,
				 size_t eapol_len)
{
	u8 *scratch;
	u8 calc_mic[SAE_MIC_LEN];
	int ret;

	scratch = kmemdup(ek, eapol_len, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	memset(((struct sprdwl_eapol_key *)scratch)->key_mic, 0, SAE_MIC_LEN);
	ret = sprdwl_sae_cmac_mic(kck, scratch, eapol_len, calc_mic);
	kfree_sensitive(scratch);
	if (ret)
		return ret;

	if (crypto_memneq(calc_mic, ek->key_mic, SAE_MIC_LEN))
		ret = -EBADMSG;

	memzero_explicit(calc_mic, sizeof(calc_mic));
	return ret;
}

/* RFC 3394 §2.2.2 AES Key Unwrap */
static int sprdwl_sae_aes_unwrap(const u8 kek[SAE_KEK_LEN], const u8 *cipher,
				 size_t cipher_len, u8 *plain)
{
	static const u8 default_iv[8] = {
		0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6
	};
	struct aes_key key;
	u8 a[8], b[AES_BLOCK_SIZE];
	size_t n, i;
	int j, ret;

	if (cipher_len < 24 || (cipher_len % 8) != 0)
		return -EINVAL;

	ret = aes_preparekey(&key, kek, SAE_KEK_LEN);
	if (ret)
		return ret;

	n = (cipher_len / 8) - 1;
	memcpy(a, cipher, 8);
	memcpy(plain, cipher + 8, n * 8);

	for (j = 5; j >= 0; j--) {
		for (i = n; i >= 1; i--) {
			u64 t = (u64)n * j + i;
			u8 *r = plain + (i - 1) * 8;
			u64 aval = get_unaligned_be64(a) ^ t;

			put_unaligned_be64(aval, b);
			memcpy(b + 8, r, 8);
			aes_decrypt(&key, b, b);
			memcpy(a, b, 8);
			memcpy(r, b + 8, 8);
		}
	}

	if (crypto_memneq(a, default_iv, 8)) {
		memzero_explicit(plain, n * 8);
		ret = -EBADMSG;
	} else {
		ret = 0;
	}

	memzero_explicit(&key, sizeof(key));
	memzero_explicit(a, sizeof(a));
	memzero_explicit(b, sizeof(b));
	return ret;
}

static void sprdwl_sae_parse_kdes(const u8 *kd, size_t kd_len,
				  const u8 **gtk, size_t *gtk_len, u8 *gtk_id,
				  const u8 **igtk, size_t *igtk_len, u16 *igtk_id,
				  const u8 **igtk_ipn,
				  const u8 **td, u8 *td_len)
{
	size_t pos = 0;

	*gtk = NULL;
	*gtk_len = 0;
	*igtk = NULL;
	*igtk_len = 0;
	*igtk_ipn = NULL;
	*td = NULL;
	*td_len = 0;

	while (pos < kd_len) {
		u8 id = kd[pos];
		u8 len;
		size_t payload_len;
		const u8 *p;

		if (id == WLAN_EID_VENDOR_SPECIFIC && pos + 1 >= kd_len)
			break;
		if (pos + 2 > kd_len)
			break;

		len = kd[pos + 1];
		if (id == WLAN_EID_VENDOR_SPECIFIC && len == 0)
			break;
		if (pos + 2 + len > kd_len)
			break;

		if (id == WLAN_EID_VENDOR_SPECIFIC && len >= 4 &&
		    kd[pos + 2] == 0x00 && kd[pos + 3] == 0x0f &&
		    kd[pos + 4] == 0xac) {
			u8 type = kd[pos + 5];

			p = &kd[pos + 6];
			payload_len = len - 4;

			if (type == WPA_KDE_TYPE_GTK && payload_len >= 2) {
				*gtk_id = p[0] & 0x03;
				*gtk = p + 2;
				*gtk_len = payload_len - 2;
			} else if (type == WPA_KDE_TYPE_IGTK &&
				   payload_len >= 8) {
				*igtk_id = get_unaligned_le16(p);
				*igtk_ipn = p + 2;
				*igtk = p + 8;
				*igtk_len = payload_len - 8;
			} else if (type == WPA_KDE_TYPE_TD &&
				   payload_len >= 1) {
				*td = p;
				*td_len = min_t(size_t, payload_len, U8_MAX);
			}
		}

		pos += 2 + len;
	}
}

static int sprdwl_sae_tx_eapol(struct sprdwl_vif *vif, const u8 kck[SAE_KCK_LEN],
			       u16 key_info, const u8 replay_counter[8],
			       const u8 *key_nonce, const u8 *key_data,
			       size_t key_data_len, bool sync)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;
	size_t eapol_len = sizeof(struct sprdwl_eapol_key) + key_data_len;
	size_t frame_len = sizeof(struct ethhdr) + eapol_len;
	size_t head = vif->priv->skb_head_len + 16;
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct sprdwl_eapol_key *ek;
	int ret;

	skb = alloc_skb(head + frame_len + 32, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, head);
	eth = skb_put_zero(skb, sizeof(*eth));
	ether_addr_copy(eth->h_dest, sae->aa);
	ether_addr_copy(eth->h_source, sae->spa);
	eth->h_proto = htons(ETH_P_PAE);

	ek = skb_put_zero(skb, eapol_len);
	ek->version = sae->eapol_version ? sae->eapol_version : 1;
	ek->type = IEEE8021X_TYPE_EAPOL_KEY;
	ek->length = htons(eapol_len - 4);
	ek->descriptor_type = EAPOL_KEY_DESC_RSN;
	ek->key_info = htons(key_info);
	ek->key_length = 0;
	memcpy(ek->replay_counter, replay_counter, sizeof(ek->replay_counter));
	if (key_nonce)
		memcpy(ek->key_nonce, key_nonce, sizeof(ek->key_nonce));
	ek->key_data_length = htons(key_data_len);
	if (key_data && key_data_len)
		memcpy(ek->key_data, key_data, key_data_len);

	ret = sprdwl_sae_cmac_mic(kck, (const u8 *)ek, eapol_len, ek->key_mic);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	skb->dev = vif->ndev;
	skb->protocol = htons(ETH_P_PAE);
	skb_reset_mac_header(skb);

	ret = sprdwl_xmit_data2cmd_wq(skb, vif->ndev);
	if (!ret && sync) {
		flush_work(&vif->priv->work);
		usleep_range(5000, 10000);
	}

	return ret;
}

static void sprdwl_sae_handle_msg1(struct sprdwl_vif *vif,
				   const struct sprdwl_eapol_key *ek)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;
	int ret;

	if (sae->replay_valid &&
	    memcmp(ek->replay_counter, sae->last_replay, 8) <= 0) {
		wl_ndev_log(L_DBG, vif->ndev,
			    "SAE: ignoring Msg 1/4 with replayed counter\n");
		return;
	}

	memcpy(sae->anonce, ek->key_nonce, sizeof(sae->anonce));
	get_random_bytes(sae->snonce, sizeof(sae->snonce));

	sprdwl_sae_derive_ptk(sae->pmk, sae->aa, sae->spa,
			      sae->anonce, sae->snonce,
			      sae->tptk_kck, sae->tptk_kek, sae->tptk_tk);
	sae->tptk_valid = true;

	ret = sprdwl_sae_tx_eapol(vif, sae->tptk_kck,
				  WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_MIC,
				  ek->replay_counter, sae->snonce,
				  sae->rsn_ies, sae->rsn_ies_len, false);
	if (ret)
		wl_ndev_log(L_ERR, vif->ndev,
			    "SAE: failed to send EAPOL Msg 2/4: %d\n", ret);
	else
		wl_ndev_log(L_INFO, vif->ndev, "SAE: sent EAPOL Msg 2/4\n");
}

static void sprdwl_sae_handle_msg3(struct sprdwl_vif *vif,
				   const struct sprdwl_eapol_key *ek,
				   size_t eapol_len, u16 kd_len)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;
	const u8 *kck = NULL, *kek = NULL, *tk = NULL;
	const u8 *gtk = NULL, *igtk = NULL, *igtk_ipn = NULL, *td = NULL;
	size_t gtk_len = 0, igtk_len = 0, plain_len;
	u8 gtk_id = 0, td_len = 0;
	u16 igtk_id = 0;
	u8 *plain;
	bool first_auth;
	int ret;

	if (sae->replay_valid &&
	    memcmp(ek->replay_counter, sae->last_replay, 8) <= 0) {
		wl_ndev_log(L_DBG, vif->ndev,
			    "SAE: ignoring Msg 3/4 with replayed counter\n");
		return;
	}

	if (memcmp(ek->key_nonce, sae->anonce, sizeof(sae->anonce))) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: Msg 3/4 ANonce mismatch\n");
		return;
	}

	if (sae->tptk_valid) {
		kck = sae->tptk_kck;
		kek = sae->tptk_kek;
		tk = sae->tptk_tk;
	} else if (sae->ptk_valid) {
		kck = sae->kck;
		kek = sae->kek;
		tk = sae->tk;
	} else {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: Msg 3/4 arrived before Msg 1/4\n");
		return;
	}

	ret = sprdwl_sae_verify_mic(kck, ek, eapol_len);
	if (ret) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: Msg 3/4 MIC verification failed (%d)\n", ret);
		return;
	}

	if (kd_len < 24 || (kd_len % 8) != 0) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: invalid wrapped Msg 3/4 Key Data len %u\n",
			    kd_len);
		return;
	}

	plain_len = kd_len - 8;
	plain = kmalloc(plain_len, GFP_KERNEL);
	if (!plain)
		return;

	ret = sprdwl_sae_aes_unwrap(kek, ek->key_data, kd_len, plain);
	if (ret) {
		kfree_sensitive(plain);
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: Msg 3/4 AES unwrap failed (%d)\n", ret);
		return;
	}

	sprdwl_sae_parse_kdes(plain, plain_len, &gtk, &gtk_len, &gtk_id,
			      &igtk, &igtk_len, &igtk_id, &igtk_ipn,
			      &td, &td_len);

	memcpy(sae->last_replay, ek->replay_counter, sizeof(sae->last_replay));
	sae->replay_valid = true;

	if (kck != sae->kck) {
		memcpy(sae->kck, kck, SAE_KCK_LEN);
		memcpy(sae->kek, kek, SAE_KEK_LEN);
		memcpy(sae->tk, tk, SAE_TK_LEN);
	}
	sae->ptk_valid = true;

	first_auth = !sae->authorized;
	ret = sprdwl_sae_tx_eapol(vif, sae->kck,
				  WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_MIC |
				  WPA_KEY_INFO_SECURE,
				  ek->replay_counter, NULL, NULL, 0,
				  first_auth);
	if (ret) {
		kfree_sensitive(plain);
		wl_ndev_log(L_ERR, vif->ndev,
			    "SAE: failed to send EAPOL Msg 4/4: %d\n", ret);
		return;
	}

	ret = sprdwl_add_key(vif->priv, vif->ctx_id, sae->tk, SAE_TK_LEN,
			     SPRDWL_PAIRWISE, 0, NULL, SPRDWL_CIPHER_CCMP,
			     sae->aa);
	if (ret)
		wl_ndev_log(L_ERR, vif->ndev,
			    "SAE: failed to install PTK: %d\n", ret);

	if (gtk && gtk_len > 0 && gtk_len <= WLAN_MAX_KEY_LEN &&
	    gtk_id <= SPRDWL_MAX_KEY_INDEX) {
		ret = sprdwl_add_key(vif->priv, vif->ctx_id, gtk, gtk_len,
				     SPRDWL_GROUP, gtk_id, ek->key_rsc,
				     sae->grp_cipher, NULL);
		if (ret)
			wl_ndev_log(L_ERR, vif->ndev,
				    "SAE: failed to install GTK idx %u: %d\n",
				    gtk_id, ret);
	}

	if (igtk && igtk_len > 0 && igtk_len <= WLAN_MAX_KEY_LEN &&
	    igtk_id <= SPRDWL_MAX_KEY_INDEX) {
		u8 ipn8[8] = { 0 };

		memcpy(ipn8, igtk_ipn, 6);
		ret = sprdwl_add_key(vif->priv, vif->ctx_id, igtk, igtk_len,
				     SPRDWL_GROUP, igtk_id, ipn8,
				     SPRDWL_CIPHER_AES_CMAC, NULL);
		memzero_explicit(ipn8, sizeof(ipn8));
		if (ret)
			wl_ndev_log(L_ERR, vif->ndev,
				    "SAE: failed to install IGTK idx %u: %d\n",
				    igtk_id, ret);
	}

	if (first_auth) {
		sae->authorized = true;
		cfg80211_port_authorized(vif->ndev, sae->aa, td, td_len,
					 GFP_KERNEL);
		wl_ndev_log(L_INFO, vif->ndev,
			    "SAE: 4-way handshake complete for %pM\n", sae->aa);
	}

	kfree_sensitive(plain);
}

static void sprdwl_sae_handle_group_msg1(struct sprdwl_vif *vif,
					 const struct sprdwl_eapol_key *ek,
					 size_t eapol_len, u16 kd_len)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;
	const u8 *gtk = NULL, *igtk = NULL, *igtk_ipn = NULL, *td = NULL;
	size_t gtk_len = 0, igtk_len = 0, plain_len;
	u8 gtk_id = 0, td_len = 0;
	u16 igtk_id = 0;
	u8 *plain;
	int ret;

	if (!sae->authorized || !sae->ptk_valid) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: Group Key Msg 1/2 before PTK ready\n");
		return;
	}

	if (sae->replay_valid &&
	    memcmp(ek->replay_counter, sae->last_replay, 8) <= 0) {
		wl_ndev_log(L_DBG, vif->ndev,
			    "SAE: ignoring Group Msg 1/2 with replayed counter\n");
		return;
	}

	ret = sprdwl_sae_verify_mic(sae->kck, ek, eapol_len);
	if (ret) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: Group Msg 1/2 MIC verification failed (%d)\n",
			    ret);
		return;
	}

	if (kd_len < 24 || (kd_len % 8) != 0) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: invalid Group Msg 1/2 Key Data len %u\n",
			    kd_len);
		return;
	}

	plain_len = kd_len - 8;
	plain = kmalloc(plain_len, GFP_KERNEL);
	if (!plain)
		return;

	ret = sprdwl_sae_aes_unwrap(sae->kek, ek->key_data, kd_len, plain);
	if (ret) {
		kfree_sensitive(plain);
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: Group Msg 1/2 AES unwrap failed (%d)\n", ret);
		return;
	}

	sprdwl_sae_parse_kdes(plain, plain_len, &gtk, &gtk_len, &gtk_id,
			      &igtk, &igtk_len, &igtk_id, &igtk_ipn,
			      &td, &td_len);

	memcpy(sae->last_replay, ek->replay_counter, sizeof(sae->last_replay));

	if (gtk && gtk_len > 0 && gtk_len <= WLAN_MAX_KEY_LEN &&
	    gtk_id <= SPRDWL_MAX_KEY_INDEX) {
		ret = sprdwl_add_key(vif->priv, vif->ctx_id, gtk, gtk_len,
				     SPRDWL_GROUP, gtk_id, ek->key_rsc,
				     sae->grp_cipher, NULL);
		if (ret)
			wl_ndev_log(L_ERR, vif->ndev,
				    "SAE: GTK rekey install idx %u failed: %d\n",
				    gtk_id, ret);
	}

	if (igtk && igtk_len > 0 && igtk_len <= WLAN_MAX_KEY_LEN &&
	    igtk_id <= SPRDWL_MAX_KEY_INDEX) {
		u8 ipn8[8] = { 0 };

		memcpy(ipn8, igtk_ipn, 6);
		ret = sprdwl_add_key(vif->priv, vif->ctx_id, igtk, igtk_len,
				     SPRDWL_GROUP, igtk_id, ipn8,
				     SPRDWL_CIPHER_AES_CMAC, NULL);
		memzero_explicit(ipn8, sizeof(ipn8));
		if (ret)
			wl_ndev_log(L_ERR, vif->ndev,
				    "SAE: IGTK rekey install idx %u failed: %d\n",
				    igtk_id, ret);
	}

	kfree_sensitive(plain);

	ret = sprdwl_sae_tx_eapol(vif, sae->kck,
				  WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE,
				  ek->replay_counter, NULL, NULL, 0, false);
	if (ret)
		wl_ndev_log(L_ERR, vif->ndev,
			    "SAE: failed to send Group Msg 2/2: %d\n", ret);
}

static void sprdwl_sae_process_skb(struct sprdwl_vif *vif, struct sk_buff *skb)
{
	struct sprdwl_sae_ctx *sae = &vif->sae;
	const struct ethhdr *eth;
	const struct sprdwl_eapol_key *ek;
	size_t eapol_len, body_len;
	u16 info, kd_len;

	if (skb_linearize(skb))
		return;

	if (skb->len < sizeof(*eth) + sizeof(*ek))
		return;

	eth = (const struct ethhdr *)skb->data;
	if (!ether_addr_equal(eth->h_source, sae->aa)) {
		wl_ndev_log(L_DBG, vif->ndev,
			    "SAE: drop EAPOL from unexpected src %pM\n",
			    eth->h_source);
		return;
	}

	ek = (const struct sprdwl_eapol_key *)(skb->data + sizeof(*eth));
	eapol_len = skb->len - sizeof(*eth);
	body_len = be16_to_cpu(ek->length) + 4;
	if (body_len < sizeof(*ek) || body_len > eapol_len) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: truncated EAPOL-Key frame (%zu/%zu)\n",
			    body_len, eapol_len);
		return;
	}
	eapol_len = body_len;

	kd_len = be16_to_cpu(ek->key_data_length);
	if (sizeof(*ek) + kd_len > eapol_len) {
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: EAPOL-Key data overflow (%u > %zu)\n",
			    kd_len, eapol_len - sizeof(*ek));
		return;
	}

	info = be16_to_cpu(ek->key_info);
	if ((info & WPA_KEY_INFO_TYPE_MASK) != 0)
		wl_ndev_log(L_WARN, vif->ndev,
			    "SAE: unexpected EAPOL descriptor version %u\n",
			    info & WPA_KEY_INFO_TYPE_MASK);

	sae->eapol_version = ek->version ? ek->version : 1;

	if ((info & (WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK |
		     WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE |
		     WPA_KEY_INFO_INSTALL)) ==
	    (WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK)) {
		sprdwl_sae_handle_msg1(vif, ek);
	} else if ((info & (WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK |
			    WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE |
			    WPA_KEY_INFO_ENCR_KEY_DATA)) ==
		   (WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK |
		    WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE |
		    WPA_KEY_INFO_ENCR_KEY_DATA)) {
		sprdwl_sae_handle_msg3(vif, ek, eapol_len, kd_len);
	} else if ((info & (WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK |
			    WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE |
			    WPA_KEY_INFO_ENCR_KEY_DATA)) ==
		   (WPA_KEY_INFO_ACK | WPA_KEY_INFO_MIC |
		    WPA_KEY_INFO_SECURE | WPA_KEY_INFO_ENCR_KEY_DATA)) {
		sprdwl_sae_handle_group_msg1(vif, ek, eapol_len, kd_len);
	} else {
		wl_ndev_log(L_DBG, vif->ndev,
			    "SAE: ignoring EAPOL-Key with key_info=0x%04x\n",
			    info);
	}
}

static void sprdwl_sae_work(struct work_struct *work)
{
	struct sprdwl_sae_ctx *sae = container_of(work, struct sprdwl_sae_ctx,
						  work);
	struct sprdwl_vif *vif = container_of(sae, struct sprdwl_vif, sae);
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sae->rx_queue)) != NULL) {
		mutex_lock(&sae->mutex);
		if (sae->active)
			sprdwl_sae_process_skb(vif, skb);
		mutex_unlock(&sae->mutex);
		dev_kfree_skb(skb);
	}
}
