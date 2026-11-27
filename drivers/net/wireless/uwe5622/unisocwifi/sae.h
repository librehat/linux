/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SPRDWL_SAE_H__
#define __SPRDWL_SAE_H__

#include <linux/if_ether.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct sprdwl_vif;

#define SPRDWL_SAE_PMK_LEN	32
#define SPRDWL_SAE_PMKID_LEN	16
#define SPRDWL_SAE_MAX_PWD_LEN	127
#define SPRDWL_SAE_MAX_RSN_LEN	256

struct sprdwl_sae_ctx {
	spinlock_t lock;
	struct mutex mutex;
	struct work_struct work;
	struct sk_buff_head rx_queue;

	bool connecting;
	bool active;
	bool tptk_valid;
	bool ptk_valid;
	bool authorized;
	bool replay_valid;

	u8 aa[ETH_ALEN];
	u8 spa[ETH_ALEN];
	u8 pmk[SPRDWL_SAE_PMK_LEN];
	u8 pmkid[SPRDWL_SAE_PMKID_LEN];
	u8 anonce[32];
	u8 snonce[32];

	u8 tptk_kck[16];
	u8 tptk_kek[16];
	u8 tptk_tk[16];

	u8 kck[16];
	u8 kek[16];
	u8 tk[16];

	u8 last_replay[8];

	u8 rsn_ies[SPRDWL_SAE_MAX_RSN_LEN];
	u16 rsn_ies_len;

	u8 grp_cipher;
	u8 eapol_version;
};

void sprdwl_sae_init(struct sprdwl_vif *vif);
void sprdwl_sae_deinit(struct sprdwl_vif *vif);
void sprdwl_sae_reset(struct sprdwl_vif *vif);

int sprdwl_sae_send_ie(struct sprdwl_vif *vif, const u8 *pwd, size_t pwd_len);
void sprdwl_sae_save_req_ies(struct sprdwl_vif *vif, const u8 *ies,
			     size_t ies_len);
bool sprdwl_sae_extract_pmk_ie(u8 *resp_ie, u16 *resp_ie_len,
			       u8 pmk[SPRDWL_SAE_PMK_LEN],
			       u8 pmkid[SPRDWL_SAE_PMKID_LEN]);
void sprdwl_sae_start_4way(struct sprdwl_vif *vif, const u8 *bssid,
			   const u8 pmk[SPRDWL_SAE_PMK_LEN],
			   const u8 pmkid[SPRDWL_SAE_PMKID_LEN],
			   const u8 *req_ie, u16 req_ie_len);
bool sprdwl_sae_rx_eapol(struct sprdwl_vif *vif, struct sk_buff *skb);

#endif /* __SPRDWL_SAE_H__ */
