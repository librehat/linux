// SPDX-License-Identifier: GPL-2.0
/*
 * Unisoc UMS512 (sharkl5pro, DPU r4p0) KMS driver.
 *
 * The bootloader brings up the MIPI-DSI link and the panel (one of several
 * vendor panels, picked by panel ID) in video burst mode and leaves the DPU
 * free-running in DPI mode. Re-initialising DSI from Linux has never produced
 * a picture on this board, so this driver *adopts* the running pipeline:
 *
 *  - the panel mode (size + porches) is read back from the DPU itself, so
 *    every panel variant works without a panel driver;
 *  - the DSI host / D-PHY / panel are never touched;
 *  - the DPU layer engine is fully owned by DRM: 4 hardware layers exposed as
 *    one primary + 3 overlay planes, atomic commits latched with REG_UPDATE,
 *    vblank and page-flip events from the DPU interrupt;
 *  - buffers are physically contiguous DMA (CMA) memory and the display
 *    IOMMU is put in bypass, so DPU addresses are plain physical addresses.
 *
 * The simple-framebuffer the bootloader handed over is kicked out once this
 * driver takes over the scanout.
 */

#include <linux/aperture.h>
#include <linux/backlight.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <video/mipi_display.h>

#include <drm/clients/drm_client_setup.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_blend.h>
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_damage_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_encoder.h>
#include <drm/drm_fb_dma_helper.h>
#include <drm/drm_fbdev_dma.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_gem_atomic_helper.h>
#include <drm/drm_gem_dma_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_managed.h>
#include <drm/drm_modeset_helper.h>
#include <drm/drm_modeset_helper_vtables.h>
#include <drm/drm_plane.h>
#include <drm/drm_print.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_vblank.h>

static bool panel_sleep = true;
module_param(panel_sleep, bool, 0644);
MODULE_PARM_DESC(panel_sleep, "Send MIPI-DSI 0x28/0x10 sleep-in during system suspend (default: true)");

#define DRIVER_NAME	"ums512-dpu"
#define DRIVER_DESC	"Unisoc UMS512 DPU (bootloader-initialised DSI)"

/* ---- DPU r4p0 registers ------------------------------------------------ */
#define REG_DPU_VERSION		0x000
#define REG_DPU_CTRL		0x004
#define REG_DPU_CFG0		0x008
#define REG_DPU_CFG1		0x00c
#define REG_DPU_CFG2		0x010
#define REG_PANEL_SIZE		0x020
#define REG_BLEND_SIZE		0x024
#define REG_BG_COLOR		0x02c

#define REG_LAY_BASE_ADDR0	0x030
#define REG_LAY_CTRL		0x040
#define REG_LAY_SIZE		0x044
#define REG_LAY_PITCH		0x048
#define REG_LAY_POS		0x04c
#define REG_LAY_ALPHA		0x050
#define REG_LAY_CROP_START	0x05c
#define LAY_STRIDE		0x030
#define LAY_HW_MAX		8

#define REG_DPU_INT_EN		0x1e0
#define REG_DPU_INT_CLR		0x1e4
#define REG_DPU_INT_STS		0x1e8
#define REG_DPI_H_TIMING	0x1f4
#define REG_DPI_V_TIMING	0x1f8

#define DPU_CTRL_RUN		BIT(0)
#define DPU_CTRL_REG_UPDATE	BIT(2)
#define DPU_CFG0_IF_EDPI	BIT(0)

#define INT_DONE		BIT(0)
#define INT_TE			BIT(1)
#define INT_ERR			BIT(2)	/* layer FIFO underflow */
#define INT_UPDATE_DONE		BIT(4)
#define INT_VSYNC		BIT(5)

#define LAY_EN			BIT(0)
#define LAY_ALPHA_LAYER		(1 << 2)	/* use layer alpha only */
#define LAY_ALPHA_COMBO		(2 << 2)	/* pixel alpha * layer alpha */
#define LAY_FMT_ARGB8888	(3 << 4)
#define LAY_FMT_RGB565		(4 << 4)
#define LAY_ENDIAN_B3B2B1B0	(1 << 8)
#define LAY_RB_SWITCH		BIT(10)
#define LAY_BLEND_PREMULT	BIT(16)

/* ---- display IOMMU (VAU) at DPU + 0x800 ------------------------------- */
#define VAU_CFG			0x04
#define VAU_EN			BIT(0)
#define VAU_GATE_EN		BIT(1)

#define NUM_PLANES		4

/* ---- Unisoc DSI r3p1 host registers (LP cmd TX during video blanking) --- */
#define DSI_REG_VID_MODE_CFG		0x38
#define DSI_VID_LP_CMD_EN		BIT(15)
#define DSI_REG_GEN_HDR			0x6c
#define DSI_REG_GEN_PLD_DATA		0x70
#define DSI_REG_CMD_MODE_STATUS		0x98
#define DSI_GEN_WDATA_FIFO_EMPTY	BIT(3)
#define DSI_GEN_CMD_FIFO_EMPTY		BIT(5)

enum dpu_panel_type {
	DPU_PANEL_NT36523B = 0,
	DPU_PANEL_HX83102E,
	DPU_PANEL_FT8201AB,
};

struct dpu_dsi_cmd {
	u8 type;
	u8 len;
	u8 data[2];
	u16 delay_ms;
};

struct ums512_dpu {
	struct drm_device drm;
	void __iomem *base;
	void __iomem *mmu;
	void __iomem *dsi;
	int irq;

	struct drm_crtc crtc;
	struct drm_encoder encoder;
	struct drm_connector connector;
	struct drm_display_mode mode;
	u32 width_mm, height_mm;

	struct backlight_device *bl_dev;
	struct mutex dsi_lock;		/* serializes DSI TX & panel state */
	enum dpu_panel_type panel_type;
	bool crtc_enabled;
	bool panel_asleep;

	spinlock_t lock;		/* protects event, int_en */
	struct drm_pending_vblank_event *event;
	u32 int_en;
	unsigned long underflows;
};

#define to_dpu(dev) container_of(dev, struct ums512_dpu, drm)

/* ---- MIPI-DSI DCS panel & backlight control ---------------------------- */

static enum dpu_panel_type dpu_detect_panel_type(void)
{
	if (strstr(saved_command_line, "hx83102e"))
		return DPU_PANEL_HX83102E;
	if (strstr(saved_command_line, "ft8201ab"))
		return DPU_PANEL_FT8201AB;
	return DPU_PANEL_NT36523B;
}

static const char *dpu_panel_name(enum dpu_panel_type type)
{
	switch (type) {
	case DPU_PANEL_HX83102E:
		return "hx83102e";
	case DPU_PANEL_FT8201AB:
		return "ft8201ab";
	case DPU_PANEL_NT36523B:
	default:
		return "nt36523b";
	}
}

static int dpu_dsi_write_locked(struct ums512_dpu *dpu, u8 type,
				const u8 *buf, size_t len)
{
	u32 val, hdr;
	size_t i;
	int ret;

	if (!dpu->dsi)
		return -ENODEV;

	/*
	 * Ensure LP command transmission during video blanking without
	 * touching SOFT_RESET, DSI_MODE_CFG, or PHY_INTERFACE_CTRL.
	 */
	val = readl(dpu->dsi + DSI_REG_VID_MODE_CFG);
	if (!(val & DSI_VID_LP_CMD_EN))
		writel(val | DSI_VID_LP_CMD_EN, dpu->dsi + DSI_REG_VID_MODE_CFG);

	if (type == MIPI_DSI_DCS_LONG_WRITE ||
	    type == MIPI_DSI_GENERIC_LONG_WRITE) {
		ret = readl_poll_timeout(dpu->dsi + DSI_REG_CMD_MODE_STATUS,
					 val, val & DSI_GEN_WDATA_FIFO_EMPTY,
					 10, 50000);
		if (ret) {
			drm_err_ratelimited(&dpu->drm,
					    "DSI TX payload FIFO timeout\n");
			return ret;
		}

		for (i = 0; i < len; i += 4) {
			u32 payload = 0;
			size_t j;

			for (j = 0; j < 4 && (i + j) < len; j++)
				payload |= (u32)buf[i + j] << (j * 8);
			writel(payload, dpu->dsi + DSI_REG_GEN_PLD_DATA);
		}

		hdr = type | ((len & 0xff) << 8) | (((len >> 8) & 0xff) << 16);
	} else {
		u8 b0 = len > 0 ? buf[0] : 0;
		u8 b1 = len > 1 ? buf[1] : 0;

		hdr = type | ((u32)b0 << 8) | ((u32)b1 << 16);
	}

	ret = readl_poll_timeout(dpu->dsi + DSI_REG_CMD_MODE_STATUS, val,
				 val & DSI_GEN_CMD_FIFO_EMPTY, 10, 50000);
	if (ret) {
		drm_err_ratelimited(&dpu->drm, "DSI TX cmd FIFO timeout\n");
		return ret;
	}

	writel(hdr, dpu->dsi + DSI_REG_GEN_HDR);

	ret = readl_poll_timeout(dpu->dsi + DSI_REG_CMD_MODE_STATUS, val,
				 val & DSI_GEN_CMD_FIFO_EMPTY, 10, 50000);
	if (ret)
		drm_err_ratelimited(&dpu->drm, "DSI TX drain timeout\n");

	return ret;
}

static int dpu_dsi_send_seq_locked(struct ums512_dpu *dpu,
				   const struct dpu_dsi_cmd *cmds, size_t n)
{
	size_t i;
	int ret;

	for (i = 0; i < n; i++) {
		ret = dpu_dsi_write_locked(dpu, cmds[i].type, cmds[i].data,
					   cmds[i].len);
		if (ret)
			return ret;
		if (cmds[i].delay_ms)
			msleep(cmds[i].delay_ms);
	}

	return 0;
}

static const struct dpu_dsi_cmd nt36523b_unlock_cmds[] = {
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xff, 0x10 }, 0 },
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xf0, 0x55 }, 0 },
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xf1, 0xaa }, 0 },
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xf2, 0x66 }, 0 },
};

static const struct dpu_dsi_cmd nt36523b_lock_cmds[] = {
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xff, 0x10 }, 0 },
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xf0, 0xaa }, 0 },
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xf1, 0x55 }, 0 },
	{ MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM, 2, { 0xf2, 0x99 }, 0 },
};

static int dpu_bl_set_hw_locked(struct ums512_dpu *dpu, u8 level)
{
	u8 cmd12[3];
	u8 cmd8[2];
	u16 val12;
	int ret;

	if (!dpu->dsi)
		return 0;

	if (dpu->panel_type == DPU_PANEL_FT8201AB) {
		cmd8[0] = MIPI_DCS_SET_DISPLAY_BRIGHTNESS;
		cmd8[1] = level;
		return dpu_dsi_write_locked(dpu, MIPI_DSI_DCS_SHORT_WRITE_PARAM,
					    cmd8, sizeof(cmd8));
	}

	val12 = level ? min_t(u16, ((u16)level << 4) | (level >> 4), 0x0ffe) : 0;
	cmd12[0] = MIPI_DCS_SET_DISPLAY_BRIGHTNESS;
	cmd12[1] = val12 >> 8;
	cmd12[2] = val12 & 0xff;

	if (dpu->panel_type == DPU_PANEL_NT36523B) {
		ret = dpu_dsi_send_seq_locked(dpu, nt36523b_unlock_cmds,
					      ARRAY_SIZE(nt36523b_unlock_cmds));
		if (ret)
			return ret;
	}

	ret = dpu_dsi_write_locked(dpu, MIPI_DSI_DCS_LONG_WRITE,
				   cmd12, sizeof(cmd12));

	if (dpu->panel_type == DPU_PANEL_NT36523B && !ret)
		ret = dpu_dsi_send_seq_locked(dpu, nt36523b_lock_cmds,
					      ARRAY_SIZE(nt36523b_lock_cmds));

	return ret;
}

static int dpu_bl_update_status(struct backlight_device *bl)
{
	struct ums512_dpu *dpu = bl_get_data(bl);
	int level = backlight_get_brightness(bl);
	int ret = 0;

	mutex_lock(&dpu->dsi_lock);
	if (dpu->crtc_enabled && !dpu->panel_asleep)
		ret = dpu_bl_set_hw_locked(dpu, clamp_t(int, level, 0, 255));
	mutex_unlock(&dpu->dsi_lock);

	return ret;
}

static const struct backlight_ops dpu_bl_ops = {
	.update_status = dpu_bl_update_status,
};

static const struct dpu_dsi_cmd nt36523b_sleep_in_cmds[] = {
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_SET_DISPLAY_OFF }, 50 },
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_ENTER_SLEEP_MODE }, 120 },
};

static const struct dpu_dsi_cmd nt36523b_sleep_out_cmds[] = {
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_EXIT_SLEEP_MODE }, 100 },
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_SET_DISPLAY_ON }, 20 },
};

static const struct dpu_dsi_cmd hx83102e_sleep_in_cmds[] = {
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_SET_DISPLAY_OFF }, 20 },
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_ENTER_SLEEP_MODE }, 120 },
};

static const struct dpu_dsi_cmd hx83102e_sleep_out_cmds[] = {
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_EXIT_SLEEP_MODE }, 50 },
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_SET_DISPLAY_ON }, 20 },
};

static const struct dpu_dsi_cmd ft8201ab_sleep_in_cmds[] = {
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_SET_DISPLAY_OFF }, 20 },
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_ENTER_SLEEP_MODE }, 140 },
};

static const struct dpu_dsi_cmd ft8201ab_sleep_out_cmds[] = {
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_EXIT_SLEEP_MODE }, 90 },
	{ MIPI_DSI_DCS_SHORT_WRITE, 1, { MIPI_DCS_SET_DISPLAY_ON }, 20 },
};

static void dpu_panel_sleep_in_locked(struct ums512_dpu *dpu)
{
	int ret = 0;

	if (!dpu->dsi || dpu->panel_asleep)
		return;

	dpu_bl_set_hw_locked(dpu, 0);

	if (!panel_sleep)
		return;

	switch (dpu->panel_type) {
	case DPU_PANEL_HX83102E:
		ret = dpu_dsi_send_seq_locked(dpu, hx83102e_sleep_in_cmds,
					      ARRAY_SIZE(hx83102e_sleep_in_cmds));
		break;
	case DPU_PANEL_FT8201AB:
		ret = dpu_dsi_send_seq_locked(dpu, ft8201ab_sleep_in_cmds,
					      ARRAY_SIZE(ft8201ab_sleep_in_cmds));
		break;
	case DPU_PANEL_NT36523B:
	default:
		ret = dpu_dsi_send_seq_locked(dpu, nt36523b_lock_cmds,
					      ARRAY_SIZE(nt36523b_lock_cmds));
		if (!ret)
			ret = dpu_dsi_send_seq_locked(dpu, nt36523b_sleep_in_cmds,
						      ARRAY_SIZE(nt36523b_sleep_in_cmds));
		break;
	}

	if (ret)
		drm_warn(&dpu->drm, "panel sleep-in failed (%d)\n", ret);
	else
		dpu->panel_asleep = true;
}

static void dpu_panel_sleep_out_locked(struct ums512_dpu *dpu)
{
	int ret = 0;

	if (!dpu->dsi || !dpu->panel_asleep)
		return;

	switch (dpu->panel_type) {
	case DPU_PANEL_HX83102E:
		ret = dpu_dsi_send_seq_locked(dpu, hx83102e_sleep_out_cmds,
					      ARRAY_SIZE(hx83102e_sleep_out_cmds));
		break;
	case DPU_PANEL_FT8201AB:
		ret = dpu_dsi_send_seq_locked(dpu, ft8201ab_sleep_out_cmds,
					      ARRAY_SIZE(ft8201ab_sleep_out_cmds));
		break;
	case DPU_PANEL_NT36523B:
	default:
		ret = dpu_dsi_send_seq_locked(dpu, nt36523b_sleep_out_cmds,
					      ARRAY_SIZE(nt36523b_sleep_out_cmds));
		if (!ret)
			ret = dpu_dsi_send_seq_locked(dpu, nt36523b_unlock_cmds,
						      ARRAY_SIZE(nt36523b_unlock_cmds));
		break;
	}

	if (ret)
		drm_warn(&dpu->drm, "panel sleep-out failed (%d)\n", ret);
	dpu->panel_asleep = false;
}

static const u32 dpu_formats[] = {
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_ABGR8888,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
};

static const u64 dpu_modifiers[] = {
	DRM_FORMAT_MOD_LINEAR,
	DRM_FORMAT_MOD_INVALID
};

static inline void lay_wr(struct ums512_dpu *dpu, unsigned int idx,
			  u32 reg, u32 val)
{
	writel(val, dpu->base + reg + idx * LAY_STRIDE);
}

static void dpu_int_update(struct ums512_dpu *dpu, u32 set, u32 clr)
{
	unsigned long flags;

	spin_lock_irqsave(&dpu->lock, flags);
	dpu->int_en = (dpu->int_en & ~clr) | set;
	writel(dpu->int_en, dpu->base + REG_DPU_INT_EN);
	spin_unlock_irqrestore(&dpu->lock, flags);
}

/* ---- planes ------------------------------------------------------------ */

static u32 dpu_fmt_bits(u32 fourcc)
{
	switch (fourcc) {
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
		return LAY_FMT_ARGB8888 | LAY_RB_SWITCH;
	case DRM_FORMAT_RGB565:
		return LAY_FMT_RGB565;
	case DRM_FORMAT_BGR565:
		return LAY_FMT_RGB565 | LAY_RB_SWITCH;
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_ARGB8888:
	default:
		return LAY_FMT_ARGB8888;
	}
}

static int dpu_plane_atomic_check(struct drm_plane *plane,
				  struct drm_atomic_commit *state)
{
	struct drm_plane_state *new = drm_atomic_get_new_plane_state(state, plane);
	struct drm_crtc_state *crtc_state = NULL;
	struct drm_framebuffer *fb = new->fb;
	bool primary = plane->type == DRM_PLANE_TYPE_PRIMARY;
	int ret;

	if (new->crtc)
		crtc_state = drm_atomic_get_new_crtc_state(state, new->crtc);

	/* No scaler in the layer path: src must equal dst. */
	ret = drm_atomic_helper_check_plane_state(new, crtc_state,
						  DRM_PLANE_NO_SCALING,
						  DRM_PLANE_NO_SCALING,
						  !primary, true);
	if (ret || !new->visible)
		return ret;

	if (fb->pitches[0] % fb->format->cpp[0])
		return -EINVAL;
	if (fb->pitches[0] / fb->format->cpp[0] > 0xffff)
		return -EINVAL;

	return 0;
}

static void dpu_plane_atomic_update(struct drm_plane *plane,
				    struct drm_atomic_commit *state)
{
	struct ums512_dpu *dpu = to_dpu(plane->dev);
	struct drm_plane_state *s = drm_atomic_get_new_plane_state(state, plane);
	struct drm_framebuffer *fb = s->fb;
	unsigned int idx = plane->index;
	u32 w, h, x, y, ctrl;
	dma_addr_t addr;

	if (!s->visible) {
		lay_wr(dpu, idx, REG_LAY_CTRL, 0);
		return;
	}

	/* Clipped rectangles (visible part only). */
	x = s->dst.x1;
	y = s->dst.y1;
	w = drm_rect_width(&s->dst);
	h = drm_rect_height(&s->dst);

	/* Point the base at the first visible source pixel. */
	addr = drm_fb_dma_get_gem_addr(fb, s, 0);

	ctrl = LAY_EN | dpu_fmt_bits(fb->format->format);
	if (fb->format->has_alpha &&
	    s->pixel_blend_mode != DRM_MODE_BLEND_PIXEL_NONE) {
		ctrl |= LAY_ALPHA_COMBO;
		if (s->pixel_blend_mode == DRM_MODE_BLEND_PREMULTI)
			ctrl |= LAY_BLEND_PREMULT;
	} else {
		ctrl |= LAY_ALPHA_LAYER;
	}

	lay_wr(dpu, idx, REG_LAY_BASE_ADDR0, lower_32_bits(addr));
	lay_wr(dpu, idx, REG_LAY_POS, x | y << 16);
	lay_wr(dpu, idx, REG_LAY_SIZE, w | h << 16);
	lay_wr(dpu, idx, REG_LAY_CROP_START, 0);
	lay_wr(dpu, idx, REG_LAY_PITCH, fb->pitches[0] / fb->format->cpp[0]);
	lay_wr(dpu, idx, REG_LAY_ALPHA, s->alpha >> 8);
	lay_wr(dpu, idx, REG_LAY_CTRL, ctrl);
}

static void dpu_plane_atomic_disable(struct drm_plane *plane,
				     struct drm_atomic_commit *state)
{
	struct ums512_dpu *dpu = to_dpu(plane->dev);

	lay_wr(dpu, plane->index, REG_LAY_CTRL, 0);
}

static bool dpu_plane_format_mod_supported(struct drm_plane *plane, u32 format,
					   u64 modifier)
{
	return modifier == DRM_FORMAT_MOD_LINEAR;
}

static const struct drm_plane_helper_funcs dpu_plane_helper_funcs = {
	.atomic_check	= dpu_plane_atomic_check,
	.atomic_update	= dpu_plane_atomic_update,
	.atomic_disable	= dpu_plane_atomic_disable,
};

static const struct drm_plane_funcs dpu_plane_funcs = {
	.update_plane		= drm_atomic_helper_update_plane,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.atomic_duplicate_state	= drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
	.format_mod_supported	= dpu_plane_format_mod_supported,
};

/* ---- CRTC -------------------------------------------------------------- */

static void dpu_latch(struct ums512_dpu *dpu)
{
	writel(readl(dpu->base + REG_DPU_CTRL) | DPU_CTRL_REG_UPDATE,
	       dpu->base + REG_DPU_CTRL);
}

static enum drm_mode_status dpu_crtc_mode_valid(struct drm_crtc *crtc,
						const struct drm_display_mode *m)
{
	struct ums512_dpu *dpu = to_dpu(crtc->dev);

	/* The link is fixed by the bootloader. */
	if (m->hdisplay != dpu->mode.hdisplay ||
	    m->vdisplay != dpu->mode.vdisplay)
		return MODE_BAD;
	return MODE_OK;
}

static int dpu_crtc_atomic_check(struct drm_crtc *crtc,
				 struct drm_atomic_commit *state)
{
	struct drm_crtc_state *cs = drm_atomic_get_new_crtc_state(state, crtc);

	if (!cs->enable)
		return 0;
	/* A visible primary plane is required: the DPU has no "off" state. */
	return drm_atomic_helper_check_crtc_primary_plane(cs);
}

static void dpu_crtc_atomic_enable(struct drm_crtc *crtc,
				   struct drm_atomic_commit *state)
{
	struct ums512_dpu *dpu = to_dpu(crtc->dev);

	writel(readl(dpu->base + REG_DPU_CTRL) | DPU_CTRL_RUN,
	       dpu->base + REG_DPU_CTRL);
	dpu_int_update(dpu, INT_UPDATE_DONE | INT_ERR, 0);
	drm_crtc_vblank_on(crtc);

	mutex_lock(&dpu->dsi_lock);
	dpu->crtc_enabled = true;
	if (!dpu->panel_asleep && dpu->bl_dev)
		dpu_bl_set_hw_locked(dpu, clamp_t(int,
						  backlight_get_brightness(dpu->bl_dev),
						  0, 255));
	mutex_unlock(&dpu->dsi_lock);
}

static void dpu_crtc_atomic_disable(struct drm_crtc *crtc,
				    struct drm_atomic_commit *state)
{
	struct ums512_dpu *dpu = to_dpu(crtc->dev);
	struct drm_pending_vblank_event *event;
	unsigned int i;

	mutex_lock(&dpu->dsi_lock);
	dpu->crtc_enabled = false;
	if (dpu->dsi && !dpu->panel_asleep)
		dpu_bl_set_hw_locked(dpu, 0);
	mutex_unlock(&dpu->dsi_lock);

	/*
	 * Stopping the DPU would break the bootloader-owned DSI video stream
	 * and we cannot restart the panel, so "off" means: turn off backlight,
	 * blank all layers, and keep scanning out the black background.
	 */
	for (i = 0; i < LAY_HW_MAX; i++)
		lay_wr(dpu, i, REG_LAY_CTRL, 0);
	dpu_latch(dpu);

	dpu_int_update(dpu, 0, INT_UPDATE_DONE | INT_ERR);
	synchronize_irq(dpu->irq);

	spin_lock_irq(&crtc->dev->event_lock);
	event = dpu->event;
	dpu->event = NULL;
	if (event)
		drm_crtc_send_vblank_event(crtc, event);
	spin_unlock_irq(&crtc->dev->event_lock);
	if (event)
		drm_crtc_vblank_put(crtc);

	drm_crtc_vblank_off(crtc);

	spin_lock_irq(&crtc->dev->event_lock);
	if (crtc->state->event && !crtc->state->active) {
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		crtc->state->event = NULL;
	}
	spin_unlock_irq(&crtc->dev->event_lock);
}

static void dpu_crtc_atomic_flush(struct drm_crtc *crtc,
				  struct drm_atomic_commit *state)
{
	struct ums512_dpu *dpu = to_dpu(crtc->dev);
	struct drm_pending_vblank_event *event = crtc->state->event;
	unsigned long flags;

	if (!crtc->state->active)
		return;

	if (event) {
		crtc->state->event = NULL;
		spin_lock_irqsave(&crtc->dev->event_lock, flags);
		if (drm_crtc_vblank_get(crtc) == 0)
			dpu->event = event;	/* completed by UPDATE_DONE irq */
		else
			drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irqrestore(&crtc->dev->event_lock, flags);
	}

	/* All layer registers are shadowed; latch them at the next frame. */
	dpu_latch(dpu);
}

static int dpu_enable_vblank(struct drm_crtc *crtc)
{
	dpu_int_update(to_dpu(crtc->dev), INT_VSYNC, 0);
	return 0;
}

static void dpu_disable_vblank(struct drm_crtc *crtc)
{
	dpu_int_update(to_dpu(crtc->dev), 0, INT_VSYNC);
}

static const struct drm_crtc_helper_funcs dpu_crtc_helper_funcs = {
	.mode_valid	= dpu_crtc_mode_valid,
	.atomic_check	= dpu_crtc_atomic_check,
	.atomic_flush	= dpu_crtc_atomic_flush,
	.atomic_enable	= dpu_crtc_atomic_enable,
	.atomic_disable	= dpu_crtc_atomic_disable,
};

static const struct drm_crtc_funcs dpu_crtc_funcs = {
	.reset			= drm_atomic_helper_crtc_reset,
	.set_config		= drm_atomic_helper_set_config,
	.page_flip		= drm_atomic_helper_page_flip,
	.atomic_duplicate_state	= drm_atomic_helper_crtc_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_crtc_destroy_state,
	.enable_vblank		= dpu_enable_vblank,
	.disable_vblank		= dpu_disable_vblank,
};

static irqreturn_t dpu_irq(int irq, void *data)
{
	struct ums512_dpu *dpu = data;
	struct drm_pending_vblank_event *event;
	u32 sts = readl(dpu->base + REG_DPU_INT_STS);

	if (!sts)
		return IRQ_NONE;
	writel(sts, dpu->base + REG_DPU_INT_CLR);

	if (sts & INT_VSYNC)
		drm_crtc_handle_vblank(&dpu->crtc);

	if (sts & INT_UPDATE_DONE) {
		spin_lock(&dpu->drm.event_lock);
		event = dpu->event;
		dpu->event = NULL;
		if (event)
			drm_crtc_send_vblank_event(&dpu->crtc, event);
		spin_unlock(&dpu->drm.event_lock);
		if (event)
			drm_crtc_vblank_put(&dpu->crtc);
	}

	if (sts & INT_ERR) {
		dpu->underflows++;
		drm_err_ratelimited(&dpu->drm, "layer FIFO underflow (%lu)\n",
				     dpu->underflows);
	}

	return IRQ_HANDLED;
}

/* ---- connector ---------------------------------------------------------- */

static int dpu_conn_get_modes(struct drm_connector *connector)
{
	struct ums512_dpu *dpu = to_dpu(connector->dev);

	return drm_connector_helper_get_modes_fixed(connector, &dpu->mode);
}

static const struct drm_connector_helper_funcs dpu_conn_helper_funcs = {
	.get_modes = dpu_conn_get_modes,
};

static const struct drm_connector_funcs dpu_conn_funcs = {
	.reset			= drm_atomic_helper_connector_reset,
	.fill_modes		= drm_helper_probe_single_connector_modes,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
};

/* Enable the CRTC (vblank on) before planes are flushed. */
static const struct drm_mode_config_helper_funcs dpu_mode_config_helpers = {
	.atomic_commit_tail = drm_atomic_helper_commit_tail_rpm,
};

static const struct drm_mode_config_funcs dpu_mode_config_funcs = {
	.fb_create	= drm_gem_fb_create_with_dirty,
	.atomic_check	= drm_atomic_helper_check,
	.atomic_commit	= drm_atomic_helper_commit,
};

DEFINE_DRM_GEM_DMA_FOPS(dpu_fops);

static const struct drm_driver dpu_drm_driver = {
	.driver_features = DRIVER_GEM | DRIVER_MODESET | DRIVER_ATOMIC,
	.fops	= &dpu_fops,
	.name	= DRIVER_NAME,
	.desc	= DRIVER_DESC,
	.major	= 1,
	.minor	= 0,
	DRM_GEM_DMA_DRIVER_OPS,
	DRM_FBDEV_DMA_DRIVER_OPS,
};

/* ---- probe -------------------------------------------------------------- */

static int dpu_read_mode(struct ums512_dpu *dpu, struct clk *dpi_clk)
{
	struct drm_device *drm = &dpu->drm;
	struct drm_display_mode *m = &dpu->mode;
	u32 size = readl(dpu->base + REG_PANEL_SIZE);
	u32 ht = readl(dpu->base + REG_DPI_H_TIMING);
	u32 vt = readl(dpu->base + REG_DPI_V_TIMING);
	u32 hact = size & 0xffff, vact = size >> 16;

	if (!hact || !vact) {
		drm_err(drm, "DPU not initialised by the bootloader (PANEL_SIZE=0)\n");
		return -ENODEV;
	}
	if (readl(dpu->base + REG_DPU_CFG0) & DPU_CFG0_IF_EDPI) {
		drm_err(drm, "DPU in command (EDPI) mode, unsupported\n");
		return -ENODEV;
	}

	m->hdisplay = hact;
	m->hsync_start = hact + ((ht >> 20) & 0xfff);	/* front porch */
	m->hsync_end = m->hsync_start + (ht & 0xff);	/* sync */
	m->htotal = m->hsync_end + ((ht >> 8) & 0xfff);	/* back porch */
	m->vdisplay = vact;
	m->vsync_start = vact + ((vt >> 20) & 0xfff);
	m->vsync_end = m->vsync_start + (vt & 0xff);
	m->vtotal = m->vsync_end + ((vt >> 8) & 0xfff);

	if (m->htotal == hact || m->vtotal == vact) {
		/* Timings unreadable: fall back to a nominal 60 Hz. */
		m->hsync_start = m->hsync_end = m->htotal = hact;
		m->vsync_start = m->vsync_end = m->vtotal = vact;
	}
	m->clock = DIV_ROUND_UP((unsigned long)m->htotal * m->vtotal * 60, 1000);
	m->type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED;
	m->width_mm = dpu->width_mm;
	m->height_mm = dpu->height_mm;
	drm_mode_set_name(m);

	drm_info(drm, "adopted mode " DRM_MODE_FMT " (H=%08x V=%08x)\n",
		 DRM_MODE_ARG(m), ht, vt);
	return 0;
}

static int dpu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ums512_dpu *dpu;
	struct drm_device *drm;
	struct drm_plane *primary = NULL;
	struct clk_bulk_data *clks;
	struct clk *dpi_clk;
	struct device_node *fb_np;
	struct resource fb_res;
	unsigned int i;
	int ret;

	dpu = devm_drm_dev_alloc(dev, &dpu_drm_driver, struct ums512_dpu, drm);
	if (IS_ERR(dpu))
		return PTR_ERR(dpu);
	drm = &dpu->drm;
	spin_lock_init(&dpu->lock);
	mutex_init(&dpu->dsi_lock);
	dpu->crtc_enabled = true;
	dpu->panel_type = dpu_detect_panel_type();
	platform_set_drvdata(pdev, drm);

	/* The DPU master port carries 32-bit addresses. */
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	/* Plain ioremap: the vendor "dpu"/"iommu" nodes describe these too. */
	dpu->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(dpu->base))
		return PTR_ERR(dpu->base);
	dpu->mmu = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(dpu->mmu))
		dpu->mmu = NULL;
	if (platform_get_resource(pdev, IORESOURCE_MEM, 2)) {
		dpu->dsi = devm_platform_ioremap_resource(pdev, 2);
		if (IS_ERR(dpu->dsi))
			dpu->dsi = NULL;
	}

	ret = devm_clk_bulk_get_all_enabled(dev, &clks);
	if (ret < 0)
		return dev_err_probe(dev, ret, "clocks\n");
	dpi_clk = devm_clk_get_optional(dev, "dpi");
	if (IS_ERR(dpi_clk))
		dpi_clk = NULL;

	of_property_read_u32(dev->of_node, "width-mm", &dpu->width_mm);
	of_property_read_u32(dev->of_node, "height-mm", &dpu->height_mm);

	ret = dpu_read_mode(dpu, dpi_clk);
	if (ret)
		return ret;

	dpu->irq = platform_get_irq(pdev, 0);
	if (dpu->irq < 0)
		return dpu->irq;

	ret = drmm_mode_config_init(drm);
	if (ret)
		return ret;
	drm->mode_config.min_width = 1;
	drm->mode_config.min_height = 1;
	drm->mode_config.max_width = 4096;
	drm->mode_config.max_height = 4096;
	drm->mode_config.preferred_depth = 24;
	drm->mode_config.funcs = &dpu_mode_config_funcs;
	drm->mode_config.helper_private = &dpu_mode_config_helpers;

	for (i = 0; i < NUM_PLANES; i++) {
		enum drm_plane_type type = i ? DRM_PLANE_TYPE_OVERLAY :
					       DRM_PLANE_TYPE_PRIMARY;
		struct drm_plane *plane;

		plane = drmm_universal_plane_alloc(drm, struct drm_plane, dev,
						   1, &dpu_plane_funcs,
						   dpu_formats,
						   ARRAY_SIZE(dpu_formats),
						   dpu_modifiers, type, NULL);
		if (IS_ERR(plane))
			return PTR_ERR(plane);
		drm_plane_helper_add(plane, &dpu_plane_helper_funcs);
		/* HW blends layers strictly in index order. */
		drm_plane_create_zpos_immutable_property(plane, i);
		drm_plane_create_alpha_property(plane);
		drm_plane_create_blend_mode_property(plane,
				BIT(DRM_MODE_BLEND_PIXEL_NONE) |
				BIT(DRM_MODE_BLEND_PREMULTI) |
				BIT(DRM_MODE_BLEND_COVERAGE));
		if (!i)
			primary = plane;
	}

	ret = drmm_crtc_init_with_planes(drm, &dpu->crtc, primary, NULL,
					 &dpu_crtc_funcs, NULL);
	if (ret)
		return ret;
	drm_crtc_helper_add(&dpu->crtc, &dpu_crtc_helper_funcs);

	ret = drmm_encoder_init(drm, &dpu->encoder, NULL,
				DRM_MODE_ENCODER_DSI, NULL);
	if (ret)
		return ret;
	dpu->encoder.possible_crtcs = drm_crtc_mask(&dpu->crtc);

	ret = drmm_connector_init(drm, &dpu->connector, &dpu_conn_funcs,
				  DRM_MODE_CONNECTOR_DSI, NULL);
	if (ret)
		return ret;
	drm_connector_helper_add(&dpu->connector, &dpu_conn_helper_funcs);
	dpu->connector.status = connector_status_connected;
	ret = drm_connector_attach_encoder(&dpu->connector, &dpu->encoder);
	if (ret)
		return ret;

	ret = drm_vblank_init(drm, 1);
	if (ret)
		return ret;

	/* Quiesce interrupts before hooking the handler. */
	writel(0, dpu->base + REG_DPU_INT_EN);
	writel(0xffffffff, dpu->base + REG_DPU_INT_CLR);
	ret = devm_request_irq(dev, dpu->irq, dpu_irq, 0, DRIVER_NAME, dpu);
	if (ret)
		return ret;

	drm_mode_config_reset(drm);

	/* Take the scanout over from the boot framebuffer. */
	fb_np = of_parse_phandle(dev->of_node, "sprd,boot-framebuffer", 0);
	if (fb_np) {
		if (!of_address_to_resource(fb_np, 0, &fb_res))
			aperture_remove_conflicting_devices(fb_res.start,
							    resource_size(&fb_res),
							    DRIVER_NAME);
		of_node_put(fb_np);
	}

	/*
	 * Our buffers are physical addresses: blank stray layers, put the
	 * display IOMMU in bypass and latch, all before userspace commits.
	 */
	for (i = 1; i < LAY_HW_MAX; i++)
		lay_wr(dpu, i, REG_LAY_CTRL, 0);
	writel(0, dpu->base + REG_BG_COLOR);
	/* AXI QoS from the vendor r4p0 driver; avoids layer FIFO underflow. */
	writel((0xa << 12) | (0xa << 8) | (0xd << 4) | 0xc | BIT(18) | BIT(22),
	       dpu->base + REG_DPU_CFG1);
	writel(0x14002, dpu->base + REG_DPU_CFG2);
	if (dpu->mmu) {
		u32 cfg = readl(dpu->mmu + VAU_CFG);

		if (cfg & VAU_EN)
			drm_info(drm, "display IOMMU was enabled by bootloader, bypassing\n");
		/* Layer 0 still points at the splash; disable it with the IOMMU. */
		lay_wr(dpu, 0, REG_LAY_CTRL, 0);
		dpu_latch(dpu);
		writel(cfg & ~(VAU_EN | VAU_GATE_EN), dpu->mmu + VAU_CFG);
	}

	drm_info(drm, "DPU version %08x\n", readl(dpu->base + REG_DPU_VERSION));

	if (dpu->dsi) {
		struct backlight_properties bl_props = {
			.type = BACKLIGHT_RAW,
			.max_brightness = 255,
			.brightness = 150,
		};

		dpu->bl_dev = devm_backlight_device_register(dev,
							     "ums512-dpu-backlight",
							     dev, dpu,
							     &dpu_bl_ops,
							     &bl_props);
		if (IS_ERR(dpu->bl_dev)) {
			drm_warn(drm, "failed to register backlight (%ld)\n",
				 PTR_ERR(dpu->bl_dev));
			dpu->bl_dev = NULL;
		} else {
			drm_info(drm, "MIPI-DSI DCS backlight registered (panel %s)\n",
				 dpu_panel_name(dpu->panel_type));
			backlight_update_status(dpu->bl_dev);
		}
	}

	ret = drm_dev_register(drm, 0);
	if (ret)
		return ret;

	drm_client_setup(drm, NULL);
	return 0;
}

static void dpu_remove(struct platform_device *pdev)
{
	struct drm_device *drm = platform_get_drvdata(pdev);

	drm_dev_unplug(drm);
	drm_atomic_helper_shutdown(drm);
}

static void dpu_shutdown(struct platform_device *pdev)
{
	drm_atomic_helper_shutdown(platform_get_drvdata(pdev));
}

static int dpu_pm_suspend(struct device *dev)
{
	struct drm_device *drm = dev_get_drvdata(dev);
	struct ums512_dpu *dpu = to_dpu(drm);
	int ret;

	ret = drm_mode_config_helper_suspend(drm);
	if (ret)
		return ret;

	mutex_lock(&dpu->dsi_lock);
	dpu_panel_sleep_in_locked(dpu);
	mutex_unlock(&dpu->dsi_lock);

	return 0;
}

static int dpu_pm_resume(struct device *dev)
{
	struct drm_device *drm = dev_get_drvdata(dev);
	struct ums512_dpu *dpu = to_dpu(drm);

	mutex_lock(&dpu->dsi_lock);
	dpu_panel_sleep_out_locked(dpu);
	mutex_unlock(&dpu->dsi_lock);

	return drm_mode_config_helper_resume(drm);
}

static DEFINE_SIMPLE_DEV_PM_OPS(dpu_pm_ops, dpu_pm_suspend, dpu_pm_resume);

static const struct of_device_id dpu_of_match[] = {
	{ .compatible = "sprd,ums512-dpu-kms" },
	{ }
};
MODULE_DEVICE_TABLE(of, dpu_of_match);

static struct platform_driver dpu_platform_driver = {
	.probe		= dpu_probe,
	.remove		= dpu_remove,
	.shutdown	= dpu_shutdown,
	.driver = {
		.name		= DRIVER_NAME,
		.pm		= pm_sleep_ptr(&dpu_pm_ops),
		.of_match_table	= dpu_of_match,
	},
};
module_platform_driver(dpu_platform_driver);

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
