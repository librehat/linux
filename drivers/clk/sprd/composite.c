// SPDX-License-Identifier: GPL-2.0
//
// Spreadtrum composite clock driver
//
// Copyright (C) 2017 Spreadtrum, Inc.
// Author: Chunyan Zhang <chunyan.zhang@spreadtrum.com>

#include <linux/clk-provider.h>
#include <linux/limits.h>

#include "composite.h"

static int sprd_comp_determine_rate(struct clk_hw *hw,
				    struct clk_rate_request *req)
{
	struct sprd_comp *cc = hw_to_sprd_comp(hw);
	struct clk_hw *best_parent = NULL, *lowest_parent = NULL;
	unsigned long best_parent_rate = 0, lowest_parent_rate = 0;
	unsigned long best_rate = 0, lowest_rate = ULONG_MAX;
	unsigned long flags = clk_hw_get_flags(hw);
	unsigned int num_parents = clk_hw_get_num_parents(hw);
	unsigned int i;

	if ((flags & CLK_SET_RATE_NO_REPARENT) || num_parents <= 1)
		return divider_determine_rate(hw, req, NULL, cc->div.width, 0);

	for (i = 0; i < num_parents; i++) {
		struct clk_rate_request tmp_req = *req;
		struct clk_hw *parent;
		int ret;

		parent = clk_hw_get_parent_by_index(hw, i);
		if (!parent)
			continue;

		tmp_req.best_parent_hw = parent;
		tmp_req.best_parent_rate = clk_hw_get_rate(parent);
		if (!tmp_req.best_parent_rate && !(flags & CLK_SET_RATE_PARENT))
			continue;

		ret = divider_determine_rate(hw, &tmp_req, NULL, cc->div.width, 0);
		if (ret || !tmp_req.rate)
			continue;

		if (tmp_req.rate < req->min_rate || tmp_req.rate > req->max_rate)
			continue;

		if (tmp_req.rate <= req->rate) {
			if (!best_parent || tmp_req.rate > best_rate) {
				best_parent = tmp_req.best_parent_hw;
				best_parent_rate = tmp_req.best_parent_rate;
				best_rate = tmp_req.rate;
				if (best_rate == req->rate)
					break;
			}
		} else if (!best_parent && tmp_req.rate < lowest_rate) {
			lowest_parent = tmp_req.best_parent_hw;
			lowest_parent_rate = tmp_req.best_parent_rate;
			lowest_rate = tmp_req.rate;
		}
	}

	if (best_parent) {
		req->best_parent_hw = best_parent;
		req->best_parent_rate = best_parent_rate;
		req->rate = best_rate;
		return 0;
	}

	if (lowest_parent) {
		req->best_parent_hw = lowest_parent;
		req->best_parent_rate = lowest_parent_rate;
		req->rate = lowest_rate;
		return 0;
	}

	return -EINVAL;
}

static unsigned long sprd_comp_recalc_rate(struct clk_hw *hw,
					  unsigned long parent_rate)
{
	struct sprd_comp *cc = hw_to_sprd_comp(hw);

	return sprd_div_helper_recalc_rate(&cc->common, &cc->div, parent_rate);
}

static int sprd_comp_set_rate(struct clk_hw *hw, unsigned long rate,
			     unsigned long parent_rate)
{
	struct sprd_comp *cc = hw_to_sprd_comp(hw);

	return sprd_div_helper_set_rate(&cc->common, &cc->div,
				       rate, parent_rate);
}

static u8 sprd_comp_get_parent(struct clk_hw *hw)
{
	struct sprd_comp *cc = hw_to_sprd_comp(hw);

	return sprd_mux_helper_get_parent(&cc->common, &cc->mux);
}

static int sprd_comp_set_parent(struct clk_hw *hw, u8 index)
{
	struct sprd_comp *cc = hw_to_sprd_comp(hw);

	return sprd_mux_helper_set_parent(&cc->common, &cc->mux, index);
}

static int sprd_comp_set_rate_and_parent(struct clk_hw *hw, unsigned long rate,
					 unsigned long parent_rate, u8 index)
{
	struct sprd_comp *cc = hw_to_sprd_comp(hw);
	unsigned long temp_rate;

	temp_rate = sprd_div_helper_recalc_rate(&cc->common, &cc->div,
						parent_rate);
	if (temp_rate > rate) {
		sprd_div_helper_set_rate(&cc->common, &cc->div,
					 rate, parent_rate);
		sprd_mux_helper_set_parent(&cc->common, &cc->mux, index);
	} else {
		sprd_mux_helper_set_parent(&cc->common, &cc->mux, index);
		sprd_div_helper_set_rate(&cc->common, &cc->div,
					 rate, parent_rate);
	}

	return 0;
}

const struct clk_ops sprd_comp_ops = {
	.get_parent		= sprd_comp_get_parent,
	.set_parent		= sprd_comp_set_parent,

	.determine_rate		= sprd_comp_determine_rate,
	.recalc_rate		= sprd_comp_recalc_rate,
	.set_rate		= sprd_comp_set_rate,
	.set_rate_and_parent	= sprd_comp_set_rate_and_parent,
};
EXPORT_SYMBOL_GPL(sprd_comp_ops);
