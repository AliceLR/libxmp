#include "test.h"
#include "../src/effects.h"


TEST(test_effect_line_jump)
{
	struct pos_row {
		int pos;
		int row;
	};
	static const struct pos_row vals[] = {
		{ 0,  0 }, { 0,  0 },	/* jump to 16 (fwd) */
		{ 0, 16 }, { 0, 16 },	/* jump to 12 (back) */
		{ 0, 12 }, { 0, 12 },
		{ 0, 13 }, { 0, 13 },
		{ 0, 14 }, { 0, 14 },
		{ 0, 15 }, { 0, 15 },	/* break */
		{ 1,  0 }, { 1,  0 },	/* jump to 63 (last valid) */
		{ 1, 63 }, { 1, 63 },
		/*{ 2,  0 }*/		/* infinite loop -- libxmp ignores this pattern. */
	};

	xmp_context opaque;
	struct context_data *ctx;
	struct xmp_frame_info info;
	int i, ret;

	opaque = xmp_create_context();
	ctx = (struct context_data *)opaque;

	create_simple_module(ctx, 1, 3);

	new_event(ctx, 0, 0, 0, 0, 0, 0, FX_LINE_JUMP, 0x10, FX_SPEED, 2);
	new_event(ctx, 0, 15, 0, 0, 0, 0, FX_BREAK, 0x00, 0, 0);
	new_event(ctx, 0, 16, 0, 0, 0, 0, FX_LINE_JUMP, 0x0c, 0, 0);
	new_event(ctx, 1, 0, 0, 0, 0, 0, FX_LINE_JUMP, 0x3f, 0, 0);
	new_event(ctx, 2, 0, 0, 0, 0, 0, FX_LINE_JUMP, 0x00, 0, 0);

	ret = libxmp_scan_sequences(ctx);
	fail_unless(ret == 0, "scan error");

	xmp_start_player(opaque, 8000, 0);

	for (i = 0; i < ARRAY_SIZE(vals); i++) {
		xmp_play_frame(opaque);
		xmp_get_frame_info(opaque, &info);
		fail_unless(info.pos == vals[i].pos, "line jump error");
		fail_unless(info.row == vals[i].row, "line jump error");
	}
	/* Attempt to play through the infinite loop, don't get stuck. */
	for (i = 0; i < 10; i++) {
		xmp_play_frame(opaque);
	}

	xmp_release_module(opaque);
	xmp_free_context(opaque);
}
END_TEST
