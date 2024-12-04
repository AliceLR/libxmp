#include "test.h"

TEST(test_effect_pattern_loop_mpt_xm)
{
	compare_mixer_data(
		"data/loop_mode_mpt.xm",
		"data/loop_mode_mpt_xm.data");
}
END_TEST
