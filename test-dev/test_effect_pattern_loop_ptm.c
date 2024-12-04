#include "test.h"

TEST(test_effect_pattern_loop_ptm)
{
	compare_mixer_data(
		"data/loop_mode_ptm.ptm",
		"data/loop_mode_ptm.data");
}
END_TEST
