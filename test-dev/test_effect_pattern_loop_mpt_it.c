#include "test.h"

TEST(test_effect_pattern_loop_mpt_it)
{
	compare_mixer_data(
		"data/loop_mode_mpt.it",
		"data/loop_mode_mpt_it.data");
}
END_TEST
