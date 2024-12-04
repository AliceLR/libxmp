#include "test.h"

TEST(test_effect_pattern_loop_it210)
{
	compare_mixer_data(
		"data/loop_mode_it210.it",
		"data/loop_mode_it210.data");
}
END_TEST
