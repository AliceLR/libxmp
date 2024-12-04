#include "test.h"

TEST(test_effect_pattern_loop_st301)
{
	compare_mixer_data(
		"data/loop_mode_st301.s3m",
		"data/loop_mode_st301.data");
}
END_TEST
