#include "test.h"

TEST(test_effect_pattern_loop_st321)
{
	compare_mixer_data(
		"data/loop_mode_st321.s3m",
		"data/loop_mode_st321.data");
}
END_TEST
