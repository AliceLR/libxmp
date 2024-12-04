#include "test.h"

TEST(test_effect_pattern_loop_mpt_s3m)
{
	compare_mixer_data(
		"data/loop_mode_mpt.s3m",
		"data/loop_mode_mpt_s3m.data");
}
END_TEST
