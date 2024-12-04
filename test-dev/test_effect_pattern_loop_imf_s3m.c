#include "test.h"

TEST(test_effect_pattern_loop_imf_s3m)
{
	compare_mixer_data(
		"data/loop_mode_imf.s3m",
		"data/loop_mode_imf_s3m.data");
}
END_TEST
