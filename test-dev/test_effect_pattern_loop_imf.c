#include "test.h"

TEST(test_effect_pattern_loop_imf)
{
	compare_mixer_data(
		"data/loop_mode_imf.imf",
		"data/loop_mode_imf_imf.data");
}
END_TEST
