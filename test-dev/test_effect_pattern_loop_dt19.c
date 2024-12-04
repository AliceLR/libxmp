#include "test.h"

TEST(test_effect_pattern_loop_dt19)
{
	compare_mixer_data(
		"data/loop_mode_dt19.dtm",
		"data/loop_mode_dt19.data");
}
END_TEST
