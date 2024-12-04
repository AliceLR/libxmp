#include "test.h"

TEST(test_effect_pattern_loop_dt)
{
	compare_mixer_data(
		"data/loop_mode_dt.dtm",
		"data/loop_mode_dt_dtm.data");
}
END_TEST
