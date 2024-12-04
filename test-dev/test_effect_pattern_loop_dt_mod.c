#include "test.h"

/* Digital Tracker pattern loop behavior should be applied
 * to Digital Tracker shareware <=2.01 FA0x MODs.
 * Unfortunately, it's not possible to distinguish M.K. */

TEST(test_effect_pattern_loop_dt_mod)
{
	compare_mixer_data(
		"data/loop_mode_dt.mod",
		"data/loop_mode_dt_mod.data");
}
END_TEST
