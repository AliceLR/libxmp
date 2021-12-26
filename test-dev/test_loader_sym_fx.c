#include "test.h"

TEST(test_loader_sym_fx)
{
	xmp_context opaque;
	struct xmp_module_info info;
	FILE *f;
	int ret;

	opaque = xmp_create_context();

	/* TODO Test: most effects. */
	/* f = fopen("data/format_sym_fx.data", "r"); */

	/* Test: Set Sample Offset (high), Unset Sample Loop, low tempo */
	f = fopen("data/format_sym_fx2.data", "r");
	ret = xmp_load_module(opaque, "data/m/plastic.dsym");
	fail_unless(ret == 0, "module load");

	xmp_get_module_info(opaque, &info);

	ret = compare_module(info.mod, f);
	fail_unless(ret == 0, "format not correctly loaded");

	xmp_release_module(opaque);
	xmp_free_context(opaque);
}
END_TEST
