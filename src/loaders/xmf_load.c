/* Extended Module Player
 * Copyright (C) 2023 Alice Rowan <petrifiedrowan@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "loader.h"

static int xmf_test(HIO_HANDLE *, char *, const int);
static int xmf_load(struct module_data *, HIO_HANDLE *, const int);

const struct format_loader libxmp_loader_xmf = {
	"Imperium Galactica XMF",
	xmf_test,
	xmf_load
};

#define XMF_SAMPLE_ARRAY_SIZE (16 * 256)

/* FIXME: this was a guess (255 * sqrt(x/255)) but mostly fixes this
 * format's volume issue. Does the real replayer use a volume table that
 * over-compensates for the GUS's logarithmic volumes? */
static const int xmf_vol_table[256] = {
	0,   16,  22,  27,  32,  35,  39,  42,  45,  48,  50,  53,  55,  57,  59,
	62,  64,  66,  68,  69,  71,  73,  75,  76,  78,  80,  81,  83,  84,  86,
	87,  89,  90,  92,  93,  94,  96,  97,  98,  100, 101, 102, 103, 105, 106,
	107, 108, 109, 111, 112, 113, 114, 115, 116, 117, 118, 119, 121, 122, 123,
	124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 136, 137,
	138, 139, 140, 141, 142, 143, 144, 145, 146, 146, 147, 148, 149, 150, 151,
	152, 152, 153, 154, 155, 156, 157, 157, 158, 159, 160, 161, 161, 162, 163,
	164, 165, 165, 166, 167, 168, 168, 169, 170, 171, 171, 172, 173, 174, 174,
	175, 176, 177, 177, 178, 179, 179, 180, 181, 182, 182, 183, 184, 184, 185,
	186, 186, 187, 188, 189, 189, 190, 191, 191, 192, 193, 193, 194, 195, 195,
	196, 196, 197, 198, 198, 199, 200, 200, 201, 202, 202, 203, 204, 204, 205,
	205, 206, 207, 207, 208, 209, 209, 210, 210, 211, 212, 212, 213, 213, 214,
	215, 215, 216, 216, 217, 218, 218, 219, 219, 220, 220, 221, 222, 222, 223,
	223, 224, 225, 225, 226, 226, 227, 227, 228, 228, 229, 230, 230, 231, 231,
	232, 232, 233, 233, 234, 235, 235, 236, 236, 237, 237, 238, 238, 239, 239,
	240, 241, 241, 242, 242, 243, 243, 244, 244, 245, 245, 246, 246, 247, 247,
	248, 248, 249, 249, 250, 250, 251, 251, 252, 252, 253, 253, 254, 254, 255
};

static int xmf_test(HIO_HANDLE *f, char *t, const int start)
{
	uint8 buf[XMF_SAMPLE_ARRAY_SIZE];
	uint8 *pos;
	uint32 samples_length = 0;
	long length;
	int samples_start;
	int num_patterns;
	int num_channels;
	int num_orders;
	int num_ins;
	int i;

	if (hio_read8(f) != 0x03)
		return -1;

	if (hio_read(buf, 1, XMF_SAMPLE_ARRAY_SIZE, f) < XMF_SAMPLE_ARRAY_SIZE)
		return -1;

	/* Test instruments */
	pos = buf;
	num_ins = 0;
	for (i = 0; i < 256; i++) {
		uint32 loopstart = readmem24l(pos + 0);
		uint32 loopend   = readmem24l(pos + 3);
		uint32 datastart = readmem24l(pos + 6);
		uint32 dataend   = readmem24l(pos + 9);
		uint32 len;
		pos += 16;

		/* Despite the data start and end values, samples are stored
		 * sequentially after the pattern data. These fields are still
		 * required to calculate the sample length. */
		if (datastart > dataend) {
			D_(D_WARN "not XMF: smp %d: data start %u > end %u",
			 i, (unsigned)datastart, (unsigned)dataend);
			return -1;
		}

		len = dataend - datastart;
		samples_length += len;

		/* All known XMFs have well-formed loops. */
		if (loopend != 0 && (loopstart >= len || loopend > len || loopstart > loopend)) {
			D_(D_WARN "not XMF: smp %d: bad loop %u %u (len: %u)",
			 i, (unsigned)loopstart, (unsigned)loopend, (unsigned)len);
			return -1;
		}

		if (len > 0)
			num_ins = i + 1;
	}
	if (num_ins > MAX_INSTRUMENTS)
		return -1;

	/* Get pattern data size. */
	if (hio_read(buf, 1, 258, f) < 258)
		return -1;

	num_channels = buf[256] + 1;
	num_orders   = buf[257] + 1;

	if (num_channels > XMP_MAX_CHANNELS)
		return -1;

	num_patterns = 0;
	for (i = 0; i < num_orders; i++) {
		if (buf[i] < 0xff && buf[i] >= num_patterns)
			num_patterns = buf[i];
	}
	num_patterns++;

	/* Test total module length */
	samples_start = 0x1103 + num_channels + num_channels * 64 * 6;
	length = hio_size(f);
	if (length < samples_start || (size_t)length - samples_start < samples_length) {
		D_(D_WARN "not XMF: file length %ld is shorter than required %zu",
		 length, (size_t)samples_start + samples_length);
		return -1;
	}

	libxmp_read_title(f, t, 0);

	return 0;
}


static void xmf_translate_effect(uint8 *fxt, uint8 *fxp, uint8 effect, uint8 param)
{
	switch (effect) {
	case 0x0a:
	case 0x0c:
	case 0x0d:
	case 0x0e:
	case 0x0f:
		/* protracker compatible */
		*fxt = effect;
		*fxp = param;
		break;

	case 0x10: /* FIXME: what is this thing? */
	default:
		*fxt = *fxp = 0;
		break;
	}
}

static int xmf_load(struct module_data *m, HIO_HANDLE *f, const int start)
{
	struct xmp_module *mod = &m->mod;
	struct xmp_event *event;
	uint8 *buf, *pos;
	size_t pat_sz;
	int i, j, k;

	LOAD_INIT();

	/* Skip 0x03 */
	hio_read8(f);

	snprintf(mod->type, XMP_NAME_SIZE, "Imperium Galactica XMF");

	MODULE_INFO();

	if ((buf = (uint8 *)malloc(XMF_SAMPLE_ARRAY_SIZE)) == NULL)
		return -1;

	/* Count instruments */
	if (hio_read(buf, 1, XMF_SAMPLE_ARRAY_SIZE, f) < XMF_SAMPLE_ARRAY_SIZE)
		goto err;

	mod->ins = 0;
	pos = buf;
	for (i = 0; i < 256; i++, pos += 16) {
		if (readmem24l(pos + 9) > readmem24l(pos + 6))
			mod->ins = i;
	}
	mod->ins++;
	mod->smp = mod->ins;

	if (libxmp_init_instrument(m) < 0)
		goto err;

	/* Instruments */
	pos = buf;
	for (i = 0; i < mod->ins; i++, pos += 16) {
		struct extra_sample_data *xtra = &(m->xtra[i]);
		struct xmp_instrument *xxi = &(mod->xxi[i]);
		struct xmp_sample *xxs = &(mod->xxs[i]);
		struct xmp_subinstrument *sub;

		if (libxmp_alloc_subinstrument(mod, i, 1) < 0)
			goto err;

		sub = &(xxi->sub[0]);

		xxs->len = readmem24l(pos + 9) - readmem24l(pos + 6);
		xxs->lps = readmem24l(pos + 0);
		xxs->lpe = readmem24l(pos + 3);
		xtra->c5spd = readmem16l(pos + 14);
		sub->vol = pos[12];
		sub->sid = i;

		if (pos[13] & 0x08) /* GUS loop enable */
			xxs->flg |= XMP_SAMPLE_LOOP;
		if (pos[13] & 0x10) /* GUS reverse flag */
			xxs->flg |= XMP_SAMPLE_LOOP_BIDIR;

		if (xxs->len > 0)
			xxi->nsm = 1;

		D_(D_INFO "[%2X] %06x %06x %06x %c%c V%02x %5d", i,
		   xxs->len, xxs->lps, xxs->lpe,
		   xxs->flg & XMP_SAMPLE_LOOP ? 'L' : ' ',
		   xxs->flg & XMP_SAMPLE_LOOP_BIDIR ? 'B' : ' ',
		   sub->vol, (int)xtra->c5spd);
	}

	/* Sequence */
	if (hio_read(mod->xxo, 1, 256, f) < 256)
		return -1;

	mod->chn = hio_read8(f) + 1;
	mod->len = hio_read8(f) + 1;

	mod->pat = 0;
	for (i = 0; i < mod->len; i++) {
		if (mod->xxo[i] < 0xff && mod->xxo[i] >= mod->pat)
			mod->pat = mod->xxo[i];
	}
	mod->pat++;
	mod->trk = mod->chn * mod->pat;

	/* Panning table */
	if (hio_read(buf, 1, mod->chn, f) < mod->chn)
		goto err;

	for (i = 0; i < mod->chn; i++) {
		mod->xxc[i].pan = 0x80 + (buf[i] - 7) * 16;
		if (mod->xxc[i].pan > 255)
			mod->xxc[i].pan = 255;
	}

	D_(D_INFO "Module length: %d", mod->len);

	pat_sz = mod->chn * 6 * 64;
	if (pat_sz > XMF_SAMPLE_ARRAY_SIZE) {
		if ((pos = (uint8 *)realloc(buf, pat_sz)) == NULL)
			goto err;
		buf = pos;
	}

	if (libxmp_init_pattern(mod) < 0)
		goto err;

	/* Patterns */
	D_(D_INFO "Stored patterns: %d", mod->pat);

	for (i = 0; i < mod->pat; i++) {
		if (libxmp_alloc_pattern_tracks(mod, i, 64) < 0)
			goto err;

		if (hio_read(buf, 1, pat_sz, f) < pat_sz)
			goto err;

		pos = buf;
		for (j = 0; j < 64; j++) {
			for (k = 0; k < mod->chn; k++) {
				event = &EVENT(i, k, j);

				if (pos[0] > 0)
					event->note = pos[0] + 36;
				event->ins = pos[1];

				xmf_translate_effect(&event->fxt, &event->fxp, pos[2], pos[5]);
				xmf_translate_effect(&event->f2t, &event->f2p, pos[3], pos[4]);
				pos += 6;
			}
		}
	}
	free(buf);

	/* Sample data */
	D_(D_INFO "Stored samples: %d", mod->smp);

	/* Despite the GUS sample start and end pointers saved in the file,
	 * these are actually just loaded sequentially. */
	for (i = 0; i < mod->ins; i++) {
		if (libxmp_load_sample(m, f, 0, &mod->xxs[i], NULL))
			return -1;
	}

	m->vol_table = xmf_vol_table;
	m->volbase = 0xff;
	return 0;

  err:
	free(buf);
	return -1;
}
