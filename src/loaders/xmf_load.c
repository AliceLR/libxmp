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
#include "../period.h"

static int xmf_test(HIO_HANDLE *, char *, const int);
static int xmf_load(struct module_data *, HIO_HANDLE *, const int);

const struct format_loader libxmp_loader_xmf = {
	"Imperium Galactica XMF",
	xmf_test,
	xmf_load
};

#define XMF_SAMPLE_ARRAY_SIZE (16 * 256)

static int xmf_test(HIO_HANDLE *f, char *t, const int start)
{
	uint8 buf[XMF_SAMPLE_ARRAY_SIZE];
	uint8 *pos;
	uint32 samples_length = 0;
	long length = hio_size(f);
	int num_patterns;
	int num_channels;
	int num_orders;
	int num_ins;
	int end_of_patterns;
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
	end_of_patterns = 0x1103 + num_channels + num_channels * 64 * 6;
	if (length < end_of_patterns)
		return -1;
	if ((size_t)length - end_of_patterns < samples_length) {
		D_(D_WARN "not XMF: file length %ld is shorter than required %zu",
		 length, (size_t)end_of_patterns + samples_length);
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
	struct xmp_instrument *xxi;
	struct xmp_subinstrument *sub;
	struct xmp_sample *xxs;
	struct extra_sample_data *xtra;
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
		if (libxmp_alloc_subinstrument(mod, i, 1) < 0)
			goto err;

		xxi = &(mod->xxi[i]);
		sub = &(xxi->sub[0]);
		xxs = &(mod->xxs[i]);
		xtra = &(m->xtra[i]);

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

	m->volbase = 0xff;
	return 0;

  err:
	free(buf);
	return -1;
}
