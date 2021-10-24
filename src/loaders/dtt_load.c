/* Extended Module Player
 * Copyright (C) 1996-2021 Claudio Matsuoka and Hipolito Carraro Jr
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

#define MAGIC_DskT	MAGIC4('D','s','k','T')
#define MAGIC_EskT	MAGIC4('E','s','k','T')


static int dtt_test(HIO_HANDLE *, char *, const int);
static int dtt_load (struct module_data *, HIO_HANDLE *, const int);

const struct format_loader libxmp_loader_dtt = {
	"Desktop Tracker",
	dtt_test,
	dtt_load
};

static int dtt_test(HIO_HANDLE *f, char *t, const int start)
{
	uint32 magic = hio_read32b(f);
	if (magic != MAGIC_DskT && magic != MAGIC_EskT)
		return -1;

	libxmp_read_title(f, t, 64);

	return 0;
}


/* Maximum 16 channels and 256 rows per pattern, maximum 8 bytes per event. */
#define PATTERN_BUF_MAX (16 * 256 * 8)

static int dtt_unpack(uint8 *dest, size_t dest_buf_size,
		      uint8 *src, size_t src_buf_size, HIO_HANDLE *f)
{
	uint32 dest_len = hio_read32l(f);
	uint32 src_len = hio_read32l(f);

	if (dest_len > dest_buf_size || src_len > src_buf_size)
		return -1;

	if (hio_read(src, 1, src_len, f) < src_len)
		return -1;

	return -1;
}

static uint32 dtt_packed_offset(uint32 size)
{
	if (size & 0x80000000UL) {
		return ~size + 1;
	}
	return 0;
}

static void dtt_translate_effect(uint8 *fxt, uint8 *fxp)
{
	// FIXME
	*fxt = *fxp = 0;
}

static int dtt_load(struct module_data *m, HIO_HANDLE *f, const int start)
{
	struct xmp_module *mod = &m->mod;
	struct xmp_event *event;
	int i, j, k;
	int n;
	uint8 *cbuf = NULL;
	uint8 *ubuf = NULL;
	uint32 ubuf_size;
	int u_size;
	uint8 buf[100];
	uint32 flags;
	uint32 pofs[256];
	uint8 plen[256];
	uint32 sdata[64];
	uint32 magic;
	int has_compressed;

	LOAD_INIT();

	magic = hio_read32b(f);
	ubuf_size = PATTERN_BUF_MAX;
	has_compressed = (magic == MAGIC_EskT);

	libxmp_set_type(m, "Desktop Tracker");

	hio_read(buf, 1, 64, f);
	libxmp_copy_adjust(mod->name, buf, XMP_NAME_SIZE - 1);
	hio_read(buf, 1, 64, f);
	/* strncpy(m->author, (char *)buf, XMP_NAME_SIZE); */

	flags = hio_read32l(f);
	mod->chn = hio_read32l(f);
	mod->len = hio_read32l(f);
	hio_read(buf, 1, 8, f);
	mod->spd = hio_read32l(f);
	mod->rst = hio_read32l(f);
	mod->pat = hio_read32l(f);
	mod->ins = mod->smp = hio_read32l(f);
	mod->trk = mod->pat * mod->chn;

	/* Sanity check */
	if (mod->chn > 16 || mod->pat > 256 || mod->ins > 63) {
		D_(D_CRIT "invalid chn=%d, pat=%d, or ins=%d",
			mod->chn, mod->pat, mod->ins);
		return -1;
	}

	hio_read(mod->xxo, 1, (mod->len + 3) & ~3L, f);

	m->c4rate = C4_NTSC_RATE;

	MODULE_INFO();

	for (i = 0; i < mod->pat; i++) {
		int x = hio_read32l(f);
		if (i < 256)
			pofs[i] = x;
	}

	n = (mod->pat + 3) & ~3L;
	for (i = 0; i < n; i++) {
		int x = hio_read8(f);
		if (i < 256)
			plen[i] = x;
	}

	if (libxmp_init_instrument(m) < 0)
		return -1;

	/* Read instrument names */

	for (i = 0; i < mod->ins; i++) {
		int c2spd, looplen;

		if (libxmp_alloc_subinstrument(mod, i, 1) < 0)
			return -1;

		hio_read8(f);			/* note */
		mod->xxi[i].sub[0].vol = hio_read8(f) >> 1;
		mod->xxi[i].sub[0].pan = 0x80;
		hio_read16l(f);			/* not used */
		c2spd = hio_read32l(f);		/* period? */
		hio_read32l(f);			/* sustain start */
		hio_read32l(f);			/* sustain length */
		mod->xxs[i].lps = hio_read32l(f);
		looplen = hio_read32l(f);
		mod->xxs[i].flg = looplen > 0 ? XMP_SAMPLE_LOOP : 0;
		mod->xxs[i].lpe = mod->xxs[i].lps + looplen;
		mod->xxs[i].len = hio_read32l(f);
		hio_read(buf, 1, 32, f);
		libxmp_instrument_name(mod, i, (uint8 *)buf, 32);
		sdata[i] = hio_read32l(f);

		if (has_compressed && dtt_packed_offset(sdata[i])) {
			if (mod->xxs[i].len < MAX_SAMPLE_SIZE && mod->xxs[i].len > ubuf_size)
				ubuf_size = mod->xxs[i].len;
		}

		mod->xxi[i].nsm = !!(mod->xxs[i].len);
		mod->xxi[i].sub[0].sid = i;

		D_(D_INFO "[%2X] %-32.32s  %04x %04x %04x %c V%02x %d\n",
				i, mod->xxi[i].name, mod->xxs[i].len,
				mod->xxs[i].lps, mod->xxs[i].lpe,
				mod->xxs[i].flg & XMP_SAMPLE_LOOP ? 'L' : ' ',
				mod->xxi[i].sub[0].vol, c2spd);
	}

	if (libxmp_init_pattern(mod) < 0)
		return -1;

	/* Read and convert patterns */
	D_(D_INFO "Stored patterns: %d", mod->pat);

	if ((ubuf = malloc(ubuf_size)) == NULL)
		return -1;

	if (has_compressed) {
		if ((cbuf = malloc(ubuf_size)) == NULL)
			goto err;
	}

	for (i = 0; i < mod->pat; i++) {
		uint32 pos = 0;

		if (libxmp_alloc_pattern_tracks(mod, i, plen[i]) < 0)
			goto err;

		if (has_compressed && dtt_packed_offset(pofs[i])) {
			if (hio_seek(f, start + dtt_packed_offset(pofs[i]), SEEK_SET) < 0) {
				D_(D_CRIT "seek error for pattern %d (cmpr)", i);
				goto err;
			}

			u_size = dtt_unpack(ubuf, ubuf_size, cbuf, ubuf_size, f);
			if (u_size < 0) {
				D_(D_CRIT "unpack failed for pattern %d", i);
				goto err;
			}

		} else {
			if (hio_seek(f, start + pofs[i], SEEK_SET) < 0) {
				D_(D_CRIT "seek error for pattern %d", i);
			}
			u_size = hio_read(ubuf, 1, plen[i] * mod->chn * 8, f);

		}
		if (u_size < plen[i] * mod->chn * 4) {
			D_(D_CRIT "short read for pattern %d", i);
			goto err;
		}

		for (j = 0; j < mod->xxp[i]->rows; j++) {
			for (k = 0; k < mod->chn; k++) {
				uint32 x;

				event = &EVENT (i, k, j);
				x = readmem32l(ubuf + pos);
				pos += 4;

				event->ins  = (x & 0x0000003f);
				event->note = (x & 0x00000fc0) >> 6;
				event->fxt  = (x & 0x0001f000) >> 12;

				if (event->note)
					event->note += 48;

				/* sorry, we only have room for two effects */
				if (x & (0x1f << 17)) {
					event->f2p = (x & 0x003e0000) >> 17;

					x = readmem32l(ubuf + pos);
					pos += 4;

					event->fxp = (x & 0x000000ff);
					event->f2p = (x & 0x0000ff00) >> 8;
				} else {
					event->fxp = (x & 0xfc000000) >> 18;
				}
				dtt_translate_effect(&event->fxt, &event->fxp);
				dtt_translate_effect(&event->f2t, &event->f2p);
			}
		}
	}

	/* Read samples */
	D_(D_INFO "Stored samples: %d", mod->smp);
	for (i = 0; i < mod->ins; i++) {
		if (has_compressed && dtt_packed_offset(sdata[i])) {
			if (hio_seek(f, start + dtt_packed_offset(sdata[i]), SEEK_SET) < 0) {
				D_(D_WARN "seek error for sample %d (cmpr)", i);
				continue;
			}

			u_size = dtt_unpack(ubuf, ubuf_size, cbuf, ubuf_size, f);
			if (u_size < 0) {
				D_(D_WARN "unpack failed for sample %d", i);
				continue;
			}

			if (u_size < mod->xxs[i].len)
				mod->xxs[i].len = u_size;

			if (libxmp_load_sample(m, NULL, SAMPLE_FLAG_VIDC, &mod->xxs[i], ubuf) < 0)
				goto err;
		} else {
			if (hio_seek(f, start + sdata[i], SEEK_SET) < 0) {
				D_(D_WARN "seek error for sample %d", i);
				continue;
			}
			if (libxmp_load_sample(m, f, SAMPLE_FLAG_VIDC, &mod->xxs[i], NULL) < 0)
				goto err;
		}
	}

	free(ubuf);
	free(cbuf);
	return 0;

err:
	free(ubuf);
	free(cbuf);
	return -1;
}
