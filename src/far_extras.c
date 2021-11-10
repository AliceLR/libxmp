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

#include "common.h"
#include "player.h"
#include "lfo.h"
#include "effects.h"
#include "period.h"
#include "far_extras.h"


/**
 * FAR tempo has some unusual requirements that don't really match any other
 * format:
 *
 * 1) The coarse tempo is roughly equivalent to speed, but a value of 0 is
 *    supported, and FAR doesn't actually have a concept of ticks: it translates
 *    this value to tempo.
 *
 * 2) There is some very bizarre clamping behavior involving fine tempo slides
 *    that needs to be emulated.
 *
 * 3) Tempos can range from 1 to 356(!). FAR uses a fixed row subdivision size
 *    of 16, so just shift the tempo by 4 and hope libxmp doesn't change it.
 *
 * 4) There are two tempo modes, and they can be switched between arbitrarily...
 */
int libxmp_far_translate_tempo(int mode, int fine_change, int coarse,
			       int *fine, int *_speed, int *_bpm)
{
	/* tempo[0] = 256; tempo[i] = floor(128 / i). */
	static const int far_tempos[16] =
	{
		256, 128, 64, 42, 32, 25, 21, 18, 16, 14, 12, 11, 10, 9, 9, 8
	};
	int speed, bpm;

	if (coarse < 0 || coarse > 15 || mode < 0 || mode > 1)
		return -1;

	/* Compatibility for FAR's broken fine tempo "clamping". */
	if (fine_change < 0 && far_tempos[coarse] + *fine <= 0) {
		*fine = 0;
	} else if (fine_change > 0 && far_tempos[coarse] + *fine >= 100) {
		*fine = 100;
	}

	/* Thought that was bad enough? Apparently Daniel Potter didn't... */
	if (mode == 1) {
		/* "New" FAR tempo
		 * Note that negative values are possible in Farandole Composer
		 * via changing fine tempo and then slowing coarse tempo.
		 * These result in very slow final tempos due to signed to
		 * unsigned conversion. Zero should just be ignored entirely. */
		int tempo = far_tempos[coarse] + *fine;
		uint32 divisor;
		if (tempo == 0)
			return -1;

		divisor = 1197255 / tempo;

		/* Coincidentally(?), the "new" FAR tempo algorithm actually
		 * prevents the BPM from dropping too far under XMP_MIN_BPM,
		 * which is what libxmp needs anyway. */
		speed = 0;
		while (divisor > 0xffff) {
			divisor >>= 1;
			tempo <<= 1;
			speed++;
		}
		if (speed >= 2)
			speed++;
		speed += 3;
		bpm = tempo;
	} else {
		/* "Old" FAR tempo
		 * This runs into the XMP_MIN_BPM limit, but nothing uses it anyway. */
		speed = 16;
		bpm = (far_tempos[coarse] + *fine * 2) << 2;
	}

	if (bpm < XMP_MIN_BPM)
		bpm = XMP_MIN_BPM;

	*_speed = speed;
	*_bpm = bpm;
	return 0;
}

static void libxmp_far_update_tempo(struct context_data *ctx, int fine_change)
{
	struct player_data *p = &ctx->p;
	struct module_data *m = &ctx->m;
	struct far_module_extras *me = (struct far_module_extras *)m->extra;
	int speed, bpm;

	if (libxmp_far_translate_tempo(me->tempo_mode, fine_change,
	    me->coarse_tempo, &me->fine_tempo, &speed, &bpm) == 0) {
		p->speed = speed;
		p->bpm = bpm;
		p->frame_time = m->time_factor * m->rrate / p->bpm;
	}
}

static void libxmp_far_update_vibrato(struct lfo *lfo, int rate, int depth)
{
	if (depth != 0)
		libxmp_lfo_set_depth(lfo, GUS_FREQUENCY_STEPS(depth << 1));

	if (rate != 0)
		libxmp_lfo_set_rate(lfo, rate * 3);
	else
		libxmp_lfo_set_phase(lfo, 0);
}


void libxmp_far_play_extras(struct context_data *ctx, struct channel_data *xc, int chn)
{
	struct far_module_extras *me = FAR_MODULE_EXTRAS(ctx->m);
	struct far_channel_extras *ce = FAR_CHANNEL_EXTRAS(*xc);

	/* FAR vibrato depth is global, even though rate isn't. This might have
	 * been changed by a different channel, so make sure it's applied. */
	libxmp_far_update_vibrato(&xc->vibrato.lfo, ce->vib_rate, me->vib_depth);
}

int libxmp_far_new_channel_extras(struct channel_data *xc)
{
	xc->extra = calloc(1, sizeof(struct far_channel_extras));
	if (xc->extra == NULL)
		return -1;
	FAR_CHANNEL_EXTRAS(*xc)->magic = FAR_EXTRAS_MAGIC;
	return 0;
}

void libxmp_far_reset_channel_extras(struct channel_data *xc)
{
	memset((char *)xc->extra + 4, 0, sizeof(struct far_channel_extras) - 4);
}

void libxmp_far_release_channel_extras(struct channel_data *xc)
{
	free(xc->extra);
	xc->extra = NULL;
}

int libxmp_far_new_module_extras(struct module_data *m)
{
	m->extra = calloc(1, sizeof(struct far_module_extras));
	if (m->extra == NULL)
		return -1;
	FAR_MODULE_EXTRAS(*m)->magic = FAR_EXTRAS_MAGIC;
	FAR_MODULE_EXTRAS(*m)->vib_depth = 4;
	return 0;
}

void libxmp_far_release_module_extras(struct module_data *m)
{
	free(m->extra);
	m->extra = NULL;
}

void libxmp_far_extras_process_fx(struct context_data *ctx, struct channel_data *xc,
			   int chn, uint8 note, uint8 fxt, uint8 fxp, int fnum)
{
	struct far_module_extras *me = FAR_MODULE_EXTRAS(ctx->m);
	struct far_channel_extras *ce = FAR_CHANNEL_EXTRAS(*xc);
	int update_tempo = 0;
	int update_vibrato = 0;
	int fine_change = 0;

	/* Effects here multiplexed to reduce the number of used effect numbers. */
	switch (fxt) {
	case FX_FAR_PORTA_UP:		/* FAR pitch offset up */
		SET(FINE_BEND);
		xc->freq.fslide = GUS_FREQUENCY_STEPS(fxp << 2);
		break;

	case FX_FAR_PORTA_DN:		/* FAR pitch offset down */
		SET(FINE_BEND);
		xc->freq.fslide = -GUS_FREQUENCY_STEPS(fxp << 2);
		break;

	case FX_FAR_VIB_DEPTH:		/* FAR set vibrato depth */
		me->vib_depth = LSN(fxp);
		update_vibrato = 1;
		break;

	case FX_FAR_VIBRATO:		/* FAR vibrato */
		/* With active sustain, regular vibrato only sets the rate. */
		if (ce->vib_sustain == 0)
			ce->vib_sustain = MSN(fxp);
		ce->vib_rate = LSN(fxp);
		update_vibrato = 1;
		break;

	case FX_FAR_TEMPO:		/* FAR coarse tempo and tempo mode */
		if (MSN(fxp)) {
			me->tempo_mode = MSN(fxp) - 1;
		} else {
			me->coarse_tempo = LSN(fxp);
		}
		update_tempo = 1;
		break;

	case FX_FAR_F_TEMPO:		/* FAR fine tempo slide up/down */
		if (MSN(fxp)) {
			me->fine_tempo += MSN(fxp);
			fine_change = MSN(fxp);
		} else if (LSN(fxp)) {
			me->fine_tempo -= LSN(fxp);
			fine_change = -LSN(fxp);
		} else {
			me->fine_tempo = 0;
		}
		update_tempo = 1;
		break;
	}

	if (update_vibrato) {
		if (ce->vib_rate != 0) {
			if (ce->vib_sustain)
				SET_PER(VIBRATO);
			else
				SET(VIBRATO);
		} else {
			RESET_PER(VIBRATO);
			ce->vib_sustain = 0;
		}
		libxmp_far_update_vibrato(&xc->vibrato.lfo, ce->vib_rate, me->vib_depth);
	}

	if (update_tempo)
		libxmp_far_update_tempo(ctx, fine_change);
}
