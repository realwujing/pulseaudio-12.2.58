#ifndef fooalsasinkhfoo
#define fooalsasinkhfoo

/***
  This file is part of PulseAudio.

  Copyright 2004-2006 Lennart Poettering
  Copyright 2006 Pierre Ossman <ossman@cendio.se> for Cendio AB

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#include <pulsecore/module.h>
#include <pulsecore/modargs.h>
#include <pulsecore/sink.h>

#include "alsa-util.h"

typedef struct pa_core_alsa_sink_new_data {
        pa_sink_new_data *data;
        pa_modargs *ma;
        pa_sink *sink;
}pa_core_alsa_sink_new_data;

pa_sink* pa_alsa_sink_new(pa_module *m, pa_modargs *ma, const char*driver, pa_card *card, pa_alsa_mapping *mapping);

void pa_alsa_sink_free(pa_sink *s);

#endif
