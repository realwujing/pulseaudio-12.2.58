/***
  This file is part of PulseAudio.

  Copyright (C) 2014 Collabora Ltd. <http://www.collabora.co.uk/>

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <pulse/timeval.h>
#include <pulse/utf8.h>

#include <pulsecore/core-error.h>
#include <pulsecore/core-util.h>
#include <pulsecore/i18n.h>
#include <pulsecore/module.h>
#include <pulsecore/modargs.h>
#include <pulsecore/shared.h>
#include <pulsecore/socket-util.h>
#include <pulsecore/time-smoother.h>
#include <pulsecore/protocol-native.h>

#include "bluetooth/bluez5-util.h"
#include "alsa/alsa-util.h"
#include "alsa/alsa-sink.h"
#include "alsa/alsa-source.h"

#define HAVE_CODEC_PARAM

#ifdef HAVE_CODEC_PARAM // the diff on pcm number
#define HW_SCO_SINK_ARGS(port_name)     pa_sprintf_malloc("name=%s sink_name=bt_sco_sink device=hw:0,1 profile=bt_sco rate=48000", port_name);
#define HW_SCO_SOURCE_ARGS(port_name)   pa_sprintf_malloc("name=%s source_name=bt_sco_source device=hw:0,1 profile=bt_sco rate=48000", port_name);
#define HW_CARD "hw:0"
#else
#define HW_SCO_SINK_ARGS(port_name)      pa_sprintf_malloc("name=%s sink_name=bt_sco_sink device=hw:1,1 profile=bt_sco rate=8000", port_name);
#define HW_SCO_SOURCE_ARGS(port_name)    pa_sprintf_malloc("name=%s source_name=bt_sco_source device=hw:1,2 profile=bt_sco rate=8000", port_name);
#endif

#define MESH_PROFILE  "bt_sco"  /*bluetooth profile hsp name*/
#define DEFAULT_PROFILE_LENTH 11
#define LEVEL_BASIC (1<<0)
#define LEVEL_ID (1<<2)

int cset(const char * name, const char *card, const char *c, int roflag, int keep_handle);
void pa_alsa_notify_sink_thread_state(pa_sink *sink, pa_sink_state_t state, pa_suspend_cause_t suspend_cause);
void pa_alsa_notify_source_thread_state(pa_source *create_source, pa_source_state_t state, pa_suspend_cause_t suspend_cause);

PA_MODULE_AUTHOR("Deepin sys dev team");
PA_MODULE_DESCRIPTION("Compatible with Huawei's HiSilicon Bluetooth chip");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(true);

static const char* const valid_modargs[] = {
    NULL,
};

static const char* const valid_sink_modargs[] = {
    "path",
    "autodetect_mtu",
    "name",
    "sink_name",
    "device",
    "profile",
    "rate",
    NULL
};

static const char* const valid_src_modargs[] = {
    "path",
    "autodetect_mtu",
    "name",
    "source_name",
    "device",
    "profile",
    "rate",
    NULL
};

struct userdata {
    pa_module *module;
    pa_core *core;

    pa_sink *p_alsa_sink;
    pa_source *p_alsa_source;

    int first_flag;
    pa_bluetooth_device_module_discovery *device_module_discovery;
    pa_core_alsa_discovery *alsa_discovery;

    pa_hook_slot *device_module_init_profile_slot;
    pa_hook_slot *device_module_add_sink_slot;
    pa_hook_slot *device_module_add_source_slot;
    pa_hook_slot *device_module_sink_state_change_slot;
    pa_hook_slot *device_module_source_state_change_slot;
    pa_hook_slot *device_module_stop_thread_slot;
    pa_hook_slot *device_module_done_slot;
    pa_hook_slot *device_module_alsa_sink_begin_new_slot;
    pa_hook_slot *device_module_alsa_sink_after_new_slot;
    pa_hook_slot *device_module_alsa_source_begin_new_slot;
    pa_hook_slot *device_module_alsa_source_after_new_slot;
    pa_hook_slot *device_module_source_set_state_slot;
    pa_hook_slot *device_module_sink_put_hook_callback_slot;
    pa_hook_slot *device_module_source_put_hook_callback_slot;
    pa_hook_slot *pa_core_native_set_default_command_slot;
    pa_hook_slot *device_module_bluez_device_init_slot;
    //pa_hook_slot *pa_core_default_sink_changed_slot;
    //pa_hook_slot *pa_core_default_source_changed_slot;
};

struct set_state_data {
    pa_source_state_t state;
    pa_suspend_cause_t suspend_cause;
};

void pa_alsa_notify_sink_thread_state(pa_sink *sink, pa_sink_state_t state, pa_suspend_cause_t suspend_cause)
{
    if (sink)
    {
        if (sink->set_state_in_main_thread) {
            sink->set_state_in_main_thread(sink, state, suspend_cause);
        }
        if (sink->asyncmsgq) {
          struct set_state_data data = { .state = state, .suspend_cause = suspend_cause };

          (void)pa_asyncmsgq_send(sink->asyncmsgq, PA_MSGOBJECT(sink), PA_SINK_MESSAGE_SET_STATE, &data, 0, NULL);            
        }
        sink->state = state;
    }    
    return;
}

void pa_alsa_notify_source_thread_state(pa_source *create_source, pa_source_state_t state, pa_suspend_cause_t suspend_cause)
{
    if (create_source) {
        if (create_source->set_state_in_main_thread) {
            create_source->set_state_in_main_thread(create_source, state, suspend_cause);
        }
        if (create_source->asyncmsgq) {
          struct set_state_data data = { .state = state, .suspend_cause = suspend_cause };

          (void)pa_asyncmsgq_send(create_source->asyncmsgq, PA_MSGOBJECT(create_source), PA_SOURCE_MESSAGE_SET_STATE, &data, 0, NULL);     
        }
        create_source->state = state;
    }
    
    return;
}

static bool is_headset_profile(pa_bluetooth_profile_t profile) {
    return (profile == PA_BLUETOOTH_PROFILE_HEADSET_HEAD_UNIT || profile == PA_BLUETOOTH_PROFILE_HEADSET_AUDIO_GATEWAY);
}

static void show_control_id(snd_ctl_elem_id_t *id)
{
	char *str;

	str = snd_ctl_ascii_elem_id_get(id);
	if (str)
		pa_log_debug("%s", str);
	free(str);
}

static int show_control(const char *space, snd_hctl_elem_t *elem,
			int level)
{
	int err;
	unsigned int item, idx, count, *tlv;
	snd_ctl_elem_type_t type;
	snd_ctl_elem_id_t *id;
	snd_ctl_elem_info_t *info;
	snd_ctl_elem_value_t *control;
	snd_aes_iec958_t iec958;
	snd_ctl_elem_id_alloca(&id);
	snd_ctl_elem_info_alloca(&info);
	snd_ctl_elem_value_alloca(&control);
	if ((err = snd_hctl_elem_info(elem, info)) < 0) {
		pa_log_error("Control hw snd_hctl_elem_info error: %s", snd_strerror(err));
		return err;
	}
	if (level & LEVEL_ID) {
		snd_hctl_elem_get_id(elem, id);
		show_control_id(id);
		pa_log_debug("\n");
	}
	count = snd_ctl_elem_info_get_count(info);
	type = snd_ctl_elem_info_get_type(info);

	switch (type) {
	case SND_CTL_ELEM_TYPE_INTEGER:
		pa_log_debug(",min=%li,max=%li,step=%li", 
		       snd_ctl_elem_info_get_min(info),
		       snd_ctl_elem_info_get_max(info),
		       snd_ctl_elem_info_get_step(info));
		break;
	case SND_CTL_ELEM_TYPE_INTEGER64:
		pa_log_debug(",min=%lli,max=%lli,step=%lli",
		       snd_ctl_elem_info_get_min64(info),
		       snd_ctl_elem_info_get_max64(info),
		       snd_ctl_elem_info_get_step64(info));
		break;
	case SND_CTL_ELEM_TYPE_ENUMERATED:
	{
		unsigned int items = snd_ctl_elem_info_get_items(info);
		pa_log_debug(",items=%u\n", items);
		for (item = 0; item < items; item++) {
			snd_ctl_elem_info_set_item(info, item);
			if ((err = snd_hctl_elem_info(elem, info)) < 0) {
				pa_log_error("Control hw element info error: %s", snd_strerror(err));
				return err;
			}
			pa_log_debug("%s; Item #%u '%s'", space, item, snd_ctl_elem_info_get_item_name(info));
		}
		break;
	}
	default:
		pa_log_debug("\n");
		break;
	}

	if (level & LEVEL_BASIC) {
		if (!snd_ctl_elem_info_is_readable(info))
			goto __skip_read;
		if ((err = snd_hctl_elem_read(elem, control)) < 0) {
			pa_log_error("Control hw:0 element read error: %s", snd_strerror(err));
			return err;
		}
		
		for (idx = 0; idx < count; idx++) {
			if (idx > 0)
				pa_log_debug(",");
			switch (type) {
			case SND_CTL_ELEM_TYPE_BOOLEAN:
				pa_log_debug("%s", snd_ctl_elem_value_get_boolean(control, idx) ? "on" : "off");
				break;
			case SND_CTL_ELEM_TYPE_INTEGER:
				pa_log_debug("%li", snd_ctl_elem_value_get_integer(control, idx));
				break;
			case SND_CTL_ELEM_TYPE_INTEGER64:
				pa_log_debug("%lli", snd_ctl_elem_value_get_integer64(control, idx));
				break;
			case SND_CTL_ELEM_TYPE_ENUMERATED:
				pa_log_debug("%u", snd_ctl_elem_value_get_enumerated(control, idx));
				break;
			case SND_CTL_ELEM_TYPE_BYTES:
				pa_log_debug("0x%02x", snd_ctl_elem_value_get_byte(control, idx));
				break;
			case SND_CTL_ELEM_TYPE_IEC958:
				snd_ctl_elem_value_get_iec958(control, &iec958);
				pa_log_error("[AES0=0x%02x AES1=0x%02x AES2=0x%02x AES3=0x%02x]",
				       iec958.status[0], iec958.status[1],
				       iec958.status[2], iec958.status[3]);
				break;
			default:
				pa_log_debug("?");
				break;
			}
		}
	      __skip_read:
		if (!snd_ctl_elem_info_is_tlv_readable(info))
			goto __skip_tlv;
		/* skip ASoC ext bytes controls that may have huge binary TLV data */
		if (type == SND_CTL_ELEM_TYPE_BYTES &&
				!snd_ctl_elem_info_is_readable(info) &&
				!snd_ctl_elem_info_is_writable(info)) {
			pa_log_error("%s; ASoC TLV Byte control, skipping bytes dump", space);
			goto __skip_tlv;
		}

		tlv = malloc(4096);
		if ((err = snd_hctl_elem_tlv_read(elem, tlv, 4096)) < 0) {
			pa_log_error("Control hw:0 element TLV read error: %s", snd_strerror(err));
			free(tlv);
			return err;
		}
		//decode_tlv(strlen(space), tlv, 4096);
		free(tlv);
	}
      __skip_tlv:
	return 0;
}


int cset(const char * name, const char *card, const char *c, int roflag, int keep_handle)
{
	int err;
	static snd_ctl_t *handle = NULL;
	snd_ctl_elem_info_t *info;
	snd_ctl_elem_id_t *id;
	snd_ctl_elem_value_t *control;
	snd_ctl_elem_info_alloca(&info);
	snd_ctl_elem_id_alloca(&id);
	snd_ctl_elem_value_alloca(&control);

    pa_log_debug("cset name[%s]card[%s]c[%s]", name, card, c);
	if (snd_ctl_ascii_elem_id_parse(id, name)) {
		pa_log_error("Wrong control identifier: %s", name);
		return -1;
	}

	if (handle == NULL &&
	    (err = snd_ctl_open(&handle, card, 0)) < 0) {
		pa_log_error("Control %s open error: %s", card, snd_strerror(err));
		return err;
	}
 
	snd_ctl_elem_info_set_id(info, id);
   
	if ((err = snd_ctl_elem_info(handle, info)) < 0) {
		//if (ignore_error)
			//return 0;
		pa_log_error("Cannot find the given element from control %s", card);
		if (! keep_handle) {
			snd_ctl_close(handle);
			handle = NULL;
		}
		return err;
	}
  
	snd_ctl_elem_info_get_id(info, id);
	if (!roflag) {
        snd_ctl_elem_value_set_id(control, id);
     
		if ((err = snd_ctl_elem_read(handle, control)) < 0) {
			//if (ignore_error)
				//return 0;
			pa_log_error("Cannot read the given element from control %s", card);
			if (! keep_handle) {
				snd_ctl_close(handle);
				handle = NULL;
			}
			return err;
		}
        err = snd_ctl_ascii_value_parse(handle, control, info, c);
		if (err < 0) {
 			//if (!ignore_error)
				//error("Control %s parse error: %s\n", card, snd_strerror(err));
			if (!keep_handle) {
				snd_ctl_close(handle);
				handle = NULL;
			}
			//return ignore_error ? 0 : err;
            return err;
		}
        
		if ((err = snd_ctl_elem_write(handle, control)) < 0) {
			//if (!ignore_error)
				//error("Control %s element write error: %s\n", card, snd_strerror(err));
			if (!keep_handle) {
				snd_ctl_close(handle);
				handle = NULL;
			}
			//return ignore_error ? 0 : err;
             return err;
		}
	}
	if (! keep_handle) {
		snd_ctl_close(handle);
		handle = NULL;
	}
	{
		snd_hctl_t *hctl;
		snd_hctl_elem_t *elem;
		if ((err = snd_hctl_open(&hctl, card, 0)) < 0) {
			pa_log_error("Control %s open error: %s", card, snd_strerror(err));
			return err;
		}
   
		if ((err = snd_hctl_load(hctl)) < 0) {
			pa_log_error("Control %s load error: %s", card, snd_strerror(err));
			return err;
		}
      
		elem = snd_hctl_find_elem(hctl, id);
		if (elem)
			show_control("  ", elem, LEVEL_BASIC | LEVEL_ID);
		else
			pa_log_error("Could not find the specified element");
		snd_hctl_close(hctl);
	}
	return 0;
}

static pa_hook_result_t device_module_init_profile_cb(pa_bluetooth_device_module_discovery *y, pa_bluetooth_profile_t *d, struct userdata *u)
{
    pa_assert(d);
    pa_log_debug("enter hook %s profile %d",__func__,*d);
    #ifdef HAVE_CODEC_PARAM
    if (is_headset_profile(*d))
    {                
        cset("name=Bt Uplink Switch", HW_CARD, "0", 0, 0);
        cset("name=Bt Playback Switch", HW_CARD, "0", 0, 0);        
    }
    #endif    
    return PA_HOOK_OK;
}

/* Run from main thread */
static pa_hook_result_t device_module_add_sink_cb(pa_bluetooth_device_module_discovery *y, pa_bluetooth_device_add_sink_source_data *d, struct userdata *u) {
    pa_modargs *ma = NULL;
    const char *args = NULL;

    pa_assert(d);
    pa_assert(u);
    pa_assert(!u->p_alsa_sink);
    pa_log_debug("enter hook %s",__func__);

    if (!is_headset_profile(d->profile))
        return PA_HOOK_OK;

    args = HW_SCO_SINK_ARGS(d->output_port_name);

    // create alsa sink
    pa_alsa_refcnt_inc();
    if (!(ma = pa_modargs_new(args, valid_sink_modargs))) {
        pa_log_error("parse args fail");
        return PA_HOOK_STOP;
    }
    
    if (!(u->p_alsa_sink = pa_alsa_sink_new(d->module, ma, __FILE__, d->card, NULL))) {
        pa_log_error("alsa_sink_new fail");    
        goto fail;
    }
    pa_modargs_free(ma);
    return PA_HOOK_OK;

fail:
    pa_modargs_free(ma);
    return PA_HOOK_STOP;
}

static pa_hook_result_t device_module_add_source_cb(pa_bluetooth_device_module_discovery *y, pa_bluetooth_device_add_sink_source_data *d, struct userdata *u) {
    pa_modargs *ma = NULL;
    const char *args = NULL;

    pa_assert(d);
    pa_assert(u);
    pa_assert(!u->p_alsa_source);
    pa_log_debug("enter hook %s",__func__);

    if (!is_headset_profile(d->profile))
        return PA_HOOK_OK;

    args = HW_SCO_SOURCE_ARGS(d->input_port_name);

    // create alsa sink
    pa_alsa_refcnt_inc();
    if (!(ma = pa_modargs_new(args, valid_src_modargs))) {
        pa_log_error("parse args fail");
        return PA_HOOK_STOP;
    }
    
    if (!(u->p_alsa_source = pa_alsa_source_new(d->module, ma, __FILE__, d->card, NULL))) {
        pa_log_error("alsa_source_new fail");    
        goto fail;
    }
    pa_modargs_free(ma);
    return PA_HOOK_OK;

fail:
    pa_modargs_free(ma);
    return PA_HOOK_STOP;
}

/*hook for sink_set_state_in_io_thread_cb*/
static pa_hook_result_t 
device_module_sink_state_change_cb(pa_bluetooth_device_module_discovery *y, pa_bluetooth_device_sink_state_changed_data *d, struct userdata *u)
{
    pa_assert(d);
    pa_assert(u);
    pa_log_debug("enter hook %s",__func__);    
    pa_log_debug("profile %d cur state:%d, new state:%d, default sink:%s, configured sink:%s", 
                 d->profile, d->cur_state, d->new_state,
                 u->core->default_sink->name ? u->core->default_sink->name : "",
                 u->core->configured_default_sink ? u->core->configured_default_sink : ""); 

    if (is_headset_profile(d->profile)) {
        pa_assert(u->p_alsa_sink);
        if (d->new_state == PA_SINK_RUNNING) {
            pa_log_debug("set default sink %s",u->p_alsa_sink->name);
            pa_core_set_configured_default_sink(d->core, u->p_alsa_sink->name);
            pa_alsa_notify_sink_thread_state(u->p_alsa_sink, PA_SINK_SUSPENDED, PA_SUSPEND_IDLE);
            pa_alsa_notify_sink_thread_state(u->p_alsa_sink, PA_SINK_RUNNING, 0);
        }
    }
    return PA_HOOK_OK;
}

/*hook for source_set_state_in_io_thread_cb*/
static pa_hook_result_t 
device_module_source_state_change_cb(pa_bluetooth_device_module_discovery *y, pa_bluetooth_device_source_state_changed_data *d, struct userdata *u)
{
    //static int xxx_flag = 0; /*first start sink device*/
    pa_assert(d);
    pa_assert(u); 
    pa_log_debug("enter hook %s",__func__);

    pa_log_debug("profile %d cur state:%d, new state:%d, suspend_cause %d flag %d default source:%s, configured source:%s source name:%s",
                 d->profile, d->cur_state, d->new_state,
                 d->new_suspend_cause, u->first_flag,
                 u->core->default_source->name ? u->core->default_source->name : "",
                 u->core->configured_default_source ? u->core->configured_default_source : "",d->s_name);
    
    if (is_headset_profile(d->profile))  {
        pa_assert(u->p_alsa_sink);
        pa_assert(u->p_alsa_source);

        if (d->new_suspend_cause == PA_SUSPEND_USER) {
            if (d->cur_state == PA_SOURCE_RUNNING && d->new_state == PA_SOURCE_RUNNING) {
                pa_log_debug("in %s set default source1 %s",__func__,u->p_alsa_source->name);
                pa_core_set_configured_default_source(d->core, u->p_alsa_source->name);
            }
        } else {
            if (d->new_state == PA_SOURCE_RUNNING)
            {
                pa_log_debug("in %s set default source2 %s",__func__,u->p_alsa_source->name);
                pa_core_set_configured_default_source(d->core, u->p_alsa_source->name);
                pa_alsa_notify_source_thread_state(u->p_alsa_source, PA_SOURCE_SUSPENDED, PA_SUSPEND_IDLE);
                pa_alsa_notify_source_thread_state(u->p_alsa_source, PA_SOURCE_RUNNING, 0);

                #ifdef HAVE_CODEC_PARAM
                cset("name=Bt Uplink Switch", HW_CARD, "1", 0, 0);
                #endif

                if (!u->first_flag) {
                    pa_log_debug("in %s set default sink %s",__func__,u->p_alsa_sink->name);
                    pa_core_set_configured_default_sink(d->core, u->p_alsa_sink->name);
                    pa_alsa_notify_sink_thread_state(u->p_alsa_sink, PA_SINK_SUSPENDED, PA_SUSPEND_IDLE);
                    pa_alsa_notify_sink_thread_state(u->p_alsa_sink, PA_SINK_RUNNING, 0);

                    #ifdef HAVE_CODEC_PARAM
                    cset("name=Bt Playback Switch", HW_CARD, "1", 0, 0);
                    #endif

                    u->first_flag = 1;
                }
            }
            else
            {
                if (d->new_state == PA_SOURCE_IDLE && (d->cur_state == PA_SOURCE_RUNNING || d->cur_state == PA_SOURCE_INIT)) {
                    if(strcmp(d->core->default_source->name, u->p_alsa_source->name) == 0)
                    {
                        #ifdef HAVE_CODEC_PARAM
                        cset("name=Bt Uplink Switch", HW_CARD, "0", 0, 0);
                        #endif
                        pa_log_debug("in %s set default source3 %s",__func__,d->s_name);
                        pa_core_set_configured_default_source(d->core, d->s_name);
                    }
                } else {
                    u->first_flag = 0;
                }
            }
        }
    }
    return PA_HOOK_OK;
}

static pa_hook_result_t 
device_module_stop_thread_cb(pa_bluetooth_device_module_discovery *y, void *d, struct userdata *u)
{
    pa_assert(u);
    pa_log_debug("enter hook %s",__func__);
    if (u->p_alsa_sink)
    {
        #ifdef HAVE_CODEC_PARAM
        cset("name=Bt Playback Switch", HW_CARD, "0", 0, 0);
        #endif
        pa_alsa_sink_free(u->p_alsa_sink);
        u->p_alsa_sink = NULL;
        pa_alsa_refcnt_dec();
    }
    if (u->p_alsa_source)
    {
        #ifdef HAVE_CODEC_PARAM
        cset("name=Bt Uplink Switch", HW_CARD, "0", 0, 0);
        #endif
        pa_alsa_source_free(u->p_alsa_source);
        u->p_alsa_source = NULL;
        pa_alsa_refcnt_dec();
    }
    return PA_HOOK_OK;
}

static pa_hook_result_t 
device_module_done_cb(pa_bluetooth_device_module_discovery *y, void *d, struct userdata *u)
{
    pa_assert(u);

    pa_log_debug("enter hook %s",__func__);
    //pa_module_unload(u->module, true);
    if (u->device_module_discovery == NULL) {
        pa_log_debug("no device_module_discovery");
        return PA_HOOK_OK;
    }

    if (u->device_module_init_profile_slot) {
        pa_hook_slot_free(u->device_module_init_profile_slot);
        u->device_module_init_profile_slot = NULL;
    }

    if (u->device_module_add_sink_slot) {
        pa_hook_slot_free(u->device_module_add_sink_slot);
        u->device_module_add_sink_slot = NULL;
    }

    if (u->device_module_add_source_slot) {
        pa_hook_slot_free(u->device_module_add_source_slot);
        u->device_module_add_source_slot = NULL;
    }

    if (u->device_module_sink_state_change_slot) {
        pa_hook_slot_free(u->device_module_sink_state_change_slot);
        u->device_module_sink_state_change_slot = NULL;
    }

    if (u->device_module_source_state_change_slot) {
        pa_hook_slot_free(u->device_module_source_state_change_slot);
        u->device_module_source_state_change_slot = NULL;
    }

    if (u->device_module_stop_thread_slot) {
        pa_hook_slot_free(u->device_module_stop_thread_slot);
        u->device_module_stop_thread_slot = NULL;
    }

    if (u->device_module_done_slot) {
        pa_hook_slot_free(u->device_module_done_slot);
        u->device_module_done_slot = NULL;
    }
    
    pa_bluetooth_device_module_discovery_unref(u->device_module_discovery);
    u->device_module_discovery = NULL;
    return PA_HOOK_OK;
}

static pa_hook_result_t 
pa_core_alsa_sink_begin_new_cb(pa_core *y, pa_core_alsa_sink_new_data *d, struct userdata *u)
{
    const char *port_name = NULL;
    const char *profile_name = NULL;
    pa_device_port *port;
    pa_sink_new_data *sink_new_data = NULL;

    pa_assert(d);
    pa_assert(d->ma);
    pa_assert(d->data);
    pa_log_debug("enter hook %s",__func__);
    
    
    sink_new_data = d->data;

    port_name = pa_modargs_get_value(d->ma, "name", NULL);
    profile_name = pa_modargs_get_value(d->ma, "profile", NULL);

    //connect_ports(d->data, port_name, profile_name);
    if (!sink_new_data->card || !port_name || !profile_name) 
        return PA_HOOK_OK; 

    pa_log_debug("hook input profile = %s, port_name=%s", profile_name, port_name);
   
    if (!strcmp(profile_name, MESH_PROFILE)) {
		pa_assert_se(port = pa_hashmap_get(sink_new_data->card->ports, port_name));
		pa_assert_se(pa_hashmap_put(sink_new_data->ports, port_name, port) >= 0);
		pa_device_port_ref(port);
    }
    return PA_HOOK_OK; 
}

static pa_hook_result_t 
pa_core_alsa_sink_after_new_cb(pa_core *y, pa_core_alsa_sink_new_data *d, struct userdata *u)
{
    const char *profile_name = NULL;
    pa_sink_new_data *sink_new_data = NULL;
    pa_assert(d);
    pa_assert(d->data);
    pa_assert(d->sink);
    pa_log_debug("enter hook %s",__func__);
    
    sink_new_data = d->data;

    profile_name = pa_modargs_get_value(d->ma, "profile", NULL);
    pa_log_debug("hook profile = %s", profile_name);

    if ((sink_new_data->card)&&(profile_name)&&(!strcmp(profile_name, MESH_PROFILE)))
    {
        d->sink->priority += 100;
    }
    return PA_HOOK_OK;
}

static pa_hook_result_t 
pa_core_alsa_source_begin_new_cb(pa_core *y, pa_core_alsa_source_new_data *d, struct userdata *u)
{
    const char *port_name = NULL;
    const char *profile_name = NULL;
    pa_device_port *port = NULL;
	pa_source_new_data *source_new_data = NULL;

    pa_assert(d);
    pa_assert(d->ma);
    pa_assert(d->data);
    pa_log_debug("enter hook %s",__func__);
    
	source_new_data = d->data;

    port_name = pa_modargs_get_value(d->ma, "name", NULL);
    profile_name = pa_modargs_get_value(d->ma, "profile", NULL);

    if (!source_new_data->card || !port_name || !profile_name)
        return PA_HOOK_OK;

    pa_log_debug("hook output profile = %s, port_name=%s", profile_name, port_name);
    if (!strcmp(profile_name, MESH_PROFILE))
    {
        pa_assert_se(port = pa_hashmap_get(source_new_data->card->ports, port_name));
        pa_assert_se(pa_hashmap_put(source_new_data->ports, port_name, port) >= 0);
        pa_device_port_ref(port);
    }
    return PA_HOOK_OK;
}

static pa_hook_result_t 
pa_core_alsa_source_after_new_cb(pa_core *y, pa_core_alsa_source_new_data *d, struct userdata *u)
{
    const char *profile_name = NULL;
    pa_source_new_data *source_new_data = NULL;
    pa_assert(d);
    pa_assert(d->data);
    pa_assert(d->source);
    pa_log_debug("enter hook %s",__func__);

    source_new_data = d->data;

    profile_name = pa_modargs_get_value(d->ma, "profile", NULL);
    pa_log_debug("hook profile = %s", profile_name);

    if ((source_new_data->card)&&(profile_name)&&(!strcmp(profile_name, MESH_PROFILE)))
    {
        d->source->priority += 100;
    }
    return PA_HOOK_OK;
}

static pa_hook_result_t 
pa_core_source_set_state_cb(pa_core *y, pa_core_source_set_state *d, struct userdata *u)
{
    pa_assert(d);
    pa_assert(d->source);
    pa_log_debug("enter hook %s",__func__);

    if ((strstr(d->source->name, "bluez_source") && d->source->state == PA_SOURCE_RUNNING) &&
        (d->state == PA_SOURCE_IDLE || d->state == PA_SOURCE_SUSPENDED))
        d->ret = 0;

    return PA_HOOK_OK;
}

static pa_hook_result_t
pa_core_bluez_device_init_cb(pa_core *y, void *d, struct userdata *u)
{
    pa_assert(y);
    pa_assert(u);
    pa_log_debug("enter hook %s", __func__);

    if (u->device_module_discovery)
        return PA_HOOK_OK;
    if ((u->device_module_discovery = pa_shared_get(u->core, "bluetooth_device_module_discovery")))
        pa_bluetooth_device_module_discovery_ref(u->device_module_discovery);
    else {
        pa_log_error("module-bluez5-discover doesn't seem to be loaded 2, refusing to load module-huawei-adapter");
        return PA_HOOK_OK;
    }

    u->device_module_init_profile_slot =
         pa_hook_connect(pa_bluetooth_module_device_discovery_hook(u->device_module_discovery, PA_BLUETOOTH_DEVICE_MODULE_HOOK_INIT_PROFILE),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_module_init_profile_cb, u);
    u->device_module_add_sink_slot =
        pa_hook_connect(pa_bluetooth_module_device_discovery_hook(u->device_module_discovery, PA_BLUETOOTH_DEVICE_MODULE_HOOK_ADD_SINK),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_module_add_sink_cb, u);
    u->device_module_add_source_slot =
        pa_hook_connect(pa_bluetooth_module_device_discovery_hook(u->device_module_discovery, PA_BLUETOOTH_DEVICE_MODULE_HOOK_ADD_SOURCE),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_module_add_source_cb, u);
    u->device_module_sink_state_change_slot =
        pa_hook_connect(pa_bluetooth_module_device_discovery_hook(u->device_module_discovery, PA_BLUETOOTH_DEVICE_MODULE_HOOK_SINK_STATE_CHANGED),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_module_sink_state_change_cb, u);
    u->device_module_source_state_change_slot =
        pa_hook_connect(pa_bluetooth_module_device_discovery_hook(u->device_module_discovery, PA_BLUETOOTH_DEVICE_MODULE_HOOK_SOURCE_STATE_CHANGED),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_module_source_state_change_cb, u);
    u->device_module_stop_thread_slot =
        pa_hook_connect(pa_bluetooth_module_device_discovery_hook(u->device_module_discovery, PA_BLUETOOTH_DEVICE_MODULE_HOOK_STOP_THREAD),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_module_stop_thread_cb, u);
    u->device_module_done_slot =
        pa_hook_connect(pa_bluetooth_module_device_discovery_hook(u->device_module_discovery, PA_BLUETOOTH_DEVICE_MODULE_DONE),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) device_module_done_cb, u);
    return PA_HOOK_OK;
}

static pa_hook_result_t
pa_core_source_put_hook_callback_cb(pa_core *y, pa_core_source_put_hook_callback_data *d, struct userdata *u)
{
    pa_assert(d);
    pa_assert(y);
    pa_assert(u);
    pa_assert(d->source);
    pa_assert(d->core);
    pa_log_debug("enter hook %s",__func__);

    if(d->default_source){
        if(d->default_source->priority >= d->source->priority){
            if(!(strcmp(d->default_source->name, "bt_sco_source") == 0 && strstr(d->source->name, "bluez") != NULL)){
                pa_log_debug("default source priority is higher, no need to change");
                pa_core_set_configured_default_source(d->core, d->default_source->name);
                pa_subscription_post(d->core, PA_SUBSCRIPTION_EVENT_SERVER | PA_SUBSCRIPTION_EVENT_CHANGE, PA_INVALID_INDEX);
                pa_hook_fire(&(d->core)->hooks[PA_CORE_HOOK_DEFAULT_SOURCE_CHANGED], d->core->default_source);
                d->ret = 0;
            }
        }
    }
    return PA_HOOK_OK;
}

static pa_hook_result_t
pa_core_sink_put_hook_callback_cb(pa_core *y, pa_core_sink_put_hook_callback_data *d, struct userdata *u)
{
    pa_assert(d);
    pa_assert(y);
    pa_assert(u);
    pa_assert(d->sink);
    pa_assert(d->core);
    pa_log_debug("enter hook %s",__func__);

    if(d->default_sink){
        if(d->default_sink->priority >= d->sink->priority){
            if(!(strcmp(d->default_sink->name, "bt_sco_sink") == 0 && strstr(d->sink->name, "bluez") != NULL)){
                pa_log_debug("default sink priority is higher, no need to change");
                pa_core_set_configured_default_sink(d->core, d->default_sink->name);
                pa_subscription_post(d->core, PA_SUBSCRIPTION_EVENT_SERVER | PA_SUBSCRIPTION_EVENT_CHANGE, PA_INVALID_INDEX);
                pa_hook_fire(&(d->core)->hooks[PA_CORE_HOOK_DEFAULT_SINK_CHANGED], d->core->default_sink);
                d->ret = 0;
            }
        }
    }
    return PA_HOOK_OK;
}

static pa_hook_result_t 
pa_core_command_set_default_cb(pa_core *y, pa_native_command_set_default_data *d, struct userdata *u) {
    pa_assert(d);
    pa_assert(y);
    pa_assert(u);
    pa_log_debug("enter hook %s",__func__);

    if (d->command == PA_COMMAND_SET_DEFAULT_SINK) {
        pa_assert(d->sink);
        pa_log_debug("in %s set default sink %s",__func__,d->sink->name);
        if (d->sink->name && strlen(d->sink->name) >= DEFAULT_PROFILE_LENTH && 
            (strncmp(d->sink->name, "bluez_sink.", DEFAULT_PROFILE_LENTH) == 0||strcmp(d->sink->name, "bt_sco_sink") == 0)) {
            pa_log_debug("amixer set on success");
            cset("name=Bt Playback Switch", HW_CARD, "1", 0, 0);
        } else {
            pa_log_debug("amixer set off success");
            cset("name=Bt Playback Switch", HW_CARD, "0", 0, 0);
        }
    } else {
        pa_assert(d->source);
        pa_log_debug("set default source %s",d->source->name);
        if (d->source->name && strlen(d->source->name) >= DEFAULT_PROFILE_LENTH && strncmp(d->source->name, "bluez_source.", DEFAULT_PROFILE_LENTH) == 0) {
            if (d->source->asyncmsgq) {
                struct set_state_data data = { .state = PA_SOURCE_RUNNING, .suspend_cause = PA_SUSPEND_USER };
                (void)pa_asyncmsgq_send(d->source->asyncmsgq, PA_MSGOBJECT(d->source), PA_SOURCE_MESSAGE_SET_STATE, &data, 0, NULL);
            }
        }   
    }
    return PA_HOOK_OK;
}

int pa__init(pa_module*m) {
    pa_modargs *ma = NULL;
    struct userdata *u = NULL;

    pa_assert(m);

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("Failed to parse module arguments");
        return -1;
    }

    m->userdata = u = pa_xnew(struct userdata, 1);
    memset(u,0,sizeof(*u));
    u->module = m;
    u->core = m->core;

    u->alsa_discovery = pa_shared_get(u->core, "pa_core_alsa_discovery");

    u->device_module_alsa_sink_begin_new_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_ALSA_HOOK_ALSA_SINK_BEGIN_NEW),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_alsa_sink_begin_new_cb, u);
    u->device_module_alsa_sink_after_new_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_ALSA_HOOK_ALSA_SINK_AFTER_NEW),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_alsa_sink_after_new_cb, u);
    u->device_module_alsa_source_begin_new_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_ALSA_HOOK_ALSA_SOURCE_BEGIN_NEW),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_alsa_source_begin_new_cb, u);
    u->device_module_alsa_source_after_new_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_ALSA_HOOK_ALSA_SOURCE_AFTER_NEW),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_alsa_source_after_new_cb, u);
    u->device_module_source_set_state_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_HOOK_SOURCE_SET_STATE),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_source_set_state_cb, u);
    u->device_module_sink_put_hook_callback_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_HOOK_SINK_PUT_HOOK_CALLBACK),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_sink_put_hook_callback_cb, u);
    u->device_module_source_put_hook_callback_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_HOOK_SOURCE_PUT_HOOK_CALLBACK),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_source_put_hook_callback_cb, u);
    u->pa_core_native_set_default_command_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_NATIVE_COMMAND_SET_DEFAULT),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_command_set_default_cb, u);
    u->device_module_bluez_device_init_slot =
        pa_hook_connect(pa_alsa_discovery_hook(u->alsa_discovery, PA_CORE_BLUEZ_DEVICE_INIT),
                        PA_HOOK_NORMAL, (pa_hook_cb_t) pa_core_bluez_device_init_cb, u);
    
    pa_log("module-huawei-adapter load ok!!!");

    pa_modargs_free(ma);
    return 0;

fail_free_modargs:

    if (ma)
        pa_modargs_free(ma);

    pa__done(m);

    return -1;
}


void pa__done(pa_module*m) {
    struct userdata *u;

    pa_assert(m);

    if (!(u = m->userdata))
        return;
    
    if (u->device_module_init_profile_slot)
        pa_hook_slot_free(u->device_module_init_profile_slot);

    if (u->device_module_add_sink_slot)
        pa_hook_slot_free(u->device_module_add_sink_slot);

    if (u->device_module_add_source_slot)
        pa_hook_slot_free(u->device_module_add_source_slot);

    if (u->device_module_sink_state_change_slot)
        pa_hook_slot_free(u->device_module_sink_state_change_slot);

    if (u->device_module_source_state_change_slot)
        pa_hook_slot_free(u->device_module_source_state_change_slot);

    if (u->device_module_stop_thread_slot)
        pa_hook_slot_free(u->device_module_stop_thread_slot);
    
    if (u->device_module_done_slot)
        pa_hook_slot_free(u->device_module_done_slot);
    
    if (u->device_module_alsa_sink_begin_new_slot)
        pa_hook_slot_free(u->device_module_alsa_sink_begin_new_slot);
    
    if (u->device_module_alsa_sink_after_new_slot)
        pa_hook_slot_free(u->device_module_alsa_sink_after_new_slot);

    if (u->device_module_alsa_source_begin_new_slot)
        pa_hook_slot_free(u->device_module_alsa_source_begin_new_slot);
    
    if (u->device_module_alsa_source_after_new_slot)
        pa_hook_slot_free(u->device_module_alsa_source_after_new_slot);

    if (u->device_module_source_set_state_slot)
        pa_hook_slot_free(u->device_module_source_set_state_slot);
    
    if (u->pa_core_native_set_default_command_slot)
        pa_hook_slot_free(u->pa_core_native_set_default_command_slot);

    if (u->device_module_discovery)
        pa_bluetooth_device_module_discovery_unref(u->device_module_discovery);

    if (u->device_module_sink_put_hook_callback_slot)
        pa_hook_slot_free(u->device_module_sink_put_hook_callback_slot);

    if (u->device_module_source_put_hook_callback_slot)
        pa_hook_slot_free(u->device_module_source_put_hook_callback_slot);

    if (u->device_module_bluez_device_init_slot)
        pa_hook_slot_free(u->device_module_bluez_device_init_slot);

    pa_xfree(u);
}
