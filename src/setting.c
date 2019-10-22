/**************************************************************************
 **
 ** sngrep - SIP Messages flow viewer
 **
 ** Copyright (C) 2013-2019 Ivan Alonso (Kaian)
 ** Copyright (C) 2013-2019 Irontec SL. All rights reserved.
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 ****************************************************************************/
/**
 * @file setting.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code of functions defined in setting.h
 *
 */
#include "config.h"
#include <string.h>
#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include "ncurses/keybinding.h"
#include "glib/glib-extra.h"
#include "setting.h"
#include "storage/datetime.h"

/**
 * @brief Storage settings
 *
 * This struct contains all the configurable options and can be updated
 * from resource files.
 *
 *  - Settings
 *  - Alias
 *  - Call List columns
 */
static SettingStorage *settings = NULL;

/**
 * @brief Create a new number type setting
 */
static Setting *
setting_number_new(const gchar *name, const gchar *value)
{
    Setting *setting = g_malloc0(sizeof(Setting));
    setting->name = name;
    setting->fmt = SETTING_FMT_NUMBER;
    strncpy(setting->value, value, SETTING_MAX_LEN);
    return setting;
}

/**
 * @brief Create a new string type setting
 */
static Setting *
setting_string_new(const gchar *name, const gchar *value)
{
    Setting *setting = g_malloc0(sizeof(Setting));
    setting->name = name;
    setting->fmt = SETTING_FMT_STRING;
    strncpy(setting->value, value, SETTING_MAX_LEN);
    return setting;
}

/**
 * @brief Create a new boolean type setting
 */
static Setting *
setting_bool_new(const gchar *name, const gchar *value)
{
    Setting *setting = g_malloc0(sizeof(Setting));
    setting->name = name;
    setting->fmt = SETTING_FMT_BOOLEAN;
    strncpy(setting->value, value, SETTING_MAX_LEN);
    setting->valuelist = g_strsplit("on,off", ",", -1);
    return setting;
}

/**
 * @brief Create a new enum type setting
 */
static Setting *
setting_enum_new(const gchar *name, const gchar *value, const gchar *valuelist)
{
    Setting *setting = g_malloc0(sizeof(Setting));
    setting->name = name;
    setting->fmt = SETTING_FMT_ENUM;
    strncpy(setting->value, value, SETTING_MAX_LEN);
    setting->valuelist = g_strsplit(valuelist, ",", -1);
    return setting;
}

static void
setting_free(Setting *setting)
{
    g_return_if_fail(setting != NULL);
    switch (setting->fmt) {
        case SETTING_FMT_NUMBER:
        case SETTING_FMT_STRING:
            break;
        case SETTING_FMT_BOOLEAN:
        case SETTING_FMT_ENUM:
            g_strfreev(setting->valuelist);
            break;
        default:
            break;
    }
    g_free(setting);
}

Setting *
setting_by_id(enum SettingId id)
{
    return g_ptr_array_index(settings->values, id);
}

Setting *
setting_by_name(const gchar *name)
{
    for (guint i = 0; i < g_ptr_array_len(settings->values); i++) {
        Setting *setting = g_ptr_array_index(settings->values, i);
        if (g_strcmp0(setting->name, name) == 0) {
            return setting;
        }
    }
    return NULL;
}

enum SettingId
setting_id(const gchar *name)
{
    const Setting *sett = setting_by_name(name);
    return (sett) ? g_ptr_array_data_index(settings->values, sett) : SETTING_UNKNOWN;
}

const gchar *
setting_name(enum SettingId id)
{
    const Setting *sett = setting_by_id(id);
    return (sett) ? sett->name : NULL;
}

gint
setting_format(enum SettingId id)
{
    const Setting *sett = setting_by_id(id);
    return (sett) ? (int) sett->fmt : -1;
}

const gchar **
setting_valid_values(enum SettingId id)
{
    const Setting *sett = setting_by_id(id);
    return (const gchar **) ((sett) ? sett->valuelist : NULL);
}

const gchar *
setting_get_value(enum SettingId id)
{
    const Setting *sett = setting_by_id(id);
    return (sett && strlen(sett->value)) ? sett->value : NULL;
}

gint
setting_get_intvalue(enum SettingId id)
{
    const Setting *sett = setting_by_id(id);
    return (sett && strlen(sett->value)) ? g_atoi(sett->value) : -1;
}

void
setting_set_value(enum SettingId id, const gchar *value)
{
    Setting *sett = setting_by_id(id);
    g_return_if_fail(sett != NULL);
    memset(sett->value, 0, sizeof(sett->value));
    if (value) {
        if (strlen(value) < SETTING_MAX_LEN) {
            strcpy(sett->value, value);
        } else {
            fprintf(stderr, "Setting value %s for %s is too long\n", sett->value, sett->name);
            exit(1);
        }
    }
}

void
setting_set_intvalue(enum SettingId id, gint value)
{
    char strvalue[80];
    sprintf(strvalue, "%d", value);
    setting_set_value(id, strvalue);
}

gint
setting_enabled(enum SettingId id)
{
    return setting_has_value(id, "on") ||
           setting_has_value(id, "yes");
}

gint
setting_disabled(enum SettingId id)
{
    return setting_has_value(id, "off") ||
           setting_has_value(id, "no");
}

gint
setting_has_value(enum SettingId id, const gchar *value)
{
    Setting *sett = setting_by_id(id);
    if (sett) {
        return !strcmp(sett->value, value);
    }

    return 0;
}

void
setting_toggle(enum SettingId id)
{
    Setting *sett = setting_by_id(id);

    if (sett) {
        switch (sett->fmt) {
            case SETTING_FMT_BOOLEAN:
                (setting_enabled(id)) ? setting_set_value(id, SETTING_OFF) : setting_set_value(id, SETTING_ON);
                break;
            case SETTING_FMT_ENUM:
                setting_set_value(id, setting_enum_next(id, sett->value));
            case SETTING_FMT_STRING:
                break;
            case SETTING_FMT_NUMBER:
                break;
            default:
                break;
        }
    }
}

const gchar *
setting_enum_next(enum SettingId id, const gchar *value)
{
    int i;
    const char *vnext;
    Setting *sett;

    if (!(sett = setting_by_id(id)))
        return NULL;

    if (sett->fmt != SETTING_FMT_ENUM)
        return NULL;

    if (!sett->valuelist)
        return NULL;

    // If setting has no value, set the first one
    if (!value)
        return *sett->valuelist;

    // Iterate through valid values
    for (i = 0; sett->valuelist[i]; i++) {
        vnext = sett->valuelist[i + 1];
        // If current value matches
        if (!strcmp(sett->valuelist[i], value)) {
            return (vnext) ? vnext : setting_enum_next(id, NULL);
        }
    }

    return NULL;
}

gint
setting_column_pos(enum AttributeId id)
{
    const gchar *sett_name = attr_name(id);
    g_return_val_if_fail(sett_name != NULL, -1);

    gchar *sett_text = g_strdup_printf("cl.column.%s.pos", sett_name);
    g_return_val_if_fail(sett_text != NULL, -1);

    gint sett_id = setting_id(sett_text);
    g_free(sett_text);
    g_return_val_if_fail(sett_id != SETTING_UNKNOWN, -1);

    return setting_get_intvalue(sett_id);
}

gint
setting_column_width(enum AttributeId id)
{
    const gchar *sett_name = attr_name(id);
    g_return_val_if_fail(sett_name != NULL, -1);

    gchar *sett_text = g_strdup_printf("cl.column.%s.width", sett_name);
    g_return_val_if_fail(sett_text != NULL, -1);

    gint sett_id = setting_id(sett_text);
    g_free(sett_text);

    return setting_get_intvalue(sett_id);
}

/**
 * @brief Sets an alias for a given address
 *
 * @param address IP Address
 * @param string representing the alias
 */
static SettingAlias *
setting_alias_new(const gchar *address, const gchar *alias)
{
    SettingAlias *setting = g_malloc0(sizeof(SettingAlias));
    setting->address = g_strdup(address);
    setting->alias = g_strdup(alias);
    return setting;
}

static void
setting_alias_free(SettingAlias *setting, G_GNUC_UNUSED gpointer user_data)
{
    g_return_if_fail(setting != NULL);
    g_free(setting->alias);
    g_free(setting->address);
    g_free(setting);
}

const gchar *
setting_get_alias(const gchar *address)
{
    g_return_val_if_fail(address != NULL, NULL);

    for (GList *l = settings->alias; l != NULL; l = l->next) {
        SettingAlias *alias = l->data;
        if (g_strcmp0(alias->address, address) == 0) {
            return alias->alias;
        }
    }

    return address;
}

/**
 * @brief Sets an externip for a given address
 *
 * @param address IP Address
 * @param string representing the externip
 */
static SettingExtenIp *
setting_externip_new(const gchar *address, const gchar *externip)
{
    SettingExtenIp *setting = g_malloc0(sizeof(SettingExtenIp));
    setting->address = g_strdup(address);
    setting->externip = g_strdup(externip);
    return setting;
}

static void
setting_externip_free(SettingExtenIp *setting, G_GNUC_UNUSED gpointer user_data)
{
    g_return_if_fail(setting != NULL);
    g_free(setting->address);
    g_free(setting->externip);
    g_free(setting);
}

const gchar *
setting_get_externip(const gchar *address)
{
    g_return_val_if_fail(address != NULL, NULL);

    for (GList *l = settings->externips; l != NULL; l = l->next) {
        SettingExtenIp *externip = l->data;
        if (g_strcmp0(externip->address, address) == 0) {
            return externip->externip;
        }
        if (g_strcmp0(externip->externip, address) == 0) {
            return externip->address;
        }
    }

    return NULL;
}

gint
setting_read_file(const gchar *fname)
{
    FILE *fh;
    char line[1024], type[20], option[50], value[50];

    if (!(fh = fopen(fname, "rt")))
        return -1;

    while (fgets(line, 1024, fh) != NULL) {
        // Check if this line is a commentary or empty line
        if (!strlen(line) || *line == '#')
            continue;

        // Get configuration option from setting line
        if (sscanf(line, "%s %s %[^\t\n]", type, option, value) == 3) {
            if (!strcasecmp(type, "set")) {
                enum SettingId id = setting_id(option);
                if (id == SETTING_UNKNOWN) {
                    g_printerr("error: Unknown setting: %s\n", option);
                    continue;
                }
                setting_set_value(id, value);
            } else if (!strcasecmp(type, "alias")) {
                settings->alias = g_list_append(settings->alias, setting_alias_new(option, value));
            } else if (!strcasecmp(type, "externip")) {
                settings->externips = g_list_append(settings->externips, setting_externip_new(option, value));
            } else if (!strcasecmp(type, "bind")) {
                key_bind_action(key_action_id(option), key_from_str(value));
            } else if (!strcasecmp(type, "unbind")) {
                key_unbind_action(key_action_id(option), key_from_str(value));
            }
        }
    }
    fclose(fh);
    return 0;
}

int
settings_init(SettingOpts options)
{
    // Custom user conf file
    const gchar *homedir = g_get_home_dir();
    gchar *curdir = g_get_current_dir();

    // Allocate memory for settings storage
    settings = g_malloc0(sizeof(SettingStorage));
    settings->values = g_ptr_array_new_with_free_func((GDestroyNotify) setting_free);
    g_ptr_array_set_size(settings->values, SETTING_COUNT);

    // Default settings values
    g_ptr_array_set(settings->values, SETTING_BACKGROUND,
                    setting_enum_new("background", "dark", "dark,default"));
    g_ptr_array_set(settings->values, SETTING_COLORMODE,
                    setting_enum_new("colormode", "request", "request,cseq,callid"));
    g_ptr_array_set(settings->values, SETTING_SYNTAX,
                    setting_bool_new("syntax", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_SYNTAX_TAG,
                    setting_bool_new("syntax.tag", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_SYNTAX_BRANCH,
                    setting_bool_new("syntax.branch", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_ALTKEY_HINT,
                    setting_bool_new("hintkeyalt", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_EXITPROMPT,
                    setting_bool_new("exitprompt", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_LIMIT,
                    setting_number_new("capture.limit", "20000"));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_DEVICE,
                    setting_string_new("capture.device", "any"));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_OUTFILE,
                    setting_string_new("capture.outfile", ""));
#ifdef WITH_SSL
    g_ptr_array_set(settings->values, SETTING_CAPTURE_KEYFILE,
                    setting_string_new("capture.keyfile", ""));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_TLSSERVER,
                    setting_string_new("capture.tlsserver", ""));
#endif
    g_ptr_array_set(settings->values, SETTING_CAPTURE_RTP,
                    setting_bool_new("capture.rtp", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_IP,
                    setting_bool_new("capture.packet.ip", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_UDP,
                    setting_bool_new("capture.packet.udp", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_TCP,
                    setting_bool_new("capture.packet.tcp", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_TLS,
                    setting_bool_new("capture.packet.tls", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_HEP,
                    setting_bool_new("capture.packet.hep", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_WS,
                    setting_bool_new("capture.packet.ws", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_SIP,
                    setting_bool_new("capture.packet.sip", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_SDP,
                    setting_bool_new("capture.packet.sdp", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_RTP,
                    setting_bool_new("capture.packet.rtp", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_PACKET_RTCP,
                    setting_bool_new("capture.packet.rtcp", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_STORAGE,
                    setting_enum_new("capture.storage", "memory", "none,memory"));
    g_ptr_array_set(settings->values, SETTING_CAPTURE_ROTATE,
                    setting_bool_new("capture.rotate", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_SIP_NOINCOMPLETE,
                    setting_bool_new("sip.noincomplete", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_SIP_HEADER_X_CID,
                    setting_string_new("sip.xcid", "X-Call-ID|X-CID"));
    g_ptr_array_set(settings->values, SETTING_SIP_CALLS,
                    setting_bool_new("sip.calls", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_SAVEPATH,
                    setting_string_new("savepath", curdir));
    g_ptr_array_set(settings->values, SETTING_DISPLAY_ALIAS,
                    setting_bool_new("displayalias", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CL_SCROLLSTEP,
                    setting_number_new("cl.scrollstep", "4"));
    g_ptr_array_set(settings->values, SETTING_CL_COLORATTR,
                    setting_bool_new("cl.colorattr", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CL_AUTOSCROLL,
                    setting_bool_new("cl.autoscroll", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CL_SORTFIELD,
                    setting_string_new("cl.sortfield", attr_name(ATTR_CALLINDEX)));
    g_ptr_array_set(settings->values, SETTING_CL_SORTORDER,
                    setting_string_new("cl.sortorder", "asc"));
    g_ptr_array_set(settings->values, SETTING_CL_FIXEDCOLS,
                    setting_number_new("cl.fixedcols", "2"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_INDEX_POS,
                    setting_number_new("cl.column.index.pos", "0"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_INDEX_WIDTH,
                    setting_number_new("cl.column.index.width", "4"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPFROM_POS,
                    setting_number_new("cl.column.sipfrom.pos", "2"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPFROM_WIDTH,
                    setting_number_new("cl.column.sipfrom.width", "25"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPFROMUSER_POS,
                    setting_number_new("cl.column.sipfromuser.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPFROMUSER_WIDTH,
                    setting_number_new("cl.column.sipfromuser.width", "20"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPTO_POS,
                    setting_number_new("cl.column.sipto.pos", "3"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPTO_WIDTH,
                    setting_number_new("cl.column.sipto.width", "25"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPTOUSER_POS,
                    setting_number_new("cl.column.siptouser.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SIPTOUSER_WIDTH,
                    setting_number_new("cl.column.siptouser.width", "20"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SRC_POS,
                    setting_number_new("cl.column.src.pos", "5"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_SRC_WIDTH,
                    setting_number_new("cl.column.src.width", "22"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_DST_POS,
                    setting_number_new("cl.column.dst.pos", "6"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_DST_WIDTH,
                    setting_number_new("cl.column.dst.width", "22"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_CALLID_POS,
                    setting_number_new("cl.column.callid.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_CALLID_WIDTH,
                    setting_number_new("cl.column.callid.width", "50"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_XCALLID_POS,
                    setting_number_new("cl.column.xcallid.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_XCALLID_WIDTH,
                    setting_number_new("cl.column.xcallid.width", "50"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_DATE_POS,
                    setting_number_new("cl.column.date.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_DATE_WIDTH,
                    setting_number_new("cl.column.date.width", "10"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_TIME_POS,
                    setting_number_new("cl.column.time.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_TIME_WIDTH,
                    setting_number_new("cl.column.time.width", "8"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_METHOD_POS,
                    setting_number_new("cl.column.method.pos", "1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_METHOD_WIDTH,
                    setting_number_new("cl.column.method.width", "10"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_TRANSPORT_POS,
                    setting_number_new("cl.column.transport.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_TRANSPORT_WIDTH,
                    setting_number_new("cl.column.transport.width", "3"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_MSGCNT_POS,
                    setting_number_new("cl.column.msgcnt.pos", "4"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_MSGCNT_WIDTH,
                    setting_number_new("cl.column.msgcnt.width", "5"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_CALLSTATE_POS,
                    setting_number_new("cl.column.state.pos", "7"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_CALLSTATE_WIDTH,
                    setting_number_new("cl.column.state.width", "12"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_CONVDUR_POS,
                    setting_number_new("cl.column.convdur.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_CONVDUR_WIDTH,
                    setting_number_new("cl.column.convdur.width", "7"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_TOTALDUR_POS,
                    setting_number_new("cl.column.totaldur.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_TOTALDUR_WIDTH,
                    setting_number_new("cl.column.totaldur.width", "8"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_REASON_TXT_POS,
                    setting_number_new("cl.column.reason.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_REASON_TXT_WIDTH,
                    setting_number_new("cl.column.reason.width", "25"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_WARNING_POS,
                    setting_number_new("cl.column.warning.pos", "-1"));
    g_ptr_array_set(settings->values, SETTING_CL_COL_WARNING_WIDTH,
                    setting_number_new("cl.column.warning.width", "4"));
    g_ptr_array_set(settings->values, SETTING_CF_FORCERAW,
                    setting_bool_new("cf.forceraw", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CF_RAWMINWIDTH,
                    setting_number_new("cf.rawminwidth", "40"));
    g_ptr_array_set(settings->values, SETTING_CF_RAWFIXEDWIDTH,
                    setting_number_new("cf.rawfixedwidth", ""));
    g_ptr_array_set(settings->values, SETTING_CF_SPLITCALLID,
                    setting_bool_new("cf.splitcallid", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CF_HIGHTLIGHT,
                    setting_enum_new("cf.highlight", "bold", "bold,reverse,reversebold"));
    g_ptr_array_set(settings->values, SETTING_CF_SCROLLSTEP,
                    setting_number_new("cf.scrollstep", "4"));
    g_ptr_array_set(settings->values, SETTING_CF_LOCALHIGHLIGHT,
                    setting_bool_new("cf.localhighlight", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CF_SDP_INFO,
                    setting_enum_new("cf.sdpinfo", SETTING_OFF, "off,first,full,compressed"));
    g_ptr_array_set(settings->values, SETTING_CF_MEDIA,
                    setting_bool_new("cf.media", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CF_ONLYMEDIA,
                    setting_bool_new("cf.onlymedia", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CF_DELTA,
                    setting_bool_new("cf.deltatime", SETTING_ON));
    g_ptr_array_set(settings->values, SETTING_CF_HIDEDUPLICATE,
                    setting_bool_new("cf.hideduplicate", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_CR_SCROLLSTEP,
                    setting_number_new("cr.scrollstep", "10"));
    g_ptr_array_set(settings->values, SETTING_CR_NON_ASCII,
                    setting_string_new("cr.nonascii", "."));
    g_ptr_array_set(settings->values, SETTING_FILTER_PAYLOAD,
                    setting_string_new("filter.payload", ""));
    g_ptr_array_set(settings->values, SETTING_FILTER_METHODS,
                    setting_string_new("filter.methods",
                                       "REGISTER,INVITE,SUBSCRIBE,NOTIFY,OPTIONS,PUBLISH,MESSAGE,INFO,REFER,UPDATE"));
#ifdef USE_HEP
    g_ptr_array_set(settings->values, SETTING_HEP_SEND,
                    setting_bool_new("eep.send", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_HEP_SEND_VER,
                    setting_number_new("eep.send.version", "3"));
    g_ptr_array_set(settings->values, SETTING_HEP_SEND_ADDR,
                    setting_string_new("eep.send.address", "127.0.0.1"));
    g_ptr_array_set(settings->values, SETTING_HEP_SEND_PORT,
                    setting_number_new("eep.send.port", "9060"));
    g_ptr_array_set(settings->values, SETTING_HEP_SEND_PASS,
                    setting_string_new("eep.send.pass", ""));
    g_ptr_array_set(settings->values, SETTING_HEP_SEND_ID,
                    setting_number_new("eep.send.id", "2000"));
    g_ptr_array_set(settings->values, SETTING_HEP_LISTEN,
                    setting_bool_new("eep.listen", SETTING_OFF));
    g_ptr_array_set(settings->values, SETTING_HEP_LISTEN_VER,
                    setting_string_new("eep.listen.version", "3"));
    g_ptr_array_set(settings->values, SETTING_HEP_LISTEN_ADDR,
                    setting_string_new("eep.listen.address", "0.0.0.0"));
    g_ptr_array_set(settings->values, SETTING_HEP_LISTEN_PORT,
                    setting_number_new("eep.listen.port", "9060"));
    g_ptr_array_set(settings->values, SETTING_HEP_LISTEN_PASS,
                    setting_string_new("eep.listen.pass", ""));
    g_ptr_array_set(settings->values, SETTING_HEP_LISTEN_UUID,
                    setting_bool_new("eep.listen.uuid", SETTING_OFF));
#endif

    // Done if config file should not be read
    if (!options.use_defaults) {

        // Read options from configuration files
        setting_read_file("/etc/sngreprc");
        setting_read_file("/usr/local/etc/sngreprc");

        // Get user configuration
        if (getenv("SNGREPRC") != NULL) {
            setting_read_file(getenv("SNGREPRC"));
        } else if (homedir != NULL) {
            GString *userconf = g_string_new(homedir);
            g_string_append(userconf, "/.sngreprc");
            setting_read_file(userconf->str);
            g_string_free(userconf, TRUE);
        }
    }
    g_free(curdir);

    // Override settings if requested
    if (options.file != NULL) {
        setting_read_file(options.file);
    }

    return 0;
}

void
settings_deinit()
{
    g_list_foreach(settings->alias, (GFunc) setting_alias_free, NULL);
    g_list_free(settings->alias);
    g_list_foreach(settings->externips, (GFunc) setting_externip_free, NULL);
    g_list_free(settings->externips);
    g_ptr_array_free(settings->values, TRUE);
    g_free(settings);
}

void
settings_dump()
{
    for (guint i = 1; i < SETTING_COUNT; i++) {
        printf("SettingId: %d\t SettingName: %-30s Value: %s\n", i,
               setting_name(i),
               setting_get_value(i));
    }

    for (GList *l = settings->alias; l != NULL; l = l->next) {
        SettingAlias *alias = l->data;
        printf("Address: %s\t Alias: %s\n",
               alias->address,
               alias->alias
        );
    }

    for (GList *l = settings->externips; l != NULL; l = l->next) {
        SettingExtenIp *externip = l->data;
        printf("Address: %s\t ExternIP: %s\n",
               externip->address,
               externip->externip
        );
    }
}
