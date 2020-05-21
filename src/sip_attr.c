/**************************************************************************
 **
 ** sngrep - SIP Messages flow viewer
 **
 ** Copyright (C) 2013-2018 Ivan Alonso (Kaian)
 ** Copyright (C) 2013-2018 Irontec SL. All rights reserved.
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
 * @file sip_attr.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in sip_attr.h
 *
 */
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "option.h"
#include "sip_attr.h"
#include "util.h"
#include "curses/ui_manager.h"

static sip_attr_hdr_t attrs[SIP_ATTR_COUNT] = {
    { SIP_ATTR_CALLINDEX,   "index",       "Idx",  "Call Index",    4 },
    { SIP_ATTR_SIPFROM,     "sipfrom",     NULL,   "SIP From",      25 },
    { SIP_ATTR_SIPFROMUSER, "sipfromuser", NULL,   "SIP From User", 20 },
    { SIP_ATTR_SIPTO,       "sipto",       NULL,   "SIP To",        25 },
    { SIP_ATTR_SIPTOUSER,   "siptouser",   NULL,   "SIP To User",   20 },
    { SIP_ATTR_SRC,         "src",         NULL,   "Source",        22 },
    { SIP_ATTR_DST,         "dst",         NULL,   "Destination",   22 },
    { SIP_ATTR_CALLID,      "callid",      NULL,   "Call-ID",       50 },
    { SIP_ATTR_XCALLID,     "xcallid",     NULL,   "X-Call-ID",     50 },
    { SIP_ATTR_DATE,        "date",        NULL,   "Date",          10 },
    { SIP_ATTR_TIME,        "time",        NULL,   "Time",          8 },
    { SIP_ATTR_METHOD,      "method",      NULL,   "Method",        10, sip_attr_color_method },
    { SIP_ATTR_TRANSPORT,   "transport",   "Trans", "Transport",    3 },
    { SIP_ATTR_MSGCNT,      "msgcnt",      "Msgs", "Message Count", 5 },
    { SIP_ATTR_CALLSTATE,   "state",       NULL,   "Call State",    10, sip_attr_color_state },
    { SIP_ATTR_CONVDUR,     "convdur",     "ConvDur", "Conversation Duration", 7 },
    { SIP_ATTR_TOTALDUR,    "totaldur",    "TotalDur", "Total Duration", 8 },
    { SIP_ATTR_REASON_TXT,  "reason",      "Reason Text",   "Reason Text", 25 },
    { SIP_ATTR_WARNING,     "warning",     "Warning", "Warning code", 4 }
};

sip_attr_hdr_t *
sip_attr_get_header(enum sip_attr_id id)
{
    return &attrs[id];
}

const char *
sip_attr_get_description(enum sip_attr_id id)
{
    sip_attr_hdr_t *header;
    if ((header = sip_attr_get_header(id))) {
        return header->desc;
    }
    return NULL;
}

const char *
sip_attr_get_title(enum sip_attr_id id)
{
    sip_attr_hdr_t *header;
    if ((header = sip_attr_get_header(id))) {
        if (header->title)
            return header->title;
        return header->desc;
    }
    return NULL;
}

const char *
sip_attr_get_name(enum sip_attr_id id)
{
    sip_attr_hdr_t *header;
    if ((header = sip_attr_get_header(id))) {
        return header->name;
    }
    return NULL;
}

int
sip_attr_get_width(enum sip_attr_id id)
{
    sip_attr_hdr_t *header;
    if ((header = sip_attr_get_header(id))) {
        return header->dwidth;
    }
    return 0;
}

int
sip_attr_from_name(const char *name)
{
    int i;
    for (i = 0; i < SIP_ATTR_COUNT; i++) {
        if (!strcasecmp(name, attrs[i].name)) {
            return attrs[i].id;
        }
    }
    return -1;
}

int
sip_attr_get_color(int id, const char *value)
{
    sip_attr_hdr_t *header;

    if (!setting_enabled(SETTING_CL_COLORATTR))
        return 0;

    if ((header = sip_attr_get_header(id))) {
        if (header->color) {
            return header->color(value);
        }
    }
    return 0;
}

int
sip_attr_color_method(const char *value)
{
    switch (sip_method_from_str(value)) {
        case SIP_METHOD_INVITE:
            return COLOR_PAIR(CP_RED_ON_DEF) | A_BOLD;
        case SIP_METHOD_NOTIFY:
            return COLOR_PAIR(CP_YELLOW_ON_DEF);
        case SIP_METHOD_OPTIONS:
            return COLOR_PAIR(CP_YELLOW_ON_DEF);
        case SIP_METHOD_REGISTER:
            return COLOR_PAIR(CP_MAGENTA_ON_DEF);
        case SIP_METHOD_SUBSCRIBE:
            return COLOR_PAIR(CP_BLUE_ON_DEF);
	case SIP_METHOD_KDMQ:
	    return COLOR_PAIR(CP_CYAN_ON_DEF) | A_BOLD;
        default:
            return 0;
    }
}

int
sip_attr_color_state(const char *value)
{
    if (!strcmp(value, call_state_to_str(SIP_CALLSTATE_CALLSETUP)))
        return COLOR_PAIR(CP_YELLOW_ON_DEF);
    if (!strcmp(value, call_state_to_str(SIP_CALLSTATE_INCALL)))
        return COLOR_PAIR(CP_BLUE_ON_DEF);
    if (!strcmp(value, call_state_to_str(SIP_CALLSTATE_COMPLETED)))
        return COLOR_PAIR(CP_GREEN_ON_DEF);
    if (!strcmp(value, call_state_to_str(SIP_CALLSTATE_CANCELLED)))
        return COLOR_PAIR(CP_RED_ON_DEF);
    if (!strcmp(value, call_state_to_str(SIP_CALLSTATE_REJECTED)))
        return COLOR_PAIR(CP_RED_ON_DEF);
    if (!strcmp(value, call_state_to_str(SIP_CALLSTATE_BUSY)))
        return COLOR_PAIR(CP_MAGENTA_ON_DEF);
    if (!strcmp(value, call_state_to_str(SIP_CALLSTATE_DIVERTED)))
        return COLOR_PAIR(CP_CYAN_ON_DEF);
    return 0;
}
