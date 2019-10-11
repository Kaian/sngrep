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
 * @file packet_ip.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage IPv4 and IPv6 protocol
 *
 */
#ifndef __SNGREP_PACKET_IP_H
#define __SNGREP_PACKET_IP_H

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif

#include <glib.h>
#include <netinet/ip.h>
#include "parser/packet.h"
#include "parser/address.h"
#include "parser/parser.h"

typedef struct _PacketIpData PacketIpData;
typedef struct _PacketIpDatagram PacketIpDatagram;
typedef struct _PacketIpFragment PacketIpFragment;
typedef struct _DissectorIpData DissectorIpData;

struct _PacketIpData
{
    //! Version (IPv4, IPv6)
    guint32 version;
    //! IP Protocol
    guint8 protocol;
    //! Source Address
    gchar srcip[ADDRESSLEN];
    //! Destination Address
    gchar dstip[ADDRESSLEN];
};

struct _PacketIpDatagram
{
    //! Source Address
    gchar srcip[ADDRESSLEN];
    //! Destination Address
    gchar dstip[ADDRESSLEN];
    //! Fragmentation identifier
    guint32 id;
    //! Datagram length
    guint32 len;
    //! Datagram seen bytes
    guint32 seen;
    //! Fragments
    GPtrArray *fragments;
};

//! @brief IP assembly data.
struct _PacketIpFragment
{
    //! Packet Source addresses
    gchar srcip[ADDRESSLEN];
    //! Packet Destination address
    gchar dstip[ADDRESSLEN];
    //! IP version
    guint32 version;
    //! IP transport dissectors
    guint8 proto;
    //! IP header size
    guint32 hl;
    //! Fragment offset
    guint16 off;
    //! IP content len
    guint32 len;
    //! Fragmentation flag
    guint16 frag;
    //! Fragmentation identifier
    guint32 id;
    //! Fragmentation offset
    guint16 frag_off;
    //! More fragments expected
    guint16 more;
    //! Packets with this frame data
    Packet *packet;
    //! Fragment contents
    GByteArray *data;
};

struct _DissectorIpData
{
    GList *assembly;
};

/**
 * @brief Retrieve packet IP protocol specific data
 * @param packet Packet pointer to get data
 * @return Pointer to PacketIPData | NULL
 */
PacketIpData *
packet_ip_data(const Packet *packet);

/**
 * @brief Create a IP parser
 *
 * @return a protocols' parsers pointer
 */
PacketDissector *
packet_ip_new();

#endif
