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
 * @file address.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage network addresses
 *
 * Multiple structures contain source and destination address.
 * This file contains the unification of all sngrep address containers.
 *
 */

#ifndef __SNGREP_ADDRESS_H
#define __SNGREP_ADDRESS_H

#include <netinet/in.h>
#include <glib.h>

//! Address string Length
#ifdef USE_IPV6
#ifdef INET6_ADDRSTRLEN
#define ADDRESSLEN INET6_ADDRSTRLEN
#else
#define ADDRESSLEN 46
#endif
#else
#define ADDRESSLEN INET_ADDRSTRLEN
#endif

#define ADDRESS_ZERO { .ip = { 0 }, .port = 0}

//! Shorter declaration of address structure
typedef struct _Address Address;

/**
 * @brief Network address
 */
struct _Address
{
    //! IP address
    gchar *ip;
    //! Port
    guint16 port;
};

/**
 * @brief Check if two address are equal (including port)
 *
 * @param addr1 Address structure
 * @param addr2 Address structure
 * @return true if addresses contain the IP address, false otherwise
 */
gboolean
addressport_equals(const Address *addr1, const Address *addr2);

/**
 * @brief Check if two address are equal (ignoring port)
 *
 * @param addr1 Address structure
 * @param addr2 Address structure
 * @return true if addresses contain the same data, false otherwise
 */
gboolean
address_equals(const Address *addr1, const Address *addr2);

/**
 * @brief Check if a given IP address belongs to a local device
 *
 * @param address Address structure
 * @return true if address is local, false otherwise
 */
gboolean
address_is_local(const Address *addr);

/**
 * @brief Convert string IP:PORT to address structure
 *
 * @param string in format IP:PORT
 * @return address structure pointer
 */
Address *
address_from_str(const gchar *ipport);

/**
 * @brief Clone existing Address allocating new memory
 * @param address Original address pointer to be cloned
 * @return
 */
Address *
address_clone(const Address *address);

/**
 * @brief Free Address pointer
 * @param address Adress structure pointer
 */
void
address_free(Address *address);

/**
 * @brif Create a new Address pointer
 */
Address *
address_new(const gchar *ip, guint16 port);

#endif /* __SNGREP_ADDRESS_H */
