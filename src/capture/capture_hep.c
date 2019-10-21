/**************************************************************************
 **
 ** sngrep - SIP Messages flow viewer
 **
 ** Copyright (C) 2013-2019 Ivan Alonso (Kaian)
 ** Copyright (C) 2013-2019 Irontec SL. All rights reserved.
 ** Copyright (C) 2012 Homer Project (http://www.sipcapture.org)
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
 * @file capture_hep.c
 *
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * @author Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *
 * @brief Functions to manage hep protocol
 *
 * This file contains declaration of structure and functions to send and
 * receive packet information through HEP-EEP (Extensible Encapsulation Protocol)
 *
 * Additional information about HEP-EEP protocol can be found in sipcature
 * repositories at https://github.com/sipcapture/HEP
 *
 * @note Most of this code has been taken from hep-c and sipgrep (originally
 * written by Alexandr Dubovikov). Modifications of sources to work with
 * sngrep packet structures has been made by Ivan Alonso (Kaian)
 *
 */
#include "config.h"
#include <glib.h>
#include <arpa/inet.h>
#include "setting.h"
#include "parser/packet_hep.h"
#include "parser/packet_ip.h"
#include "parser/packet_udp.h"
#include "parser/packet_sip.h"
#include "parser/packet.h"
#include "capture_hep.h"

// CapturePcap class definition
G_DEFINE_TYPE(CaptureInputHep, capture_input_hep, CAPTURE_TYPE_INPUT)

GQuark
capture_hep_error_quark()
{
    return g_quark_from_static_string("capture-hep");
}

static gboolean
capture_hep_parse_url(const gchar *url_str, CaptureHepUrl *url, GError **error)
{
    // Parse url in format dissectors:host:port
    gchar **tokens = g_strsplit(url_str, ":", 3);

    // Check we have at least three tokens
    if (g_strv_length(tokens) != 3) {
        g_set_error(error,
                    CAPTURE_HEP_ERROR,
                    CAPTURE_HEP_ERROR_URL_PARSE,
                    "Unable to dissect URL %s: Invalid arguments number",
                    url_str);
        return FALSE;
    }

    // Set capture url data
    if (g_strcmp0(tokens[0], "udp") == 0) {
        url->proto = G_SOCKET_PROTOCOL_UDP;
    } else {
        g_set_error(error,
                    CAPTURE_HEP_ERROR,
                    CAPTURE_HEP_ERROR_URL_PARSE,
                    "Unable to dissect URL %s: Unsupported protocol %s",
                    url_str, tokens[0]);
        return FALSE;
    }

    url->host = g_strdup(tokens[1]);
    url->port = atoi(tokens[2]);

    g_strfreev(tokens);
    return TRUE;
}

static gboolean
capture_input_hep_receive(G_GNUC_UNUSED gint fd,
                          G_GNUC_UNUSED GIOCondition condition,
                          CaptureInput *input)
{
    char buffer[MAX_HEP_BUFSIZE];
    CaptureInputHep *hep = CAPTURE_INPUT_HEP(input);
    PacketParser *parser = capture_input_parser(input);

    /* Receive HEP generic header */
    gssize received = g_socket_receive_from(
        hep->socket,
        NULL,
        buffer,
        MAX_HEP_BUFSIZE,
        FALSE,
        NULL
    );

    if (received == -1)
        return FALSE;

    // Convert packet data
    GByteArray *data = g_byte_array_new();
    g_byte_array_append(data, (const guint8 *) buffer, (guint) received);

    // Create a new packet for this data
    Packet *packet = packet_new(parser);
    PacketFrame *frame = g_malloc0(sizeof(PacketFrame));
    frame->data = g_byte_array_new();
    g_byte_array_append(frame->data, data->data, data->len);
    packet->frames = g_list_append(packet->frames, frame);

    // Pass packet to dissectors
    parser->current = parser->dissector_tree;
    packet_parser_next_dissector(parser, packet, data);

    // Remove packet reference after parsing
    packet_unref(packet);
    g_byte_array_unref(data);

    return TRUE;
}

CaptureInput *
capture_input_hep(const gchar *url, GError **error)
{
    // Create a new structure to handle this capture source
    CaptureInputHep *hep = g_object_new(CAPTURE_TYPE_INPUT_HEP, NULL);

    hep->version = setting_get_intvalue(SETTING_HEP_LISTEN_VER);
    hep->password = setting_get_value(SETTING_HEP_LISTEN_PASS);
    if (url != NULL) {
        if (!capture_hep_parse_url(url, &hep->url, error)) {
            return NULL;
        }
    } else {
        hep->url.proto = G_SOCKET_PROTOCOL_UDP;
        hep->url.host = setting_get_value(SETTING_HEP_LISTEN_ADDR);
        hep->url.port = setting_get_intvalue(SETTING_HEP_LISTEN_PORT);
    }

    // Check protocol version is support
    if (hep->version != 2 && hep->version != 3) {
        g_set_error(error,
                    CAPTURE_HEP_ERROR,
                    CAPTURE_HEP_ERROR_VERSION,
                    "HEP: Unsupported protocol version %d",
                    hep->version);
        return NULL;
    }

    GSocketAddress *listen_addr = g_inet_socket_address_new_from_string(
        hep->url.host,
        hep->url.port
    );

    if (listen_addr == NULL) {
        g_set_error(error,
                    CAPTURE_HEP_ERROR,
                    CAPTURE_HEP_ERROR_URL_PARSE,
                    "HEP: failed g_inet_socket_address_new_from_string() for %s:%d",
                    hep->url.host, hep->url.port);
        return NULL;
    }

    // Create a socket for a new TCP IPv4 connection
    GError *socket_error = NULL;
    hep->socket = g_socket_new(
        G_SOCKET_FAMILY_IPV4,
        G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP,
        &socket_error
    );

    if (socket_error != NULL) {
        g_propagate_error(error, socket_error);
        return NULL;
    }

    // Bind that socket to the requested address and port
    g_socket_bind(hep->socket, listen_addr, TRUE, &socket_error);
    if (socket_error != NULL) {
        g_propagate_error(error, socket_error);
        return NULL;
    }

    // Create a new structure to handle this capture source
    g_autofree gchar *source_str = g_strdup_printf("L:%d", hep->url.port);
    capture_input_set_source_str(CAPTURE_INPUT(hep), source_str);
    capture_input_set_mode(CAPTURE_INPUT(hep), CAPTURE_MODE_ONLINE);

    // Create packet parser tree
    packet_parser_dissector_init(
        capture_input_parser(CAPTURE_INPUT(hep)),
        NULL,
        PACKET_HEP
    );

    capture_input_set_source(
        CAPTURE_INPUT(hep),
        g_socket_create_source(
            hep->socket,
            G_IO_IN | G_IO_ERR | G_IO_HUP,
            FALSE
        )
    );

    g_source_set_callback(
        capture_input_source(CAPTURE_INPUT(hep)),
        (GSourceFunc) G_CALLBACK(capture_input_hep_receive),
        CAPTURE_INPUT(hep),
        NULL
    );

    return CAPTURE_INPUT(hep);
}

void *
capture_input_hep_start(CaptureInput *input)
{
    g_source_attach(capture_input_source(input), NULL);
    return NULL;
}

void
capture_input_hep_stop(CaptureInput *input)
{
    CaptureInputHep *hep = CAPTURE_INPUT_HEP(input);
    g_socket_close(hep->socket, NULL);
    g_clear_object(&hep->socket);
}

const char *
capture_input_hep_port(CaptureManager *manager)
{
    for (GSList *l = manager->inputs; l != NULL; l = l->next) {
        CaptureInput *input = l->data;
        if (capture_input_tech(input) == CAPTURE_TECH_HEP) {
            CaptureInputHep *hep = CAPTURE_INPUT_HEP(input);
            return g_strdup_printf("%d", hep->url.port);
        }
    }

    return NULL;
}

static void
capture_input_hep_class_init(CaptureInputHepClass *klass)
{
    CaptureInputClass *input_class = CAPTURE_INPUT_CLASS(klass);
    input_class->start = capture_input_hep_start;
    input_class->stop = capture_input_hep_stop;
}

static void
capture_input_hep_init(CaptureInputHep *self)
{
    capture_input_set_tech(CAPTURE_INPUT(self), CAPTURE_TECH_HEP);
}

G_DEFINE_TYPE(CaptureOutputHep, capture_output_hep, CAPTURE_TYPE_OUTPUT)

CaptureOutput *
capture_output_hep(const gchar *url, GError **error)
{
    // Create a new structure to handle this capture sink
    CaptureOutputHep *hep = g_object_new(CAPTURE_TYPE_OUTPUT_HEP, NULL);

    // Fill configuration structure
    hep->version = setting_get_intvalue(SETTING_HEP_SEND_VER);
    hep->password = setting_get_value(SETTING_HEP_SEND_PASS);
    hep->id = (guint16) setting_get_intvalue(SETTING_HEP_SEND_ID);
    if (url != NULL) {
        if (!capture_hep_parse_url(url, &hep->url, error)) {
            return NULL;
        }
    } else {
        hep->url.proto = G_SOCKET_PROTOCOL_UDP;
        hep->url.host = setting_get_value(SETTING_HEP_SEND_ADDR);
        hep->url.port = setting_get_intvalue(SETTING_HEP_SEND_PORT);
    }

    // Check protocol version is support
    if (hep->version != 2 && hep->version != 3) {
        g_set_error(error,
                    CAPTURE_HEP_ERROR,
                    CAPTURE_HEP_ERROR_VERSION,
                    "HEP client: Unsupported protocol version %d",
                    hep->version);
        return NULL;
    }

    GSocketAddress *srv_addr = g_inet_socket_address_new_from_string(
        hep->url.host,
        hep->url.port
    );

    if (srv_addr == NULL) {
        g_set_error(error,
                    CAPTURE_HEP_ERROR,
                    CAPTURE_HEP_ERROR_URL_PARSE,
                    "HEP: failed parser HEP server address from %s:%d",
                    hep->url.host, hep->url.port);
        return NULL;
    }

    // Create a socket for a new TCP IPv4 connection
    hep->socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM, G_SOCKET_PROTOCOL_UDP, error);
    if (hep->socket == NULL) {
        // Error MUST be set by socket function
        g_assert (error == NULL || *error != NULL);
        return NULL;

    }

    // Connect to HEP server
    if (!g_socket_connect(hep->socket, srv_addr, FALSE, error)) {
        // Error MUST be set by socket function
        g_assert (error == NULL || *error != NULL);
        return NULL;
    }

    g_autofree gchar *sink = g_strdup_printf("L:%d", hep->url.port);
    capture_output_set_sink(CAPTURE_OUTPUT(hep), sink);

    return CAPTURE_OUTPUT(hep);
}

void
capture_output_hep_write(CaptureOutput *output, Packet *packet)
{
    guint32 ip_len = 0, total_len = 0;
    CaptureHepChunkIp4 src_ip4, dst_ip4;
#ifdef USE_IPV6
    CaptureHepChunkIp6 src_ip6, dst_ip6;
#endif
    CaptureHepChunk payload_chunk;
    CaptureHepChunk authkey_chunk;

    // Get first frame information (for timestamps)
    PacketFrame *frame = g_list_nth_data(packet->frames, 0);

    // Packet IP Data
    PacketIpData *ip = packet_ip_data(packet);
    g_return_if_fail(ip != NULL);

    // Packet UDP Data
    PacketUdpData *udp = g_ptr_array_index(packet->proto, PACKET_UDP);
    g_return_if_fail(udp != NULL);

    // Packet SIP Data
    PacketSipData *sip = g_ptr_array_index(packet->proto, PACKET_SIP);
    g_return_if_fail(sip != NULL);

    // Get HEP output data
    CaptureOutputHep *hep = CAPTURE_OUTPUT_HEP(output);

    // Data to send on the wire
    g_autoptr(GByteArray) data = g_byte_array_sized_new(total_len);

    // Set "HEP3" banner header
    g_autofree CaptureHepGeneric *hg = g_malloc0(sizeof(CaptureHepGeneric));
    memcpy(hg->header.id, "\x48\x45\x50\x33", 4);

    // IP dissectors
    hg->ip_family.chunk.vendor_id = g_htons(0x0000);
    hg->ip_family.chunk.type_id = g_htons(0x0001);
    hg->ip_family.chunk.length = g_htons(sizeof(hg->ip_family));
    hg->ip_family.data = (guint8) (ip->version == 4 ? AF_INET : AF_INET6);

    // Proto ID
    hg->ip_proto.chunk.vendor_id = g_htons(0x0000);
    hg->ip_proto.chunk.type_id = g_htons(0x0002);
    hg->ip_proto.chunk.length = g_htons(sizeof(hg->ip_proto));
    hg->ip_proto.data = (guint8) ip->protocol;

    // IPv4
    if (ip->version == 4) {
        src_ip4.chunk.vendor_id = g_htons(0x0000);
        src_ip4.chunk.type_id = g_htons(0x0003);
        src_ip4.chunk.length = g_htons(sizeof(src_ip4));
        inet_pton(AF_INET, ip->srcip, &src_ip4.data);

        dst_ip4.chunk.vendor_id = g_htons(0x0000);
        dst_ip4.chunk.type_id = g_htons(0x0004);
        dst_ip4.chunk.length = g_htons(sizeof(dst_ip4));
        inet_pton(AF_INET, ip->dstip, &dst_ip4.data);

        ip_len = sizeof(dst_ip4) + sizeof(src_ip4);
    }

#ifdef USE_IPV6
        // IPv6
    else if (ip->version == 6) {
        src_ip6.chunk.vendor_id = g_htons(0x0000);
        src_ip6.chunk.type_id = g_htons(0x0005);
        src_ip6.chunk.length = g_htons(sizeof(src_ip6));
        inet_pton(AF_INET6, ip->srcip, &src_ip6.data);

        dst_ip6.chunk.vendor_id = g_htons(0x0000);
        dst_ip6.chunk.type_id = g_htons(0x0006);
        dst_ip6.chunk.length = g_htons(sizeof(dst_ip6));
        inet_pton(AF_INET6, ip->dstip, &dst_ip6.data);

        ip_len = sizeof(dst_ip6) + sizeof(src_ip6);
    }
#endif

    // Source Port
    hg->src_port.chunk.vendor_id = g_htons(0x0000);
    hg->src_port.chunk.type_id = g_htons(0x0007);
    hg->src_port.chunk.length = g_htons(sizeof(hg->src_port));
    hg->src_port.data = g_htons(udp->sport);

    // Destination Port
    hg->dst_port.chunk.vendor_id = g_htons(0x0000);
    hg->dst_port.chunk.type_id = g_htons(0x0008);
    hg->dst_port.chunk.length = g_htons(sizeof(hg->dst_port));
    hg->dst_port.data = g_htons(udp->dport);

    // Timestamp secs
    hg->time_sec.chunk.vendor_id = g_htons(0x0000);
    hg->time_sec.chunk.type_id = g_htons(0x0009);
    hg->time_sec.chunk.length = g_htons(sizeof(hg->time_sec));
    hg->time_sec.data = g_htonl(g_date_time_to_unix(frame->ts));

    // Timestamp usecs
    hg->time_usec.chunk.vendor_id = g_htons(0x0000);
    hg->time_usec.chunk.type_id = g_htons(0x000a);
    hg->time_usec.chunk.length = g_htons(sizeof(hg->time_usec));
    hg->time_usec.data = g_htonl(g_date_time_get_microsecond(frame->ts));

    // Protocol type
    hg->proto_t.chunk.vendor_id = g_htons(0x0000);
    hg->proto_t.chunk.type_id = g_htons(0x000b);
    hg->proto_t.chunk.length = g_htons(sizeof(hg->proto_t));
    hg->proto_t.data = 1;

    // Capture Id
    hg->capt_id.chunk.vendor_id = g_htons(0x0000);
    hg->capt_id.chunk.type_id = g_htons(0x000c);
    hg->capt_id.chunk.length = g_htons(sizeof(hg->capt_id));
    hg->capt_id.data = g_htons(hep->id);

    // Payload
    payload_chunk.vendor_id = g_htons(0x0000);
    payload_chunk.type_id = g_htons(0x000f);
    payload_chunk.length = g_htons(sizeof(payload_chunk) + strlen(sip->payload));

    total_len = sizeof(CaptureHepGeneric) + strlen(sip->payload) + ip_len + sizeof(CaptureHepChunk);

    // Authorization key
    if (hep->password != NULL) {
        total_len += sizeof(CaptureHepChunk);
        authkey_chunk.vendor_id = g_htons(0x0000);
        authkey_chunk.type_id = g_htons(0x000e);
        authkey_chunk.length = g_htons(sizeof(authkey_chunk) + strlen(hep->password));
        total_len += strlen(hep->password);
    }

    // Total packet length
    hg->header.length = g_htons(total_len);
    g_byte_array_append(data, (gpointer) hg, sizeof(CaptureHepGeneric));

    // IPv4
    if (ip->version == 4) {
        g_byte_array_append(data, (gpointer) &src_ip4, sizeof(CaptureHepChunkIp4));
        g_byte_array_append(data, (gpointer) &dst_ip4, sizeof(CaptureHepChunkIp4));
    }

#ifdef USE_IPV6
        // IPv6
    else if (ip->version == 6) {
        g_byte_array_append(data, (gpointer) &src_ip6, sizeof(CaptureHepChunkIp6));
        g_byte_array_append(data, (gpointer) &dst_ip6, sizeof(CaptureHepChunkIp6));
    }
#endif

    // Authorization key chunk
    if (hep->password != NULL) {
        g_byte_array_append(data, (gpointer) &authkey_chunk, sizeof(CaptureHepChunk));
        g_byte_array_append(data, (gpointer) hep->password, (guint) strlen(hep->password));
    }

    // SIP Payload
    g_byte_array_append(data, (gpointer) &payload_chunk, sizeof(CaptureHepChunk));
    g_byte_array_append(data, (gpointer) sip->payload, (guint) strlen(sip->payload));

    // Send payload to HEPv3 Server
    if (g_socket_send(hep->socket, (const gchar *)data->data, data->len, FALSE, NULL) == -1) {
        return;
    }
}

void
capture_output_hep_close(CaptureOutput *output)
{
    CaptureOutputHep *hep = CAPTURE_OUTPUT_HEP(output);
    g_socket_close(hep->socket, NULL);
    g_clear_object(&hep->socket);
}

const gchar *
capture_output_hep_port(CaptureManager *manager)
{
    for (GSList *l = manager->outputs; l != NULL; l = l->next) {
        CaptureOutput *output = l->data;
        if (capture_output_tech(output) == CAPTURE_TECH_HEP) {
            CaptureOutputHep *hep = CAPTURE_OUTPUT_HEP(output);
            return g_strdup_printf("%d", hep->url.port);
        }
    }

    return NULL;
}

static void
capture_output_hep_class_init(CaptureOutputHepClass *klass)
{
    CaptureOutputClass *output_class = CAPTURE_OUTPUT_CLASS(klass);
    output_class->write = capture_output_hep_write;
    output_class->close = capture_output_hep_close;
}

static void
capture_output_hep_init(CaptureOutputHep *self)
{
    capture_output_set_tech(CAPTURE_OUTPUT(self), CAPTURE_TECH_HEP);
}
