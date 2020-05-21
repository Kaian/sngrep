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
 * @file sip.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage SIP calls and messages
 *
 * This file contains the functions and structures to manage the SIP calls and
 * messages.
 */

#ifndef __SNGREP_SIP_H
#define __SNGREP_SIP_H

#include "config.h"
#include <stdbool.h>
#include <regex.h>
#ifdef WITH_PCRE
#include <pcre.h>
#endif
#include "sip_call.h"
#include "vector.h"
#include "hash.h"

#define MAX_SIP_PAYLOAD 10240

//! Shorter declaration of sip_call_list structure
typedef struct sip_call_list sip_call_list_t;
//! Shorter declaration of sip codes structure
typedef struct sip_code sip_code_t;
//! Shorter declaration of sip stats
typedef struct sip_stats sip_stats_t;
//! Shorter declaration of sip sort
typedef struct sip_sort sip_sort_t;

//! SIP Methods
enum sip_methods {
    SIP_METHOD_REGISTER = 1,
    SIP_METHOD_INVITE,
    SIP_METHOD_SUBSCRIBE,
    SIP_METHOD_NOTIFY,
    SIP_METHOD_OPTIONS,
    SIP_METHOD_PUBLISH,
    SIP_METHOD_INFO,
    SIP_METHOD_REFER,
    SIP_METHOD_UPDATE,
    SIP_METHOD_KDMQ,
    SIP_METHOD_MESSAGE,
    SIP_METHOD_CANCEL,
    SIP_METHOD_BYE,
    SIP_METHOD_ACK,
    SIP_METHOD_PRACK,
};

//! Return values for sip_validate_packet
enum validate_result {
    VALIDATE_NOT_SIP        = -1,
    VALIDATE_PARTIAL_SIP    = 0,
    VALIDATE_COMPLETE_SIP   = 1,
    VALIDATE_MULTIPLE_SIP   = 2
};

/**
 * @brief Different Request/Response codes in SIP Protocol
 */
struct sip_code
{
    int id;
    const char *text;
};

/**
 * @brief Structure to store dialog stats
 */
struct sip_stats
{
    //! Total number of captured dialogs
    int total;
    //! Total number of displayed dialogs after filtering
    int displayed;
};

/**
 * @brief Sorting information for the sip list
 */
struct sip_sort
{
    //! Sort call list by this attribute
    enum sip_attr_id by;
    //! Sory by attribute ascending
    bool asc;
};

/**
 * @brief call structures head list
 *
 * This structure acts as header of calls list
 */
struct sip_call_list {
    //! List of all captured calls
    vector_t *list;
    //! List of active captured calls
    vector_t *active;
    //! Changed flag. For interface optimal updates
    bool changed;
    //! Sort call list following this options
    sip_sort_t sort;
    //! Last created id
    int last_index;
    //! Call-Ids hash table
    htable_t *callids;

    // Max call limit
    int limit;
    //! Only store dialogs starting with INVITE
    int only_calls;
    //! Only store dialogs starting with some Methods
    int ignore_incomplete;
    //! match expression text
    const char *match_expr;
#ifdef WITH_PCRE
    //! Compiled match expression
    pcre *match_regex;
#else
    //! Compiled match expression
    regex_t match_regex;
#endif
    //! Invert match expression result
    int match_invert;

    //! Regexp for payload matching
    regex_t reg_method;
    regex_t reg_callid;
    regex_t reg_xcallid;
    regex_t reg_response;
    regex_t reg_cseq;
    regex_t reg_from;
    regex_t reg_to;
    regex_t reg_valid;
    regex_t reg_cl;
    regex_t reg_body;
    regex_t reg_reason;
    regex_t reg_warning;
};

/**
 * @brief Initialize SIP Storage structures
 *
 * @param limit Max number of Stored calls
 * @param only_calls only parse dialogs starting with INVITE
 * @param no_incomplete only parse dialog starting with some methods
 */
void
sip_init(int limit, int only_calls, int no_incomplete);

/**
 * @brief Deallocate all memory used for SIP calls
 */
void
sip_deinit();

/**
 * @brief Parses Call-ID header of a SIP message payload
 *
 * Mainly used to check if a payload contains a callid.
 *
 * @param payload SIP message payload
 * @param callid Character array to store callid
 * @return callid parsed from Call-ID header
 */
char *
sip_get_callid(const char* payload, char *callid);

/**
 * @brief Parses X-Call-ID header of a SIP message payload
 *
 * Mainly used to check if a payload contains a xcallid.
 *
 * @param payload SIP message payload
 * @paramx callid Character array to store callid
 * @return xcallid parsed from Call-ID header
 */
char *
sip_get_xcallid(const char* payload, char *xcallid);

/**
 * @brief Validate the packet payload is a SIP message
 *
 * This function will validate the payload of a packet to determine if it
 * contains a full SIP packet. In order to be valid, the SIP packet must
 * have a initial line with Request or Respones, a Content-Length header
 * field and a body matching the length of that header.
 *
 * This function will only be used for TCP captured packets, when the
 * Content-Length header field is a MUST.
 *
 * @param packet TCP assembled packet structure
 * @return -1 if the packet first line doesn't match a SIP message
 * @return 0 if the packet contains SIP but is not yet complete
 * @return 1 if the packet is a complete SIP message
 */
int
sip_validate_packet(packet_t *packet);

/**
 * @brief Loads a new message from raw header/payload
 *
 * Use this function to convert raw data into call and message
 * structures. This is mainly used to load data from a file or
 *
 * @param packet Packet structure pointer
 * @return a SIP msg structure pointer
 */
sip_msg_t *
sip_check_packet(packet_t *packet);

/**
 * @brief Return if the call list has changed
 *
 * Check if the call list has changed since the last time
 * this function was invoked. We consider list has changed when a new
 * call has been added or removed.
 *
 * @return true if list has changed, false otherwise
 */
bool
sip_calls_has_changed();

/**
 * @brief Getter for calls linked list size
 *
 * @return how many calls are linked in the list
 */
int
sip_calls_count();

/**
 * @brief Return an iterator of call list
 */
vector_iter_t
sip_calls_iterator();

/**
 * @brief Return an iterator of call list
 *
 * We consider 'active' calls those that are willing to have
 * an rtp stream that will receive new packets.
 *
 */
vector_iter_t
sip_active_calls_iterator();

/**
 * @brief Return if a call is in active's call vector
 *
 * @param call Call to be searched
 * @return TRUE if call is active, FALSE otherwise
 */
bool
sip_call_is_active(sip_call_t *call);

/**
 * @brief Return the call list
 */
vector_t *
sip_calls_vector();

/**
 * @brief Return the active call list
 */
vector_t *
sip_active_calls_vector();

/**
 * @brief Return stats from call list
 *
 * @param total Total calls processed
 * @param displayed number of calls matching filters
 */
sip_stats_t
sip_calls_stats();


/**
 * @brief Find a call structure in calls linked list given a call index
 *
 * @param index Position of the call in the calls vector
 * @return pointer to the sip_call structure found or NULL
 */
sip_call_t *
sip_find_by_index(int index);

/**
 * @brief Find a call structure in calls linked list given an callid
 *
 * @param callid Call-ID Header value
 * @return pointer to the sip_call structure found or NULL
 */
sip_call_t *
sip_find_by_callid(const char *callid);


/**
 * @brief Parse extra fields only for dialogs strarting with invite
 *
 * @note This function assumes the msg is already part of a call
 *
 * @param msg SIP message structure
 * @param payload SIP message payload
 */
void
sip_parse_extra_headers(sip_msg_t *msg, const u_char *payload);

/**
 * @brief Remove al calls
 *
 * This funtion will clear the call list invoking the destroy
 * function for each one.
 */
void
sip_calls_clear();

/**
 * @brief Remove al calls
 *
 * This funtion will clear the call list of calls other than ones
 * fitting the current filter
 */
void
sip_calls_clear_soft();

/**
 * @brief Remove first call in the call list
 *
 * This function removes the first call in the calls vector avoiding
 * reaching the capture limit.
 */
void
sip_calls_rotate();

/**
 * @brief Get message Request/Response code
 *
 * Parse Payload to get Message Request/Response code.
 *
 * @param msg SIP Message to be parsed
 * @return numeric representation of Request/ResponseCode
 */
int
sip_get_msg_reqresp(sip_msg_t *msg, const u_char *payload);

/**
 * @brief Get full Response code (including text)
 *
 *
 */
const char *
sip_get_msg_reqresp_str(sip_msg_t *msg);

/**
 * @brief Parse SIP Message payload if not parsed
 *
 * This function can be used for delayed parsing. This way
 * the message will only use the minimun required memory
 * to store basic information.
 *
 * @param msg SIP message structure
 * @return parsed message
 */
sip_msg_t *
sip_parse_msg(sip_msg_t *msg);

/**
 * @brief Parse SIP Message payload to fill sip_msg structe
 *
 * Parse the payload content to set message attributes.
 *
 * @param msg SIP message structure
 * @param payload SIP message payload
 * @return 0 in all cases
 */
int
sip_parse_msg_payload(sip_msg_t *msg, const u_char *payload);

/**
 * @brief Parse SIP Message payload for SDP media streams
 *
 * Parse the payload content to get SDP information
 *
 * @param msg SIP message structure
 * @return 0 in all cases
 */
void
sip_parse_msg_media(sip_msg_t *msg, const u_char *payload);

/**
 * @brief Set Capture Matching expression
 *
 * @param expr String containing matching expression
 * @param insensitive 1 for case insensitive matching
 * @param invert 1 for reverse matching
 * @return 0 if expresion is valid, 1 otherwise
 */
int
sip_set_match_expression(const char *expr, int insensitive, int invert);

/**
 * @brief Get Capture Matching expression
 *
 * @return String containing matching expression
 */
const char *
sip_get_match_expression();

/**
 * @brief Checks if a given payload matches expression
 *
 * @param payload Packet payload
 * @return 1 if matches, 0 otherwise
 */
int
sip_check_match_expression(const char *payload);

/**
 * @brief Get String value for a Method
 *
 * @param method One of the methods defined in @sip_codes
 * @return a string representing the method text
 */
const char *
sip_method_str(int method);

/*
 * @brief Get String value of Transport
 */
const char *
sip_transport_str(int transport);

/**
 * @brief Converts Request Name or Response code to number
 *
 * If the argument is a method, the corresponding value of @sip_methods
 * will be returned. If a Resposne code, the numeric value of the code
 * will be returned.
 *
 * @param a string representing the Request/Resposne code text
 * @return numeric representation of Request/Response code
 */
int
sip_method_from_str(const char *method);

/**
 * @brief Get summary of message header data
 *
 * For raw prints, it's handy to have the ngrep header style message
 * data.
 *
 * @param msg SIP message
 * @param out pointer to allocated memory to contain the header output
 * @returns pointer to out
 */
char *
sip_get_msg_header(sip_msg_t *msg, char *out);

void
sip_set_sort_options(sip_sort_t sort);

sip_sort_t
sip_sort_options();

void
sip_sort_list();

void
sip_list_sorter(vector_t *vector, void *item);

#endif
