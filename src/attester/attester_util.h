/**
 * @file attester_util.h
 * @brief Small helpers shared by the Attester's CoAP handlers.
 */

#ifndef CHARRA_ATTESTER_UTIL_H
#define CHARRA_ATTESTER_UTIL_H

#include <coap3/coap.h>

/**
 * @brief libcoap release callback: frees the response buffer once the PDU
 * has been sent. Passed to coap_add_data_large_response() by every handler
 * that answers out of the heap.
 */
void attester_release_data(struct coap_session_t* session, void* app_ptr);

#endif /* CHARRA_ATTESTER_UTIL_H */
