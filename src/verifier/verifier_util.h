/**
 * @file verifier_util.h
 * @brief Small helpers shared by the Verifier's CoAP resource handlers.
 */

#ifndef CHARRA_VERIFIER_UTIL_H
#define CHARRA_VERIFIER_UTIL_H

#include <coap3/coap.h>

/** @brief coap_add_data_large_response() release callback: frees the
 * marshaled response buffer once libcoap has finished sending it. */
void release_response_data(
        struct coap_session_t* session, void* app_ptr);

#endif /* CHARRA_VERIFIER_UTIL_H */
