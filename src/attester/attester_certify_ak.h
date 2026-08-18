/**
 * @file attester_certify_ak.h
 * @brief /certify_ak_of_attester -- RP-mediated AK provisioning.
 */

#ifndef CHARRA_ATTESTER_CERTIFY_AK_H
#define CHARRA_ATTESTER_CERTIFY_AK_H

#include <coap3/coap.h>

void coap_certify_ak_of_attester_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

#endif /* CHARRA_ATTESTER_CERTIFY_AK_H */
