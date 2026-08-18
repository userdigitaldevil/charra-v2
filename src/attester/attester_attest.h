/**
 * @file attester_attest.h
 * @brief /attest -- produce Quote_a over the requested PCR selection.
 */

#ifndef CHARRA_ATTESTER_ATTEST_H
#define CHARRA_ATTESTER_ATTEST_H

#include <coap3/coap.h>

void coap_attest_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

#endif /* CHARRA_ATTESTER_ATTEST_H */
