/**
 * @file attester_result.h
 * @brief /attest_result -- RP's Step 2a verdict on this Attester's evidence.
 */

#ifndef CHARRA_ATTESTER_RESULT_H
#define CHARRA_ATTESTER_RESULT_H

#include <coap3/coap.h>

/**
 * @brief /attest_result: RP's Step 2a verdict on evidence this Attester
 * produced. Advisory -- nothing here depends on it; it exists so a rejected
 * device can see that it was rejected instead of assuming success.
 */
void coap_attest_result_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

#endif /* CHARRA_ATTESTER_RESULT_H */
