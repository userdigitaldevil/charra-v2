/**
 * @file verifier_qualify.h
 * @brief /qualify + /qualify_submit -- Step 2's privacy-cleansing check.
 */

#ifndef CHARRA_VERIFIER_QUALIFY_H
#define CHARRA_VERIFIER_QUALIFY_H

#include <coap3/coap.h>

/** @brief Issues a synthetic event log for the RP to run its PATH_Clean
 * SDK over, keeping the expected redacted result in memory. */
void coap_qualify_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

/** @brief Compares the RP's redaction against the expected result and, on
 * a match, remembers this RP for the rest of this process's lifetime so
 * later /appraise calls can check qualification without repeating the
 * handshake. */
void coap_qualify_submit_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

#endif /* CHARRA_VERIFIER_QUALIFY_H */
