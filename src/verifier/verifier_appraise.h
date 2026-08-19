/**
 * @file verifier_appraise.h
 * @brief /appraise -- the Verifier's Step 3a + 3b evidence appraisal.
 */

#ifndef CHARRA_VERIFIER_APPRAISE_H
#define CHARRA_VERIFIER_APPRAISE_H

#include <coap3/coap.h>

/**
 * @brief Appraises one evidence bundle and answers with the verdict.
 *
 * Runs Step 3a (the RP's own identity) before Step 3b (the Attester's
 * evidence proper), so evidence relayed by an unidentified RP is rejected
 * before it is ever examined.
 */
void coap_appraise_handler(struct coap_resource_t* resource,
        struct coap_session_t* session, const struct coap_pdu_t* request,
        const struct coap_string_t* query, struct coap_pdu_t* response);

#endif /* CHARRA_VERIFIER_APPRAISE_H */
