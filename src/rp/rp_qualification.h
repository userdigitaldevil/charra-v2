/**
 * @file rp_qualification.h
 * @brief RP's side of the /qualify + /qualify/submit handshake.
 *
 * The Verifier periodically checks that the RP still runs the correct
 * PATH_Clean SDK by sending a synthetic log and comparing the redacted
 * result against its own. This module answers that challenge and caches the
 * grant so the handshake runs at most once per validity window.
 */

#ifndef CHARRA_RP_QUALIFICATION_CLIENT_H
#define CHARRA_RP_QUALIFICATION_CLIENT_H

#include "../common/charra_error.h"

/**
 * @brief Run the handshake once, or short-circuit if the cached grant is
 * still valid.
 *
 * Re-qualifies only once the grant has genuinely expired -- there is no
 * renewal margin, so this can land inside an attestation cycle.
 *
 * @param[in] num_verifiers how many entries of verifiers[] to try; the
 * first reachable one is used, since the Verifier-side ledger is shared.
 */
CHARRA_RC rp_perform_qualification_handshake_once(int num_verifiers);


#endif /* CHARRA_RP_QUALIFICATION_CLIENT_H */
