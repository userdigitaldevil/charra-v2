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

#include <time.h>

#include "../common/charra_error.h"

/**
 * @brief Run the handshake once, or short-circuit if the cached grant is
 * still valid.
 *
 * @param[in] num_verifiers how many entries of verifiers[] to try; the
 * first reachable one is used, since the Verifier-side ledger is shared.
 * @param[in] refresh_margin_seconds treat a grant expiring within this many
 * seconds as needing renewal. 0 means "only if actually expired", which is
 * what the attestation path wants; daemon mode passes a margin from its
 * idle window so a renewal never lands inside an attestation.
 */
CHARRA_RC rp_perform_qualification_handshake_once(
        int num_verifiers, time_t refresh_margin_seconds);


#endif /* CHARRA_RP_QUALIFICATION_CLIENT_H */
