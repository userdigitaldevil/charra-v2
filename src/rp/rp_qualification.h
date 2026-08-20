/**
 * @file rp_qualification.h
 * @brief RP's side of the /qualify + /qualify/submit handshake.
 *
 * The Verifier checks that the RP still runs the correct PATH_Clean SDK by
 * sending a synthetic log and comparing the redacted result against its
 * own. This module answers that challenge, once, against a single
 * Verifier.
 *
 * One handshake is enough for all of them: the Verifier that ran it writes
 * the verdict into a file every Verifier reads (verifier_qualified_rps.h).
 * Nothing expires -- the RP stays qualified until that line is removed.
 */

#ifndef CHARRA_RP_QUALIFICATION_CLIENT_H
#define CHARRA_RP_QUALIFICATION_CLIENT_H

#include "../common/charra_error.h"

/**
 * @brief Run the handshake once, or short-circuit if this process has
 * already qualified.
 *
 * @param[in] num_verifiers how many entries of verifiers[] to try. The
 * first one reachable for /qualify is used and its verdict is taken as
 * final -- every Verifier runs the same check, so a second opinion would
 * be the same opinion. That one Verifier records the result in the list
 * all of them read, so the RP never has to repeat this per Verifier.
 */
CHARRA_RC rp_perform_qualification_handshake_once(int num_verifiers);

#endif /* CHARRA_RP_QUALIFICATION_CLIENT_H */
