/**
 * @file rp_cert_cache.h
 * @brief Loading a certificate the RP cached on disk, and deciding whether
 * it is still usable.
 */

#ifndef CHARRA_RP_CERT_CACHE_H
#define CHARRA_RP_CERT_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/**
 * @brief Load a cached certificate and report whether it can be used as-is.
 *
 * Usable means: the file exists, parses as X.509, and is not yet inside the
 * renewal margin. Anything else -- missing, unreadable, malformed, expiring
 * -- is reported as unusable so the caller re-provisions, which is the only
 * correct response: every one of these caches is keyed on nothing but the
 * file existing, and no peer gives the RP a distinct signal for "the
 * certificate you sent is stale" (a Verifier just votes NO). Without acting
 * on expiry here, a lapsed certificate would be reloaded and re-sent every
 * cycle and rejected every cycle, with nothing ever replacing it -- a stuck
 * state only a manual delete could clear. Renewing slightly early also keeps
 * a renewal from landing mid-cycle.
 *
 * @param[in] cert_path file to load.
 * @param[in] description names the certificate in this function's log lines,
 * e.g. "AK certificate for this Verifier".
 * @param[out] der_out malloc'd copy of the certificate, set only when this
 * returns true; the caller owns it. NULL if the caller only wants the
 * verdict and not the bytes.
 * @param[out] der_len_out length of *der_out. Ignored when der_out is NULL.
 * @param[out] expires_at_out absolute expiry, set only when this returns
 * true. May be NULL.
 * @return true if the cached certificate is usable as it stands.
 */
bool rp_cert_cache_load(const char* cert_path, const char* description,
        uint8_t** der_out, uint32_t* der_len_out, time_t* expires_at_out);

#endif /* CHARRA_RP_CERT_CACHE_H */
