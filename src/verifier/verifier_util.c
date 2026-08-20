/**
 * @file verifier_util.c
 * @brief See verifier_util.h.
 */

#include "verifier_util.h"

#include "../common/charra_macro.h"

void release_response_data(
        struct coap_session_t* session CHARRA_UNUSED, void* app_ptr) {
    charra_free_and_null(app_ptr);
}
