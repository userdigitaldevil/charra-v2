/**
 * @file attester_util.c
 * @brief See attester_util.h.
 *
 * Shared by every handler that answers with a heap buffer.
 */



#include "attester_util.h"
#include "../common/charra_macro.h"

#define LOG_NAME "attester"

void attester_release_data(
        struct coap_session_t* session CHARRA_UNUSED, void* app_ptr) {
    charra_free_and_null(app_ptr);
}
