/**
 * \file delegate.h
 *
 * \brief Delegate interface for providing lookup functions.
 *
 * \copyright 2018 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_DELEGATE_HEADER_GUARD
#define VCCERT_DELEGATE_HEADER_GUARD

#include <stdlib.h>
#include <vccert/field_mapping.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


typedef int (*get_field_mappings_t)(const uint8_t* artifact_type, const uint8_t* transaction_type,
    long height, field_mapping_t* mappings, size_t* num_mappings);
typedef int (*release_mappings_t)(field_mapping_t* mappings);

typedef struct vccert_resolver_delegate
{
    get_field_mappings_t get_field_mappings;
    release_mappings_t release_mappings;
} vccert_resolver_delegate_t;


/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus


#endif
