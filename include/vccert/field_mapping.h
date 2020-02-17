/**
 * \file field_mapping.h
 *
 * \brief This header defines a long -> short code mapping and its associated type
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_FIELD_MAPPING_HEADER_GUARD
#define VCCERT_FIELD_MAPPING_HEADER_GUARD

#include <vccert/type.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

typedef struct field_mapping
{
    uint8_t longcode[16];
    uint16_t shortcode;
    vccert_field_types_t type;
} field_mapping_t;

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_FIELD_MAPPING_HEADER_GUARD
