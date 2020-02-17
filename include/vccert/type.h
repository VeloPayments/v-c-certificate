/**
 * \file type.h
 *
 * \brief This header defines the types of fields in a certificate
 *
 * \copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCCERT_TYPE_HEADER_GUARD
#define VCCERT_TYPE_HEADER_GUARD

#include <vccert/type.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

typedef enum vccert_field_types
{
    VCCERT_FIELD_TYPE_STRING,
    VCCERT_FIELD_TYPE_INT8,
    VCCERT_FIELD_TYPE_INT16,
    VCCERT_FIELD_TYPE_INT32,
    VCCERT_FIELD_TYPE_INT64,
    VCCERT_FIELD_TYPE_APN,
    VCCERT_FIELD_TYPE_UUID,
    VCCERT_FIELD_TYPE_DATE,
    VCCERT_FIELD_TYPE_BOOL
} vccert_field_types_t;

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif  //__cplusplus

#endif  //VCCERT_FIELD_MAPPING_HEADER_GUARD
