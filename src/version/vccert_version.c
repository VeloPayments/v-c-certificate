/**
 * \file version/vccert_version.c
 *
 * Return the version string for the vccert library.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <vccert/version.h>

/**
 * \brief Return the version string for the vccert library.
 *
 * \returns a const version string for this library.
 */
const char* vccert_version()
{
    return VCCERT_VERSION;
}
