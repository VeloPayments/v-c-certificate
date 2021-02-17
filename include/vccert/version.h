/**
 * \file vccert/version.h
 *
 * \brief Return the version string for the vccert library.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#ifndef  VCCERT_VERSION_HEADER_GUARD
# define VCCERT_VERSION_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef   __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Return the version string for the vccert library.
 *
 * \returns a const version string for this library.
 */
const char* vccert_version();

/* make this header C++ friendly. */
#ifdef   __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCCERT_VERSION_HEADER_GUARD*/
