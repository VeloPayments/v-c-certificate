/**
 * \file test_vccert_version.cpp
 *
 * Unit tests for vccert_version.
 *
 * \copyright 2021-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <minunit/minunit.h>
#include <string.h>
#include <vccert/version.h>

TEST_SUITE(vccert_version_test);

TEST(verify_version_information_set)
{
    const char* version = vccert_version();

    TEST_ASSERT(nullptr != version);
    TEST_EXPECT(!strcmp(VCCERT_VERSION, version));
}
