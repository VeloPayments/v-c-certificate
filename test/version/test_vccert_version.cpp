/**
 * \file test_vccert_version.cpp
 *
 * Unit tests for vccert_version.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <gtest/gtest.h>
#include <vccert/version.h>

TEST(vccert_version_test, verify_version_information_set)
{
    const char* version = vccert_version();

    ASSERT_NE(nullptr, version);
    EXPECT_STREQ(VCCERT_VERSION, version);
}
