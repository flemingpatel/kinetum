// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file test_tls.cpp
 * @brief TLS credential-input admission tests.
 * @author Fleming Patel
 */

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "src/common/tls.hpp"

namespace kinetum::common
{
namespace
{

/** @brief Own one isolated directory containing deliberately empty PEM files. */
class TlsMaterialTest : public ::testing::Test {
    protected:
	/** @brief Create an isolated material directory with empty CA, certificate, and key inputs. */
	void SetUp() override
	{
		std::string pattern = (std::filesystem::temp_directory_path() / "kinetum_tls_material.XXXXXX").string();
		char *created = ::mkdtemp(pattern.data());
		ASSERT_NE(created, nullptr);
		root_ = created;
		for (const char *name : {"ca.pem", "cert.pem", "key.pem"}) {
			std::ofstream file(root_ / name, std::ios::binary | std::ios::trunc);
			ASSERT_TRUE(file.good());
		}
	}

	/** @brief Remove only this fixture's owned material directory. */
	void TearDown() override
	{
		if (!root_.empty()) {
			std::error_code error;
			std::filesystem::remove_all(root_, error);
		}
	}

	std::filesystem::path root_;  ///< Isolated test material root.
};

/** @brief Reject every configured empty PEM before creating TLS credentials. */
TEST_F(TlsMaterialTest, configured_empty_material_is_rejected)
{
	tls_server_config server;
	server.cert_pem_path = (root_ / "cert.pem").string();
	server.key_pem_path = (root_ / "key.pem").string();
	EXPECT_EQ(make_server_credentials(server), nullptr);

	tls_client_config root_only;
	root_only.ca_pem_path = (root_ / "ca.pem").string();
	EXPECT_EQ(make_channel_credentials(root_only), nullptr);

	tls_client_config mutual;
	mutual.cert_pem_path = (root_ / "cert.pem").string();
	mutual.key_pem_path = (root_ / "key.pem").string();
	EXPECT_EQ(make_channel_credentials(mutual), nullptr);
}

}  // namespace
}  // namespace kinetum::common
