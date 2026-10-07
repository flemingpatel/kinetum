// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file tls.hpp
 * @brief TLS/SSL utilities for gRPC servers and clients.
 * @author Fleming Patel
 *
 * Provides a thin wrapper around gRPC SSL credentials for configuring
 * secure communication. This module handles:
 * - Server-side TLS configuration with optional client authentication
 * - Client-side TLS configuration with optional mutual TLS (mTLS)
 * - Fixed strict prevalidation of every requested certificate
 *
 * This is intentionally a thin wrapper around gRPC SSL credentials. Certificate
 * issuance, rotation, revocation, and secret delivery remain deployment-system
 * responsibilities.
 *
 * Security Considerations:
 * - Select TLS explicitly whenever the deployment requires a protected channel
 * - Use mTLS when both peers require authenticated identities
 * - Protect private key files with appropriate permissions (0600)
 *
 * Thread-safety: All functions are thread-safe.
 *
 */

#include <memory>
#include <string>

#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>

namespace kinetum::common
{

/**
 * @brief Configuration for TLS-enabled gRPC server.
 *
 * All paths should be absolute filesystem paths to PEM-encoded files.
 * This helper is TLS-only. Callers that intentionally want plaintext must use
 * grpc::InsecureServerCredentials() directly. If cert/key material is missing
 * or empty, malformed, or unreadable, make_server_credentials() returns
 * nullptr.
 *
 * @warning Every TLS server requires both cert_pem_path and key_pem_path;
 *          require_client_auth additionally requires ca_pem_path.
 */
struct tls_server_config {
	/** Server certificate chain in PEM format, including intermediates. */
	std::string cert_pem_path;

	/**
	 * Path to the server's private key (PEM format).
	 * @warning This file should be readable only by the server process.
	 */
	std::string key_pem_path;

	/** Trusted CA certificates used to verify clients when mutual TLS is required. */
	std::string ca_pem_path;

	/** Whether clients must present a certificate signed by @ref ca_pem_path. */
	bool require_client_auth = false;
};

/**
 * @brief Configuration for TLS-enabled gRPC client.
 *
 * All paths should be absolute filesystem paths to PEM-encoded files.
 * This helper is TLS-only. Callers that intentionally want plaintext must use
 * grpc::InsecureChannelCredentials() directly. If all paths are empty,
 * make_channel_credentials() returns nullptr.
 * Every supplied certificate is prevalidated for validity time and minimum
 * key strength. Leaf certificates must not be self-signed; a supplied root CA
 * may be self-signed. Hostname verification belongs to the gRPC handshake.
 */
struct tls_client_config {
	/** Trusted server CA certificates, or empty to request gRPC system roots. */
	std::string ca_pem_path;

	/** Client certificate chain in PEM format for mutual TLS. */
	std::string cert_pem_path;

	/** Client private key in PEM format for mutual TLS. */
	std::string key_pem_path;
};

/**
 * @brief Create gRPC server credentials from TLS configuration.
 *
 * Reads certificate and key files and constructs SSL server credentials.
 * This function never falls back to plaintext. If TLS material is incomplete,
 * empty, malformed, or unreadable, it returns nullptr and the caller must fail
 * startup.
 *
 * @param cfg Server TLS configuration
 * @return Shared pointer to gRPC ServerCredentials.
 *         Returns nullptr if TLS cannot be configured.
 *
 * Example:
 * @code
 *   tls_server_config cfg;
 *   cfg.cert_pem_path = "/etc/kinetum/server.crt";
 *   cfg.key_pem_path = "/etc/kinetum/server.key";
 *   cfg.ca_pem_path = "/etc/kinetum/ca.crt";
 *   cfg.require_client_auth = true;  // Enable mTLS
 *
 *   auto creds = make_server_credentials(cfg);
 *   grpc::ServerBuilder builder;
 *   builder.AddListeningPort("0.0.0.0:50051", creds);
 * @endcode
 *
 * @see make_channel_credentials for client-side credentials
 */
std::shared_ptr<grpc::ServerCredentials> make_server_credentials(const tls_server_config &cfg);

/**
 * @brief Create gRPC channel credentials from TLS configuration.
 *
 * Reads certificate and key files and constructs SSL channel credentials.
 * This function never falls back to plaintext. If all paths are empty, or if
 * configured TLS material is incomplete, empty, malformed, or unreadable, it
 * returns nullptr.
 *
 * @param cfg Client TLS configuration
 * @return Shared pointer to gRPC ChannelCredentials.
 *         Returns nullptr if TLS cannot be configured or strict validation
 *         fails.
 *
 * Example:
 * @code
 *   tls_client_config cfg;
 *   cfg.ca_pem_path = "/etc/kinetum/ca.crt";
 *   cfg.cert_pem_path = "/etc/kinetum/client.crt";  // For mTLS
 *   cfg.key_pem_path = "/etc/kinetum/client.key";   // For mTLS
 *
 *   auto creds = make_channel_credentials(cfg);
 *   auto channel = grpc::CreateChannel("server:50051", creds);
 * @endcode
 *
 * @see make_server_credentials for server-side credentials
 */
std::shared_ptr<grpc::ChannelCredentials> make_channel_credentials(const tls_client_config &cfg);

}  // namespace kinetum::common
