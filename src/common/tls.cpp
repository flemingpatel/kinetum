// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file tls.cpp
 * @brief TLS/SSL utilities implementation.
 * @author Fleming Patel
 *
 * Implements TLS credential creation for gRPC using file-based certificate
 * loading. Credential construction fails closed when TLS material is missing,
 * partial, unreadable, or fails strict validation.
 *
 * Security Considerations:
 * - TLS helpers never fall back to insecure credentials
 * - Callers that intentionally run plaintext must choose grpc::Insecure*
 *   credentials outside this module
 * - Partial TLS material is rejected before channel/server construction
 *
 * Strict prevalidation always checks:
 * - Self-signed certificate detection and rejection
 * - Certificate expiry validation (notBefore, notAfter)
 * - Key size minimums (RSA 2048, EC 256)
 *
 * Root CA material may be self-signed. Hostname verification belongs to the
 * gRPC TLS handshake.
 */

#include "src/common/tls.hpp"

#include <limits>

#include "src/common/file_io.hpp"
#include "src/common/log.hpp"

// OpenSSL headers for certificate validation
#if KINETUM_TLS_HELPERS_ENABLED
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

namespace kinetum::common
{

namespace
{

#if KINETUM_TLS_HELPERS_ENABLED

/**
 * @brief RAII wrapper for OpenSSL X509 certificate.
 */
struct x509_deleter {
	/**
	 * @brief Release an OpenSSL X509 object.
	 *
	 * @param cert Certificate pointer returned by OpenSSL.
	 */
	void operator()(X509 *cert) const
	{
		X509_free(cert);
	}
};
/** Sole parsed-certificate ownership with matching OpenSSL reclamation. */
using x509_ptr = std::unique_ptr<X509, x509_deleter>;

/**
 * @brief RAII wrapper for OpenSSL BIO.
 */
struct bio_deleter {
	/**
	 * @brief Release an OpenSSL BIO object.
	 *
	 * @param bio BIO pointer returned by OpenSSL.
	 */
	void operator()(BIO *bio) const
	{
		BIO_free(bio);
	}
};
/** Sole OpenSSL I/O-buffer ownership used while decoding TLS material. */
using bio_ptr = std::unique_ptr<BIO, bio_deleter>;

/**
 * @brief Return whether a byte count can be passed to OpenSSL int-sized APIs.
 *
 * @param size Byte count to validate.
 * @return true when size is representable as int, false otherwise.
 */
bool fits_openssl_int_size(size_t size)
{
	return size <= static_cast<size_t>(std::numeric_limits<int>::max());
}

/**
 * @brief Parse PEM certificate string into X509 object.
 *
 * Rejects oversized input before calling OpenSSL APIs that accept byte counts
 * through int-sized parameters.
 *
 * @param pem_data PEM-encoded certificate bytes.
 * @return Parsed certificate on success, nullptr on parse or size failure.
 */
x509_ptr parse_certificate(const std::string &pem_data)
{
	if (!fits_openssl_int_size(pem_data.size())) {
		return nullptr;
	}
	bio_ptr bio(BIO_new_mem_buf(pem_data.data(), static_cast<int>(pem_data.size())));
	if (!bio)
		return nullptr;
	return x509_ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

/**
 * @brief Check if certificate is self-signed (issuer == subject).
 *
 * @param cert Certificate to inspect.
 * @return true when issuer and subject are identical, false otherwise.
 */
bool is_self_signed(X509 *cert)
{
	X509_NAME *subject = X509_get_subject_name(cert);
	X509_NAME *issuer = X509_get_issuer_name(cert);
	EVP_PKEY *public_key = X509_get0_pubkey(cert);
	return subject != nullptr && issuer != nullptr && public_key != nullptr &&
	       X509_NAME_cmp(subject, issuer) == 0 && X509_verify(cert, public_key) == 1;
}

/**
 * @brief Check if certificate is currently valid (not expired, not yet valid).
 *
 * @param cert Certificate to inspect.
 * @param[out] error_detail Optional reason string populated on failure.
 * @return true when the current wall clock is inside the certificate validity window.
 */
bool is_certificate_time_valid(X509 *cert, std::string *error_detail = nullptr)
{
	const ASN1_TIME *not_before = X509_get0_notBefore(cert);
	const ASN1_TIME *not_after = X509_get0_notAfter(cert);
	if (not_before == nullptr || not_after == nullptr) {
		if (error_detail != nullptr) {
			*error_detail = "certificate validity interval is absent";
		}
		return false;
	}

	int day = 0;
	int second = 0;

	if (ASN1_TIME_diff(&day, &second, nullptr, not_before) != 1) {
		if (error_detail != nullptr) {
			*error_detail = "certificate notBefore value is malformed";
		}
		return false;
	}
	if (day > 0 || second > 0) {
		if (error_detail != nullptr) {
			*error_detail = "certificate not yet valid (notBefore in future)";
		}
		return false;
	}

	if (ASN1_TIME_diff(&day, &second, nullptr, not_after) != 1) {
		if (error_detail != nullptr) {
			*error_detail = "certificate notAfter value is malformed";
		}
		return false;
	}
	if (day < 0 || (day == 0 && second < 0)) {
		if (error_detail != nullptr) {
			*error_detail = "certificate has expired";
		}
		return false;
	}

	return true;
}

/**
 * @brief Get the key size in bits from a certificate.
 *
 * @param cert Certificate to inspect.
 * @param[out] key_type OpenSSL EVP_PKEY base ID for the certificate public key.
 * @return Public key size in bits, or 0 when the certificate has no public key.
 */
int get_certificate_key_bits(X509 *cert, int *key_type)
{
	EVP_PKEY *pkey = X509_get0_pubkey(cert);
	if (!pkey)
		return 0;

	*key_type = EVP_PKEY_base_id(pkey);
	return EVP_PKEY_bits(pkey);
}

/** Minimum admitted RSA public-key width. */
constexpr int MIN_RSA_KEY_BITS = 2048;

/** Minimum admitted elliptic-curve public-key width. */
constexpr int MIN_EC_KEY_BITS = 256;

/**
 * @brief Strictly prevalidate one certificate before gRPC construction.
 *
 * @param pem_data PEM-encoded certificate bytes.
 * @param reject_self_signed Whether this certificate must be a non-root leaf.
 * @param[out] error_message Detailed failure reason.
 * @return true only for a parseable, time-valid certificate with an admitted
 *         public-key width and the required self-signing relation.
 */
bool validate_certificate(const std::string &pem_data, bool reject_self_signed, std::string *error_message)
{
	x509_ptr cert = parse_certificate(pem_data);
	if (!cert) {
		if (error_message != nullptr) {
			*error_message = "failed to parse certificate PEM data";
		}
		return false;
	}

	if (reject_self_signed && is_self_signed(cert.get())) {
		if (error_message != nullptr) {
			*error_message = "self-signed certificate rejected";
		}
		return false;
	}

	std::string expiry_error;
	if (!is_certificate_time_valid(cert.get(), &expiry_error)) {
		if (error_message != nullptr) {
			*error_message = expiry_error;
		}
		return false;
	}

	int key_type = 0;
	const int key_bits = get_certificate_key_bits(cert.get(), &key_type);
	if (key_bits <= 0) {
		if (error_message != nullptr) {
			*error_message = "certificate public-key size is unavailable";
		}
		return false;
	}
	if (key_type == EVP_PKEY_RSA && key_bits < MIN_RSA_KEY_BITS) {
		if (error_message != nullptr) {
			*error_message = "RSA key size " + std::to_string(key_bits) + " bits is below minimum " +
					 std::to_string(MIN_RSA_KEY_BITS);
		}
		return false;
	}
	if (key_type == EVP_PKEY_EC && key_bits < MIN_EC_KEY_BITS) {
		if (error_message != nullptr) {
			*error_message = "EC key size " + std::to_string(key_bits) + " bits is below minimum " +
					 std::to_string(MIN_EC_KEY_BITS);
		}
		return false;
	}
	if (key_type != EVP_PKEY_RSA && key_type != EVP_PKEY_EC && key_type != EVP_PKEY_ED25519 &&
	    key_type != EVP_PKEY_ED448) {
		if (error_message != nullptr) {
			*error_message = "certificate public-key algorithm is not admitted";
		}
		return false;
	}

	return true;
}

#else  // !KINETUM_TLS_HELPERS_ENABLED

/**
 * @brief Fail closed when strict certificate helpers are not compiled.
 *
 * @param pem_data Unused PEM certificate bytes.
 * @param reject_self_signed Unused certificate-role policy.
 * @param[out] error_message Detailed failure reason.
 * @return false because strict certificate prevalidation is unavailable.
 */
bool validate_certificate(const std::string &pem_data, bool reject_self_signed, std::string *error_message)
{
	(void)pem_data;
	(void)reject_self_signed;
	if (error_message != nullptr) {
		*error_message = "TLS certificate helpers are disabled for strict certificate pre-validation";
	}
	return false;
}

#endif	// KINETUM_TLS_HELPERS_ENABLED

}  // namespace

std::shared_ptr<grpc::ServerCredentials> make_server_credentials(const tls_server_config &cfg)
{
	if (cfg.cert_pem_path.empty() || cfg.key_pem_path.empty()) {
		KINETUM_LOG_ERROR("tls", "tls.server.missing_paths",
				  "TLS server credentials require both cert and key paths");
		return nullptr;
	}

	if (cfg.require_client_auth && cfg.ca_pem_path.empty()) {
		KINETUM_LOG_ERROR("tls", "tls.server.missing_ca", "mTLS server credentials require --tls-ca");
		return nullptr;
	}

	auto cert_or = read_file_to_string(cfg.cert_pem_path);
	auto key_or = read_file_to_string(cfg.key_pem_path);
	auto ca_or = cfg.ca_pem_path.empty() ? status_or<std::string>(std::string{}) :
					       read_file_to_string(cfg.ca_pem_path);

	if (!cert_or.is_ok() || !key_or.is_ok() || !ca_or.is_ok()) {
		// Build detailed error message for diagnostics
		std::string details;
		if (!cert_or.is_ok())
			details += "cert=" + cfg.cert_pem_path + " ";
		if (!key_or.is_ok())
			details += "key=" + cfg.key_pem_path + " ";
		if (!ca_or.is_ok())
			details += "ca=" + cfg.ca_pem_path;

		KINETUM_LOG_ERROR("tls", "tls.server.read_failed", "Failed to read TLS server material ({})", details);
		return nullptr;
	}
	if (cert_or.value().empty() || key_or.value().empty() || (!cfg.ca_pem_path.empty() && ca_or.value().empty())) {
		KINETUM_LOG_ERROR("tls", "tls.server.empty_material",
				  "TLS server material files must contain nonempty PEM data");
		return nullptr;
	}

	std::string validation_error;
	if (!validate_certificate(cert_or.value(), true, &validation_error)) {
		KINETUM_LOG_ERROR("tls", "tls.server.invalid_certificate",
				  "SECURITY: Server certificate pre-validation failed: {}", validation_error);
		return nullptr;
	}
	if (!ca_or.value().empty()) {
		if (!validate_certificate(ca_or.value(), false, &validation_error)) {
			KINETUM_LOG_ERROR("tls", "tls.server.invalid_ca",
					  "SECURITY: Server CA certificate pre-validation failed: {}",
					  validation_error);
			return nullptr;
		}
	}

	grpc::SslServerCredentialsOptions::PemKeyCertPair kp;
	kp.private_key = key_or.value();
	kp.cert_chain = cert_or.value();

	grpc::SslServerCredentialsOptions opts;
	opts.pem_key_cert_pairs.push_back(kp);
	opts.pem_root_certs = ca_or.value();
	opts.client_certificate_request = cfg.require_client_auth ?
						  GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY :
						  GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE;

	return grpc::SslServerCredentials(opts);
}

std::shared_ptr<grpc::ChannelCredentials> make_channel_credentials(const tls_client_config &cfg)
{
	if (cfg.ca_pem_path.empty() && cfg.cert_pem_path.empty() && cfg.key_pem_path.empty()) {
		KINETUM_LOG_ERROR("tls", "tls.client.missing_material",
				  "TLS channel credentials require at least one TLS material path");
		return nullptr;
	}

	if (cfg.cert_pem_path.empty() != cfg.key_pem_path.empty()) {
		KINETUM_LOG_ERROR("tls", "tls.client.missing_paths",
				  "mTLS client credentials require both cert and key paths");
		return nullptr;
	}

	grpc::SslCredentialsOptions opts;
	bool had_errors = false;
	std::string ca_pem_content;
	std::string cert_pem_content;
	std::string key_pem_content;

	// Read CA certificate
	if (!cfg.ca_pem_path.empty()) {
		auto ca_or = read_file_to_string(cfg.ca_pem_path);
		if (ca_or.is_ok()) {
			ca_pem_content = ca_or.value();
			opts.pem_root_certs = ca_pem_content;
		} else {
			KINETUM_LOG_ERROR("tls", "tls.client.ca_read_failed", "Failed to read CA cert: {}",
					  cfg.ca_pem_path);
			had_errors = true;
		}
	}

	// Read client certificate (for mTLS)
	if (!cfg.cert_pem_path.empty()) {
		auto cert_or = read_file_to_string(cfg.cert_pem_path);
		if (cert_or.is_ok()) {
			cert_pem_content = cert_or.value();
			opts.pem_cert_chain = cert_pem_content;
		} else {
			KINETUM_LOG_ERROR("tls", "tls.client.cert_read_failed", "Failed to read client cert: {}",
					  cfg.cert_pem_path);
			had_errors = true;
		}
	}

	// Read client private key (for mTLS)
	if (!cfg.key_pem_path.empty()) {
		auto key_or = read_file_to_string(cfg.key_pem_path);
		if (key_or.is_ok()) {
			key_pem_content = key_or.value();
			opts.pem_private_key = key_pem_content;
		} else {
			KINETUM_LOG_ERROR("tls", "tls.client.key_read_failed", "Failed to read client key: {}",
					  cfg.key_pem_path);
			had_errors = true;
		}
	}

	// Handle file read errors
	if (had_errors) {
		KINETUM_LOG_ERROR("tls", "tls.client.material_rejected",
				  "Client TLS file errors - refusing to create partial credentials");
		return nullptr;
	}
	if ((!cfg.ca_pem_path.empty() && ca_pem_content.empty()) ||
	    (!cfg.cert_pem_path.empty() && cert_pem_content.empty()) ||
	    (!cfg.key_pem_path.empty() && key_pem_content.empty())) {
		KINETUM_LOG_ERROR("tls", "tls.client.empty_material",
				  "Configured TLS client material files must contain nonempty PEM data");
		return nullptr;
	}

	std::string validation_error;
	if (!cfg.ca_pem_path.empty() && !validate_certificate(ca_pem_content, false, &validation_error)) {
		KINETUM_LOG_ERROR("tls", "tls.client.invalid_ca", "SECURITY: CA certificate pre-validation failed: {}",
				  validation_error);
		return nullptr;
	}
	if (!cfg.cert_pem_path.empty() && !validate_certificate(cert_pem_content, true, &validation_error)) {
		KINETUM_LOG_ERROR("tls", "tls.client.invalid_certificate",
				  "SECURITY: Client certificate pre-validation failed: {}", validation_error);
		return nullptr;
	}

	KINETUM_LOG_INFO("tls", "tls.client.validated",
			 "Certificate pre-validation passed (self-signed=reject, expiry=check, ca_self_signed=allow)");

	return grpc::SslCredentials(opts);
}

}  // namespace kinetum::common
