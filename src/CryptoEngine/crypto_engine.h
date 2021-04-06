#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <string>
#include "mbed.h"
#include "mbedtls/pk_internal.h"
#include "secure_element.h"

class CryptoEngine
{
    public:
#if defined(MBED_CONF_APP_USE_SECURE_ELEMENT) && (MBED_CONF_APP_USE_SECURE_ELEMENT == 1)    
        CryptoEngine(SecureElement* se);
#else
        CryptoEngine(void);
#endif  // MBED_CONF_APP_USE_SECURE_ELEMENT
        ~CryptoEngine(void);

        std::string GenerateCertificateSigningRequest(void);
        std::string GetCertificateSubjectName(void);
        bool X509IssuerInfo (char* buf, size_t size, const mbedtls_x509_crt* crt);

        static std::string GenericSHA256Generator(std::string input);
    
    protected:
        mbedtls_pk_context pk_ctx_;
        std::string csr_;

    private:
        bool GenerateKeypair(void);

#if defined(MBED_CONF_APP_USE_SECURE_ELEMENT) && (MBED_CONF_APP_USE_SECURE_ELEMENT == 1)
        SecureElement* secureElement_;
        mbedtls_pk_info_t pk_info_;
#endif  // MBED_CONF_APP_USE_SECURE_ELEMENT

        mbedtls_ecp_keypair ecp_keypair_;
        mbedtls_entropy_context entropy_ctx_;
        mbedtls_ctr_drbg_context ctrdrbg_ctx_;
};

#endif  // CRYPTO_ENGINE_H