/*******************************************************************************
 * Copyright (c) 2020, Sensors and IoT Capability Centre (SIOT) at GovTech.
 *
 * Contributor(s):
 *    Lau Lee Hong  lau_lee_hong@tech.gov.sg
 *******************************************************************************/
#ifndef CRYPTO_ENGINE_V2_H
#define CRYPTO_ENGINE_V2_H

#include <string>
#include "mbed.h"

/** CryptoEngineV2 class.
 *  @brief      Handles X509 Exchange-related cryptographic processes.
 *  @details    Use this object as a base-class to build your cloud client.
 *
 *  Example:
 *  @code{.cpp}
 *  #include "mbed.h"
 *  #include "crypto_engine_v2.h"
 *
 *  int main() 
 *  {
 *      CryptoEngineV2 crypto;
 *      int success = crypto.GenerateRSAKeypair();
 *      printf("\r\nRSA Keypair Generation Code: %d\r\n", success);
 *  }
 *  @endcode
 */
        
typedef struct {
    std::string country_name;
    std::string state_name;
    std::string org_name;
} ssl_ca_params;

class CryptoEngineV2 
{
    public:
        int GenerateRSAKeypair(void);
        std::string GenerateCertificateSigningRequest(std::string timestamp);
        std::string CertificateAuthorityPEMFormatter(std::string s);
        bool X509IssuerInfo (char* buf, size_t size, const mbedtls_x509_crt* crt);
        bool X509CertificateAuthorityDecoder (std::string ssl_ca, ssl_ca_params& ca_params);
        std::string SignatureGenerator(std::string params);
        std::string GenericSHA256Generator(std::string input);
        std::string GenericSHA1Generator(std::string input);
};

 #endif  // CRYPTO_ENGINE_V2_H