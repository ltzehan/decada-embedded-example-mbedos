#ifndef SE_TRUSTX_H
#define SE_TRUSTX_H

#include "mbed.h"
#include "secure_element.h"

/** TrustX class.
 *  @brief  Derived class of SecureElement implementing the Optiga Trust X.
 *
 *  Example:
 *  @code{.cpp}
 *  #include "mbed.h"
 *  #include "se_trustx.h"
 *
 *  int main() 
 *  {
 *
 *      TrustX trustx;
 *      while (!trustx.ready())
 *      {
 *          ThisThread::sleep_for(100ms);
 *      }
 *  }
 *  @endcode
 */

class TrustX : public SecureElement
{
    public:
        TrustX();

        bool GenerateEccKeypair(mbedtls_ecp_keypair& keypair);
        mbedtls_pk_info_t GetConfiguredPkInfo(void);

        static int SignFuncWrap(void *ctx, mbedtls_md_type_t md_alg,
                                    const unsigned char *hash, size_t hash_len,
                                    unsigned char *sig, size_t *sig_len,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng);
};

#endif  // SE_TRUSTX_H