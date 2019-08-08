# stack-manuca-os

## Introduction
MANUCA OS is a functional real-time operating system for sensor node developers to swiftly build upon using the MANUCA DK, and publish sensor measure points to the government cloud via DECADA Cloud.

---
## Development Team
* Lau Lee Hong (lau\_lee\_hong@tech.gov.sg)
* Yap Zi Qi    (yap\_zi\_qi@tech.gov.sg)
* Goh Kok Boon (goh\_kok\_boon@tech.gov.sg)

---
## System Requirements
* Ubuntu 18.04 LTS
* mbed-cli (https://os.mbed.com/docs/mbed-os/v5.8/tutorials/quick-start-offline.html)

---
## Quick Start
 * Set up the development environment (https://siot.gov.sg.com/starter-kit/set-up-your-software/) 
 * Clone the repository onto local disk: 
    `git clone --recurse-submodules https://github.com/GovTechSIOT/stack-manuca-os.git`
 * Toggle operating modes in mbed_app.json
 * Disable SSL Verification by changing mbed-os/features/netsocket/TLSSocketWrapper.cpp line 550 to `mbedtls_ssl_conf_authmode(get_ssl_config(), MBEDTLS_SSL_VERIFY_NONE);`
 * Compile using ARMmbed Command Line Interface (mbed-cli): 
`mbed compile --target NUCLEO_F767ZI --toolchain GCC_ARM --profile ./tools/profiles/tiny_debug.json`
 * Copy the binary file (.bin) into the MANUCA DK via programmer (eg. stlink v3).
 
---
## Documentation and References
* Technical Instruction Manual: https://siot.gov.sg/starter-kit/introduction/
* MANUCA DK User Manual: https://siot.gov.sg/files/MANUCA_User_Manual_V1.pdf

---
## License
Apache 2.0 (see https://siot.gov.sg/starter-kit/licensing/)
