/**
 * @defgroup decada_manager Decada Manager
 * @{
 */
#include "decada_manager.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"
#include "mbed_trace.h"
#include "https_request.h"
#include "json.h"
#include "conversions.h"
#include "crypto_engine.h"
#include "device_uid.h"
#include "time_engine.h"

#define TRACE_GROUP  "DECADA_MANAGER"

/* List of trusted root CA certificates
 * For DecadaManager: COMODO Root CA
 *
 * To add more root certificates, just concatenate them.
 */
const char SSL_CA_STORE_PEM[] =  
    "-----BEGIN CERTIFICATE-----\n"
    "MIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB\n"
    "hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n"
    "A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV\n"
    "BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMTE5\n"
    "MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT\n"
    "EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR\n"
    "Q09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNh\n"
    "dGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCR\n"
    "6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2fcHK3YX/JSw8X\n"
    "pz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs/Q36nGz637CC\n"
    "9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio5JIk2kNrYrhV\n"
    "/erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62a+pGx8cgoLEf\n"
    "Zd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7gUYPDCUZObT6Z\n"
    "+pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlWPc9vqv9JWL7w\n"
    "qP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArncevPDt09qZah\n"
    "SL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0AuqLZxUpaVIC\n"
    "u9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dma/RMhnEw6abf\n"
    "Fobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5WdYgGq/yapiq\n"
    "crxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo0IwQDAdBgNVHQ4E\n"
    "FgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB\n"
    "/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAArx1UaEt65Ru2yyTUEUAJNMnMvl\n"
    "wFTPoCWOAvn9sKIN9SCYPBMtrFaisNZ+EZLpLrqeLppysb0ZRGxhNaKatBYSaVqM\n"
    "4dc+pBroLwP0rmEdEBsqpIt6xf4FpuHA1sj+nq6PK7o9mfjYcwlYRm6mnPTXJ9OV\n"
    "2jeDchzTc+CiR5kDOF3VSXkAKRzH7JsgHAckaVd4sjn8OoSgtZx8jb8uk2Intzna\n"
    "FxiuvTwJaP+EmzzV1gsD41eeFPfR60/IvYcjt7ZJQ3mFXLrrkguhxuhoqEwWsRqZ\n"
    "CuhTLJK7oQkYdQxlqHvLI7cawiiFwxv/0Cti76R7CZGYZ4wUAc1oBmpjIXUDgIiK\n"
    "boHGhfKppC3n9KUkEEeDys30jXlYsQab5xoq2Z0B15R97QNKyvDb6KkBPvVWmcke\n"
    "jkk9u+UJueBPSZI9FoJAzMxZxuY67RIuaTxslbH9qh17f4a+Hg4yRvv7E491f0yL\n"
    "S0Zj/gA0QHDBw7mh3aZw4gSzQbzpgJHqZJx64SIDqZxubw5lT2yHh17zbqD5daWb\n"
    "QOhTsiedSrnAdyGN/4fy3ryM7xfft0kL0fJuMAsaDk527RH89elWsn2/x20Kk4yl\n"
    "0MC2Hb46TpSi125sC8KKfPog88Tk5c0NqMuRkrF8hey1FGlmDoLnzc7ILaZRfyHB\n"
    "NVOFBkpdn627G190\n"
    "-----END CERTIFICATE-----\n";

const std::string decada_product_key = MBED_CONF_APP_DECADA_PRODUCT_KEY;
const std::string decada_access_key = MBED_CONF_APP_DECADA_ACCESS_KEY;
const std::string decada_access_secret = MBED_CONF_APP_DECADA_ACCESS_SECRET;
const std::string decada_ou_id = MBED_CONF_APP_DECADA_OU_ID;
const std::string api_url = MBED_CONF_APP_DECADA_API_URL;

/**
 *  @brief  Gets DECADA SSL Root CA for MQTT Connection.
 *  @author Lau Lee Hong
 *  @return PEM-formatted SSL Root CA - COMODO Cert.
 */
std::string GetDecadaRootCA(void)
{
    return SSL_CA_STORE_PEM;
}

/**
 *  @brief  REST call to Decada-cloud to check if this device has been registered prior.
 *  @author Goh Kok Boon
 *  @param network  Pointer to NetworkInterface object
 *  @return C++ string containing response code from the server
 */
std::string CheckDeviceRegistrationStatus(NetworkInterface* network)
{
    const std::string timestamp_ms = MsPaddingIntToString(RawRtcTimeNow());

    /* Sorted in ASCII order */ 
    const std::string parameters = "orgId" + decada_ou_id + "requestTimestamp" + timestamp_ms;
    const std::string signature = SignatureGenerator(parameters);

    const std::string requestUrl = "/connectService/products/" + decada_product_key + "/devices/"+ GetDeviceUid() +
     "?accessKey=" + decada_access_key + "&requestTimestamp=" + timestamp_ms +
      "&sign="+ signature + "&orgId=" + decada_ou_id;
    
    HttpsRequest* request = new HttpsRequest(network, SSL_CA_STORE_PEM, HTTP_GET, (api_url + requestUrl).c_str());
 
    HttpResponse* response = request->send();
    if (!response) 
    {
        delete request;
        printf("HttpRequest failed (error code %d)\n");
        return "invalid";   
    }
    else
    {
        std::string res_string = response->get_body_as_string();
        Json::Reader reader;
        Json::Value root;
        Json::Value sub_root;
        reader.parse(res_string, root, false);
        sub_root = root.get("data", "invalid");
        std::string device_secret = sub_root.get("deviceSecret", "invalid").asString();

        delete request;
        return device_secret;
    }
 }

/**
 *  @brief  Returns a unique device secret.
 *  @author Goh Kok Boon
 *  @param network  Pointer to NetworkInterface object
 *  @param device_name  User defined name for their device
 *  @return C++ string containing of random generated characters
 */
std::string RegisterDeviceToDecada(NetworkInterface* network, std::string device_name)
{   
    const std::string timestamp_ms = MsPaddingIntToString(RawRtcTimeNow());
    
    Json::Value root;  
    Json::Value message_content;
    message_content["deviceKey"] = GetDeviceUid();
    message_content["deviceName"] = device_name;
    message_content["timezone"] = "+08:00";
    root.append(message_content);

    Json::FastWriter fast_writer;
    std::string body = fast_writer.write(root);
    const char* body_sanitized = (char*)body.c_str();

    /* Sort in ASCII order */
    const std::string parameters = "orgId" + decada_ou_id + "requestTimestamp" + timestamp_ms + body_sanitized;
    const std::string signature = SignatureGenerator(parameters);

    const std::string requestUrl = "/connectService/products/" + decada_product_key +
     "/devices?accessKey=" + decada_access_key + "&orgId=" + decada_ou_id +
      "&requestTimestamp=" + timestamp_ms +
       "&sign=" + signature;
    
    HttpsRequest* request = new HttpsRequest(network, SSL_CA_STORE_PEM, HTTP_POST, (api_url + requestUrl).c_str());
    request->set_header("Content-Type", "application/json;charset=UTF-8");
 
    HttpResponse* response = request->send(body_sanitized, strlen(body_sanitized));
    if (!response) 
    {
        delete request;
        printf("HttpRequest failed (error code %d)\n");
        return "invalid";
    }
    else
    {
        std::string res_string = response->get_body_as_string();
        Json::Reader reader;
        Json::Value root;
        Json::Value sub_root;
        reader.parse(res_string, root, false);
        auto entries_array = root["data"];
        sub_root = entries_array[0];
        std::string device_secret = sub_root.get("deviceSecret", "invalid").asString();

        delete request;
        return device_secret;
    }
}

/**
 *  @brief  Returns a certificate to establish MQTT connection with decada.
 *  @author Goh Kok Boon
 *  @param network  Pointer to NetworkInterface object
 *  @param decada_root_ca  Retrieved decada root ca to pass in for CSR generation
 *  @return C++ string containing of certificate
 */
std::string ApplyMqttCertificate(NetworkInterface* network, std::string decada_root_ca)
{    
    const std::string timestamp_ms = MsPaddingIntToString(RawRtcTimeNow());
    
    const std::string ssl_csr = GenerateCsr(timestamp_ms);
    const std::string body_sanitized = CSRPEMFormatter(ssl_csr);    

    /* Sort in ASCII order */
    const std::string parameters = "orgId" + decada_ou_id + "requestTimestamp" + timestamp_ms + body_sanitized;
    const std::string signature = SignatureGenerator(parameters);

    const std::string requestUrl = "/connectService/products/" + decada_product_key + "/devices/" + GetDeviceUid() +
     "/certificates/apply?&orgId=" + decada_ou_id + "&requestTimestamp=" + timestamp_ms + "&accessKey=" + decada_access_key + 
       "&sign=" + signature;
        
    HttpsRequest* request = new HttpsRequest(network, SSL_CA_STORE_PEM, HTTP_POST, (api_url + requestUrl).c_str());
    request->set_header("Content-Type", "application/json;charset=UTF-8");

    HttpResponse* response = request->send((char*)body_sanitized.c_str(), strlen((char*)body_sanitized.c_str()));
    if (!response) 
    {
        delete request;
        printf("HttpRequest failed (error code %d)\n");
        return "invalid";
    }
    else
    {
        std::string res_string = response->get_body_as_string();
        Json::Reader reader;
        Json::Value root;
        Json::Value sub_root;
        reader.parse(res_string, root, false);
        sub_root = root["data"];
        std::string decada_cert = sub_root.get("cert", "invalid").asString();

        delete request;
        return decada_cert;
    }
}

/** @}*/