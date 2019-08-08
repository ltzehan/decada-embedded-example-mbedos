/**
 * @defgroup communications_mqtt Communications Front-End
 * @{
 */
 
#include "communications_mqtt.h"
#include "mbed.h" 
#include "platform.h"
#include "mbed_trace.h"
#include "global_params.h"
#include "MQTT_server_setting.h"
#include "json.h"
#include "conversions.h"
#include "crypto_engine.h"
#include "persist_store.h"
#include "time_engine.h"

#ifdef USE_WIFI
#include "ESP32Interface.h"
#else
#include "EthernetInterface.h"
#endif  // USE_WIFI

#define TRACE_GROUP  "CommunicationsMQTT"

std::string const WIFI_SSID = ReadWifiSsid();
std::string const WIFI_PASSWORD = ReadWifiPass();
std::string const BROKER_IP = "mqtt.decada.gov.sg";

/**
 *  @brief  Configure network interface (WiFi / Ethernet)
 *  @author Lee Tze Han
 *  @param network Reference to NetworkInterface pointer
 *  @return Success of NetworkInterface connection
 */
bool ConfigNetworkInterface(NetworkInterface*& network)
{
    int rc;
    
    #ifdef USE_WIFI
    const int esp32_serial_baud_rate = 115200;
    ESP32Interface* netif = new ESP32Interface(MBED_CONF_APP_ESP32_EN, NC, MBED_CONF_APP_WIFI_TX, MBED_CONF_APP_WIFI_RX, false, NC, NC, esp32_serial_baud_rate);
    rc = netif->connect(WIFI_SSID.c_str(), WIFI_PASSWORD.c_str(), MBED_CONF_APP_WIFI_SECURITY);
    #else
    EthernetInterface* netif = new EthernetInterface();
    rc = netif->connect();
    #endif  // USE_WIFI
    
    network = netif;
    
    if (rc != 0)
    {
        /* Unable to configure NetworkInterface */
        tr_err("Failed to configure NetworkInterface (rc = %d)", rc);
        
        return false;
    }
    else
    {
        tr_info("NetworkInterface successfully configured");
    }
    
    return true;
}

/**
 *  @brief  Connect to MQTT network (refer to MQTT_server_setting.h to set a different hostname/serverport).
 *  @author Lau Lee Hong, Goh Kok Boon
 *  @param mqtt_network Reference to MQTTNetwork pointer
 *  @param network      Pointer to NetworkInterface object
 *  @param root_ca      Root CA
 *  @param client_cert  SSL Client Certificate 
 *  @param private_key  SSL Private Key
 *  @return Success of opening socket through MQTTNetwork
 *  @note There is no way to query if there is an MQTT network behind the socket;
 *        this only checks if the socket is successfully opened.
 */
bool ConnectMqttNetwork(MQTTNetwork*& mqtt_network, NetworkInterface* network, std::string root_ca, std::string client_cert, std::string private_key)
{
    if (!network)
    {
        tr_error("NetworkInterface NULL");   
    }
    mqtt_network = new MQTTNetwork(network);

    int rc = mqtt_network->connect(BROKER_IP.c_str(), MQTT_SERVER_PORT, root_ca.c_str(),
            client_cert.c_str(), private_key.c_str());

    if (rc != 0)
    {
        tr_err("Failed to set-up socket (rc = %d)", rc);
        
        return false;
    }
    else
    {
        tr_info("Opened socket on %s:%d", BROKER_IP.c_str(), MQTT_SERVER_PORT);
    }
    
    return true;
}

/**
 *  @brief  Connect to MQTT broker (eg. Mosquitto).
 *  @author Lau Lee Hong
 *  @param  mqtt_client     Reference to MQTT Client pointer
 *  @param  mqtt_network    Pointer to MQTTNetwork object
 *  @param  device_secret   Cloud-provisioned device secret
 *  @return Success of connection to MQTT broker
 */
bool ConnectMqttClient(MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, MQTTNetwork* mqtt_network, std::string device_secret)
{
    if (!mqtt_network)
    {
        tr_error("MQTTNetwork NULL");   
    }
    const std::string decada_device_key = device_uuid;
    const std::string decada_product_key = MBED_CONF_APP_DECADA_PRODUCT_KEY;
    int rtc_time_ms = RawRtcTimeNow();
    std::string time_now_milli_sec = MsPaddingIntToString(rtc_time_ms);

    std::string sha1_input = "clientId" + decada_device_key + "deviceKey" + decada_device_key + "productKey" + decada_product_key +
     "timestamp" + time_now_milli_sec + device_secret;

    std::string sha1_output = GenericSHA1Generator(sha1_input);

    std::string mqtt_decada_client_id = decada_device_key + "|securemode=2,signmethod=hmacsha1,timestamp=" + time_now_milli_sec + "|";
    std::string mqtt_decada_username = decada_device_key + "&" + decada_product_key;
    std::string mqtt_decada_password = ToUpperCase(sha1_output);
    
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    data.MQTTVersion = 3;
    data.clientID.cstring = (char*)mqtt_decada_client_id.c_str();
    data.username.cstring = (char*)mqtt_decada_username.c_str();
    data.password.cstring = (char*)mqtt_decada_password.c_str();

    mqtt_client = new MQTT::Client<MQTTNetwork, Countdown>(*mqtt_network);
    
    int rc = mqtt_client->connect(data);
    if (rc != MQTT::SUCCESS)
    {
        tr_err("rc from MQTT connect is %d", rc);
     
        return false;
    }
    else
    {
        tr_info("MQTT client successfully connected to broker");
    }
    
    return true;
}

/**
 *  @brief  Disconnect the MQTT network.
 *  @author Lau Lee Hong
 *  @param  mqtt_network Reference to MQTT Network pointer
 */
void DisconnectMqttNetwork(MQTTNetwork* mqtt_network)
{
    int rc = mqtt_network->disconnect();
    if (rc != 0)
    {
        tr_warn("Failed to disconnect from MQTT network. (rc = %d)",rc);   
    }
    delete mqtt_network;
    mqtt_network = NULL;
    
    return;        
}

/**
 *  @brief  Disconnect the MQTT client.
 *  @author Lee Tze Han
 *  @param  mqtt_client Reference to MQTT Client pointer
 *  @param  sub_topic   MQTT subscribe topic
 */
void DisconnectMqttClient(MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, std::unordered_set<std::string>& all_sub_topics)
{
    for (auto& sub_topic : all_sub_topics)
    {
        int rc = mqtt_client->unsubscribe(sub_topic.c_str());
        if (rc != 0)
        {
            tr_warn("Failed to unsubscribe to MQTT.(rc = %d)",rc);   
        }
        
        rc = mqtt_client->setMessageHandler(sub_topic.c_str(), 0);
        if (rc != 0)
        {
            tr_warn("Failed to set message handler(rc = %d)",rc); 
        }
    }

    if (mqtt_client->isConnected())
    {
        int rc = mqtt_client->disconnect();
        if (rc != 0)
        {
            tr_warn("Failed to disconnect MQTT client(rc = %d)",rc);   
        }
    }

    delete mqtt_client;
    mqtt_client=NULL;

    return;        
}

/**
 *  @brief  Publish payload via MQTT.
 *  @author Lau Lee Hong
 *  @param  mqtt_client Pointer to MQTT Client object
 *  @param  topic       MQTT publish topic
 *  @param  payload     Outgoing MQTT message
 *  @return Successful(1)/unsuccessful(0) mqtt publish
 */
bool MqttPublish(MQTT::Client<MQTTNetwork, Countdown>* mqtt_client, const char* topic, std::string payload)
{   
    stdio_mutex.lock();

    char* mqtt_payload = (char*) payload.c_str();

    /* Publish MQTT message */
    MQTT::Message message;
    message.retained = false;
    message.dup = false;
    message.payload = mqtt_payload;
    message.qos = MQTT::QOS0;
    message.payloadlen = (payload.length());
        
    int rc = mqtt_client->publish(topic, message);

    stdio_mutex.unlock();
    
    if (rc != MQTT::SUCCESS)
    {
        /* Mosquitto broker is disconnected */ 
        tr_warn("rc from MQTT publish is %d", rc);
        return false;
    }
    else
    {
        tr_debug("MQTT Message published");
    }
    
    return true;
}

/**
 *  @brief  Subscribes to Mqtt Topic
 *  @author Lau Lee Hong
 *  @param  mqtt_client Pointer to MQTT Client object
 *  @param  topic       MQTT topic
 *  @return Successful(1)/unsuccessful(0) mqtt subscription service
 */
bool MqttSubscribe(MQTT::Client<MQTTNetwork, Countdown>* mqtt_client, const char* topic)
{
    int rc = mqtt_client->subscribe(topic, MQTT::QOS1, MessageArrived);
    
    if (rc != MQTT::SUCCESS) 
    {
        tr_err("rc from MQTT subscribe is %d", rc);
        
        return false;
    }
    else
    {
        tr_info("MQTT subscription service online");
    }
        
    return true;  
}

/**
 *  @brief  Callback when a message has arrived from the broker, and sends received data as mail to EventManagerThread.
 *  @author Lau Lee Hong, Yap Zi Qi
 *  @param  md  Address of message data
 */
void MessageArrived(MQTT::MessageData& md)
{
    MQTT::Message &message = md.message;
    std::string incoming_payload = (char*)message.payload;
    
    incoming_payload = incoming_payload.substr(0, message.payloadlen);

    Json::Reader reader;
    Json::Value root;
    reader.parse(incoming_payload, root, false);

    std::vector<std::pair<std::string, std::string>> param_list;
    std::string msg_id = root.get("id", "invalid").asString();

    std::string endpoint_id = root.get("method", "invalid").asString();
    std::string const identifier = "thing.service.";
    std::size_t found = endpoint_id.find(identifier);
    if (found !=std::string::npos)
    {
        endpoint_id.erase(found, found+identifier.length());     // remove first 14 characters "thing.service." in method
    }

    Json::Value params = root.get("params", "invalid");
    if (params != "invalid")
    {
        Json::Value::Members param_keys = params.getMemberNames();
        for (int i=0; i<param_keys.size(); i++)
        {
            std::string name = param_keys[i];
            std::string value = root["params"][name].asString();
            param_list.push_back(make_pair(name, value));
        }
    }

    for (auto& it : param_list)
    {
        tr_info("service identifier: %s, message_id: %s, param: %s, value: %s", endpoint_id.c_str(), msg_id.c_str(), it.first.c_str(), it.second.c_str());

        mqtt_arrived_mail_t *mqtt_arrived_mail = mqtt_arrived_mail_box.calloc();
        while (mqtt_arrived_mail == NULL)
        {
            mqtt_arrived_mail = mqtt_arrived_mail_box.calloc();
            tr_warn("Memory full. NULL pointer allocated");
            wait(0.5);
        }

        mqtt_arrived_mail->endpoint_id = StringToChar(endpoint_id);
        mqtt_arrived_mail->msg_id = StringToChar(msg_id);
        mqtt_arrived_mail->param = StringToChar(it.first);
        mqtt_arrived_mail->value = StringToChar(it.second);
        mqtt_arrived_mail_box.put(mqtt_arrived_mail);
    }

    return;
}

/**
 *  @brief  Reconnect MQTT network.
 *  @author Lau Lee Hong, Ng Tze Yang
 *  @param  network         Pointer to NetworkInterface object
 *  @param  mqtt_network    Reference to MQTTNetwork object pointer
 *  @return Successful(1)/unsuccessful(0) MQTT Network Reconnection
 */
bool ReconnectMqttNetwork(NetworkInterface* network, MQTTNetwork*& mqtt_network, std::string root_ca, std::string client_cert, std::string private_key)
{   
    bool rc = ConnectMqttNetwork(mqtt_network, network, root_ca, client_cert, private_key);
    if (rc)
    {
        tr_info("Re-established connectivity with MQTT network");
    }
    else
    {
        tr_err("Could not established connectivity with MQTT network");
    }
    
    return rc; 
}

/**
 *  @brief  Reconnect MQTT client on DECADA.
 *  @author Lau Lee Hong
 *  @param  mqtt_network    Pointer to MQTTNetwork object
 *  @param  mqtt_client     Reference to MQTT::Client object pointer
 *  @param  device_secret   Cloud-provisioned device secret
 *  @param  all_sub_topics  MQTT subscription topics list
 *  @return Successful(1)/unsuccessful(0) MQTT Client Reconnection
 */
bool ReconnectMqttClient(MQTTNetwork* mqtt_network, MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, std::string device_secret, std::unordered_set<std::string>& all_sub_topics)
{
    bool is_connected = ConnectMqttClient(mqtt_client, mqtt_network, device_secret);
    bool is_subscribed;
    for (auto& sub_topic : all_sub_topics)
    {
        is_subscribed = MqttSubscribe(mqtt_client, sub_topic.c_str());
    }
    
    if (is_connected && is_subscribed)
    {
        tr_info("Re-established connectivity with MQTT client");
        return true;
    }
    else
    {
        tr_warn("Could not re-establish connectivity with MQTT client");
        return false;
    }
}

/**
 *  @brief  Disconnect and Reconnect MQTT network & client on DECADA.
 *  @author Ng Tze Yang
 *  @param  network         Pointer to NetworkInterface object
 *  @param  mqtt_network    Reference to MQTTNetwork object pointer
 *  @param  mqtt_client     Reference to MQTT::Client object pointer
 *  @param  device_secret   Cloud-provisioned device secret
 *  @param  all_sub_topics  MQTT subscription topics list
 *  @return Successful(1)/unsuccessful(0) MQTT Client Reconnection
 */
bool ReconnectMqttService(NetworkInterface* network,MQTTNetwork*& mqtt_network, MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, std::string device_secret, std::unordered_set<std::string>& all_sub_topics, std::string root_ca, std::string client_cert, std::string private_key)
{   
    const uint8_t max_mqtt_failed_reconnections = 10;
    static uint8_t mqtt_failed_reconnections = 0;

    mqtt_mutex.lock();
    DisconnectMqttNetwork(mqtt_network);
    DisconnectMqttClient(mqtt_client, all_sub_topics);
    bool network_is_connected = ReconnectMqttNetwork(network,mqtt_network, root_ca, client_cert, private_key);
    bool client_is_connected = ReconnectMqttClient(mqtt_network, mqtt_client, device_secret, all_sub_topics);
    mqtt_mutex.unlock();
        
    if (network_is_connected && client_is_connected)
    {
        mqtt_failed_reconnections = 0;
        return true;
    }
    else
    {
        mqtt_failed_reconnections++;
        if (mqtt_failed_reconnections == max_mqtt_failed_reconnections)
        {
            NVIC_SystemReset();
        }
        return false;
    }
}

/** @}*/