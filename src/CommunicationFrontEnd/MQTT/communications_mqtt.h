/*******************************************************************************
 * Copyright (c) 2018-2019, Sensors and IoT Capability Centre (SIOT) at GovTech.
 *
 * Contributor(s):
 *    Lau Lee Hong  lau_lee_hong@tech.gov.sg
 *    Lee Tze Han
 *******************************************************************************/
#ifndef COMMUNICATIONS_MQTT_H
#define COMMUNICATIONS_MQTT_H

#include <string>
#include <unordered_set>
#include "MQTTNetwork.h"
#include "MQTTmbed.h"
#include "MQTTClient.h"

#undef USE_WIFI
#if defined(MBED_CONF_APP_USE_WIFI) && (MBED_CONF_APP_USE_WIFI == 1)
    #define USE_WIFI
#endif  // USE_WIFI

/* Network Connection */
bool ConfigNetworkInterface(NetworkInterface*& network);
bool ConnectMqttNetwork(MQTTNetwork*& mqtt_network, NetworkInterface* network, std::string root_ca, std::string client_cert, std::string private_key);
bool ConnectMqttClient(MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, MQTTNetwork* mqtt_network, std::string device_secret);

/* Network Disconnection */
void DisconnectMqttNetwork(MQTTNetwork* mqtt_network);
void DisconnectMqttClient(MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, std::unordered_set<std::string>& all_sub_topics);

/* Publish & Subscribe */
bool MqttPublish(MQTT::Client<MQTTNetwork, Countdown>* mqtt_client, const char* topic, std::string payload);
bool MqttSubscribe(MQTT::Client<MQTTNetwork, Countdown>* mqtt_client, const char* topic);
void MessageArrived(MQTT::MessageData& md);

/* Reconnection */
bool ReconnectMqttNetwork(NetworkInterface* network,MQTTNetwork*& mqtt_network,std::string root_ca, std::string client_cert, std::string private_key);
bool ReconnectMqttClient(MQTTNetwork* mqtt_network, MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, std::string device_secret, std::unordered_set<std::string>& all_sub_topics);
bool ReconnectMqttService(NetworkInterface* network,MQTTNetwork*& mqtt_network, MQTT::Client<MQTTNetwork, Countdown>*& mqtt_client, std::string device_secret, std::unordered_set<std::string>& all_sub_topics, std::string root_ca, std::string client_cert, std::string private_key);

#endif  // COMMUNICATIONS_MQTT_H