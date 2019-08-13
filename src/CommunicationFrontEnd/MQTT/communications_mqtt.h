/*******************************************************************************************************
 * Copyright (c) 2018-2019 Government Technology Agency of Singapore (GovTech)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 *******************************************************************************************************/
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
