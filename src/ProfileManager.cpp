#include "ProfileManager.h"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>

using json = nlohmann::json;

// --- Base64 Helpers ---
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        "abcdefghijklmnopqrstuvwxyz"
                                        "0123456789+/";

static std::string base64_encode(const std::string &in) {
  std::string out;
  int val = 0, valb = -6;
  for (unsigned char c : in) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(base64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}

static std::string base64_decode(const std::string &in) {
  std::string out;
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++)
    T[base64_chars[i]] = i;

  int val = 0, valb = -8;
  for (unsigned char c : in) {
    if (T[c] == -1)
      break;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}
// ----------------------

ProfileManager::ProfileManager(const std::string &filepath)
    : filepath(filepath) {
  // Ensure file exists
  std::ifstream f(filepath);
  if (!f.good()) {
    std::ofstream of(filepath);
    of.close();
  }
}

std::map<std::string, Profile> ProfileManager::get_profiles() const {
  std::map<std::string, Profile> profiles;
  std::ifstream f(filepath);
  if (!f.is_open())
    return profiles;

  std::stringstream buffer;
  buffer << f.rdbuf();
  std::string content = buffer.str();

  // Trim whitespace
  content.erase(0, content.find_first_not_of(" \n\r\t"));
  content.erase(content.find_last_not_of(" \n\r\t") + 1);

  if (content.empty())
    return profiles;

  try {
    std::string json_str = base64_decode(content);
    json j = json::parse(json_str);

    for (auto &[key, val] : j.items()) {
      Profile p;
      p.name = val.value("name", "");
      p.protocol = val.value("protocol", "MQTT");
      p.host = val.value("host", "localhost");
      p.port = val.value("port", "1883");
      p.username = val.value("username", "");
      p.password = val.value("password", "");
      p.mqtt_topic = val.value("mqtt_topic", "");
      p.amqp_vhost = val.value("amqp_vhost", "");
      p.amqp_queue = val.value("amqp_queue", "");
      p.amqp_exchange = val.value("amqp_exchange", "");
      p.amqp_routing = val.value("amqp_routing", "");
      profiles[key] = p;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error loading profiles: " << e.what() << std::endl;
  }
  return profiles;
}

void ProfileManager::save(const std::string &name, const Profile &p) {
  auto profiles = get_profiles();
  profiles[name] = p;

  json j;
  for (const auto &[key, val] : profiles) {
    j[key] = {{"name", val.name},
              {"protocol", val.protocol},
              {"host", val.host},
              {"port", val.port},
              {"username", val.username},
              {"password", val.password},
              {"mqtt_topic", val.mqtt_topic},
              {"amqp_vhost", val.amqp_vhost},
              {"amqp_queue", val.amqp_queue},
              {"amqp_exchange", val.amqp_exchange},
              {"amqp_routing", val.amqp_routing}};
  }

  std::string encoded = base64_encode(j.dump());
  std::ofstream f(filepath);
  f << encoded;
}

void ProfileManager::remove(const std::string &name) {
  auto profiles = get_profiles();
  if (profiles.erase(name)) {
    json j;
    for (const auto &[key, val] : profiles) {
      j[key] = {{"name", val.name},
                {"protocol", val.protocol},
                {"host", val.host},
                {"port", val.port},
                {"username", val.username},
                {"password", val.password},
                {"mqtt_topic", val.mqtt_topic},
                {"amqp_vhost", val.amqp_vhost},
                {"amqp_queue", val.amqp_queue},
                {"amqp_exchange", val.amqp_exchange},
                {"amqp_routing", val.amqp_routing}};
    }
    std::string encoded = base64_encode(j.dump());
    std::ofstream f(filepath);
    f << encoded;
  }
}
