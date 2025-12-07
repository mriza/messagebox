#ifndef PROFILE_MANAGER_H
#define PROFILE_MANAGER_H

#include <map>
#include <string>
#include <vector>

struct Profile {
  std::string name;
  std::string protocol;
  std::string host;
  std::string port;
  std::string username;
  std::string password; // Will be stored obfuscated/hashed in file
  std::string mqtt_topic;
  std::string amqp_vhost;
  std::string amqp_queue;
  std::string amqp_exchange;
  std::string amqp_routing;
};

class ProfileManager {
public:
  ProfileManager(const std::string &filepath = "profiles.txt");
  std::map<std::string, Profile> get_profiles() const;
  void save(const std::string &name, const Profile &profile);
  void remove(const std::string &name);

private:
  std::string filepath;
};

#endif // PROFILE_MANAGER_H
