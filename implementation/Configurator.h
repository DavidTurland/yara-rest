#ifndef CONFIGURATOR_H
#define CONFIGURATOR_H
// #include "Configurator.h"
#include <string>

#include "yaml-cpp/yaml.h"
#include "version.h"

namespace org::turland::yara
{
class Configurator{
public:
    Configurator(std::string config_file):version("0.2.0"){
        config = YAML::LoadFile(config_file);
        meta   = config["meta"];
        server = config["server"];
        yara   = config["yara"];                
        if (meta["date"]) {
            std::cout << "meta date " << meta["date"].as<std::string>() << "\n";
        }
    }

    int port(){
        return server["port"].as<int>();
    }
    
    int num_threads(){
        return server["num_threads"].as<int>();;
    }

private:
    YAML::Node config;
    YAML::Node meta;
    YAML::Node server;
    YAML::Node yara ;        
    Version version;

};
}
#endif