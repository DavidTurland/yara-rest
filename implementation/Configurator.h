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
    Configurator(std::string config_file){
        config = YAML::LoadFile(config_file);
        meta   = config["meta"];
        server = config["server"];
        yara   = config["yara"];                
        if (meta["date"]) {
            std::cout << "meta date " << meta["date"].as<std::string>() << "\n";
        }
    }

    template <typename T> T _get_node_value(YAML::Node node,const std::string& key, T def){
        if (node[key]){
            return node[key].as<T>();
        }else{
            return def;
        }
    }
    
    int port(){
        return _get_node_value(server,"port",8080);
    }
    
    int num_threads(){
        return _get_node_value(server,"num_threads",-1);
    }

private:
    YAML::Node config;
    YAML::Node meta;
    YAML::Node server;
    YAML::Node yara ;    
};
}
#endif