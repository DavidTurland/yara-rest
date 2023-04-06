#pragma once
#include <string>
#include <stdio.h>
namespace org::turland::yara
{
// https://stackoverflow.com/questions/14374272/how-to-parse-version-number-to-compare-it
struct Version
{
    Version(std::string versionStr)
    {
        sscanf(versionStr.c_str(), "%d.%d.%d.%d", &major, &minor, &revision, &build);
    }

    bool operator<(const Version &otherVersion)
    {
        if(major < otherVersion.major)
            return true;
        if(otherVersion.major < major) 
            return false;
        if(minor < otherVersion.minor)
            return true;
        if(otherVersion.minor < minor) 
            return false;    
        if(revision < otherVersion.revision)
            return true;
        if(otherVersion.revision < revision) 
            return false;                
        if(build < otherVersion.build)
            return true;
         if(otherVersion.build < build) 
            return false;                   
        return false;
    }

    int major, minor, revision, build;
};

} // namespace org::turland::yara