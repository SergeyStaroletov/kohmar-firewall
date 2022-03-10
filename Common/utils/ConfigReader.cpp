#include "ConfigReader.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdlib.h>

// trim from start
static inline std::string &ltrim(std::string &s) {
  s.erase(s.begin(),
          std::find_if(s.begin(), s.end(),
                       std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

// trim from end
static inline std::string &rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       std::not1(std::ptr_fun<int, int>(std::isspace)))
              .base(),
          s.end());
  return s;
}

// trim from both ends
static inline std::string &trim(std::string &s) { return ltrim(rtrim(s)); }

bool ConfigReader::readConfig(bool show) {

  string activeSection = "_global";

  try {
    ifstream f;
    f.open(filename.c_str(), ifstream::in);
    if (!f.good())
      throw exception();
    string key, value;
    while (!f.eof()) {
      char c = 0;
      f.get(c);
      if (c == '#') {
        getline(f, key, '\n');
        continue;
      }
      if (c == '\r' || c == '\n')
        continue;

      if (c == '<') {
        // open or close tag
        f.get(c); // next char

        if (c != '/') {
          // it is an open tag
          getline(f, key, ' '); // it is the name of a tag, skip
          key = c + key;

          getline(f, activeSection, '>');
          getline(f, key, '\n'); // skip to eol
          continue;
        } else {
          // it is closed tag
          getline(f, key, '>'); // it is name of end tag, skip

          activeSection = "_global";
          // getline(f, key, '\n');//skip to eol
          continue;
        }
      }

      if (f.eof())
        break;
      std::getline(f, key, '=');
      if (c != '<')
        key = c + key;
      key = trim(key);
      std::getline(f, value, '\n');
      value = trim(value);

      if (show)
        cout << activeSection << ": '" + key + "'='" + value + "'" << endl;

      confMap[activeSection][key] = value;

      // confMap.insert(std::pair<string, string>(key, value));
    }
    f.close();
  } catch (...) {
    cerr << "Error reading config file " << filename << ". Exiting." << endl;
    return false;
  }
  return true;
}

ConfigReader::ConfigReader(string filename, bool show) {
  this->filename = filename;
  this->ok = readConfig(show);
}

ConfigReader::~ConfigReader() {
  // TODO Auto-generated destructor stub
}

string ConfigReader::getGlobalProperty(string propName, string defaultVal) {

  map<string, string>::iterator it;
  map<string, string> global = confMap["_global"];

  it = global.find(propName);

  if (it == global.end())
    return defaultVal;
  else
    return global[propName];
}

void ConfigReader::getNames(std::vector<string> &valuesVec) {

  valuesVec.clear();

  for (stringMap::iterator iter = confMap.begin(); iter != confMap.end();
       ++iter) {
    string k = iter->first;
    if (k != "_global")
      valuesVec.push_back(k);
  }
}

string ConfigReader::getProperty(string section, string propName) {

  stringMap::iterator i = confMap.find(section);
  if (i == confMap.end())
    return ""; // no section found

  map<string, string>::iterator it;
  map<string, string> sect = confMap[section];

  it = sect.find(propName);

  if (it == sect.end())
    return ""; // no property found

  return sect[propName];
}

int ConfigReader::getGlobalProperty(string propName, int defaultVal) {

  map<string, string>::iterator it;
  map<string, string> global = confMap["_global"];

  it = global.find(propName);

  if (it == global.end())
    return defaultVal;

  else {
    istringstream stream(global[propName]);
    int number = 0;
    stream >> number;
    return number;
  }
}

void ConfigReader::getAllGlobalProperties(map<string, string> &res) {

  res.clear();

  map<string, string> global = confMap["_global"];

  for (map<string, string>::iterator iter = global.begin();
       iter != global.end(); ++iter) {
    string k = iter->first;
    string v = iter->second;
    res[k] = v;
  }
}

void ConfigReader::getAllSectionProperties(string section,
                                           map<string, string> &res) {

  res.clear();

  map<string, string> sect = confMap[section];

  for (map<string, string>::iterator iter = sect.begin(); iter != sect.end();
       ++iter) {
    string k = iter->first;
    string v = iter->second;
    res[k] = v;
  }
}

void ConfigReader::getAllPropertiesForSectionWithGlobal(
    string section, map<string, string> &res) {

  res.clear();
  // get global properties

  getAllGlobalProperties(res);

  // get self properties and mix it into res
  map<string, string> sect;

  getAllSectionProperties(section, sect);

  for (map<string, string>::iterator iter = sect.begin(); iter != sect.end();
       ++iter) {
    string k = iter->first;
    string v = iter->second;
    res[k] = v;
  }
}
