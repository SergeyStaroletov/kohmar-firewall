

#ifndef CONFIGREADER_H_
#define CONFIGREADER_H_

#include <string>
#include <map>
#include <vector>
using namespace std;


typedef map<string, map<string, string> > stringMap;


class ConfigReader {
public:
	ConfigReader(string filename,bool show=true);

	string getGlobalProperty(string propName,string defaultVal) ;
	int getGlobalProperty(string propName, int defaultVal) ;
	void getAllGlobalProperties(map<string, string> &res)  ;
	string getProperty(string section, string propName) ;
	void getPropertiesForSection(string section, map<string, string> &res)  ;
	void getAllPropertiesForSectionWithGlobal(string section, map<string, string> &res)  ;
	void getAllSectionProperties(string section, map<string, string> &res) ;

	bool readConfig(bool show) ;

	void getNames(std::vector<string> & valuesVec) ;

	bool isOk() {return ok ;}


	virtual ~ConfigReader();


private:

  stringMap confMap;//name -> (key->value)
  string filename ;
  bool ok ;

} ;


#endif /* CONFIGREADER_H_ */
