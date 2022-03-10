#ifndef SERVICE_H_
#define SERVICE_H_

#include <ios>
#include <string>

/*
 * Class for providing service exception
 */
class ServiceException : public std::ios_base::failure {
public:
  ServiceException(const std::string &str) : std::ios_base::failure(str) {}
};

/*
 * Abstract class for providing background services
 */
class Service {
public:
  Service();
  virtual void setup() = 0; // install a service in background
  virtual void stop() = 0;  // stop service
  void setName(std::string name) {
    this->name = name;
  } // set name of sth service
  std::string getName() { return name; }

  virtual ~Service();

private:
  std::string name;
};

#endif /* SERVICE_H_ */
