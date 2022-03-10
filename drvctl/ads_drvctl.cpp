/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Staroletov, Chudov
 */

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../Common/utils/ConfigReader.h"
#include "../Common/utils/Logger.h"
#include "../Common/utils/PrintfLogger.h"
#include "../Common/utils/Thread.h"

using namespace std;

Logger *logger;

string path;
string iface;
string drop;
long buf_size;
long max_mime_memory;
string classes;
string types;
string logging;
string filtering;
string filtering_multi;
string prior;
string targert;
string resender;
int resender_poll_delay;
int resender_mmap;
int min_size;
string sniffer;
int fd;
char buf[255];

bool connect() {
  logger->log("Connecting to device...");
  fd = open("/dev/ads_drv_setup", O_WRONLY);
  if (fd == -1) {
    logger->log("Can't access character data device /dev/ads_drv_setup! Module "
                "works wrong");
    return false;
  }
  return true;
}

void start() {
  int r;
  logger->log("STARTING");

  logger->log("Loading our module via insmod...");
  sprintf(buf, "insmod %s/ads_netfilter.ko", path.c_str());
  int res = system(buf);
  if (res != 0) {
    logger->log("Unable to install module!");
    exit(1);
  }
  logger->log("Creating virtual device...");

  dev_t dev = makedev(232, 0);
  mknod("/dev/ads_drv_setup", S_IFCHR + O_RDWR, dev);
  chmod("/dev/ads_drv_setup", 0777);

  connect();

  if (sniffer == "on") {

    logger->log("Configuring module priority...");
    sprintf(buf, "pr %s\n", prior.c_str());
    r = write(fd, buf, strlen(buf));

    logger->log("Configuring module target...");
    sprintf(buf, "tt %s\n", targert.c_str());
    r = write(fd, buf, strlen(buf));

    logger->log("Configuring if " + iface + "...");
    sprintf(buf, "if %s\n", iface.c_str());
    r = write(fd, buf, strlen(buf));

    logger->log("Configuring drop/pass packets...");
    if (drop == "on")
      sprintf(buf, "drop_packets\n");
    else
      sprintf(buf, "pass_packets\n");
    r = write(fd, buf, strlen(buf));

    logger->log("Configuring buffer size...");

    sprintf(buf, "bf %ld\n", buf_size);

    r = write(fd, buf, strlen(buf));

    logger->log("Configuring filtering enabled...");

    if (filtering == "on")
      sprintf(buf, "mf 1\n");
    else
      sprintf(buf, "mf 0\n");
    r = write(fd, buf, strlen(buf));

    if (filtering_multi == "on")
      sprintf(buf, "mg 1\n");
    else
      sprintf(buf, "mg 0\n");
    r = write(fd, buf, strlen(buf));

    logger->log("Configuring minimum packet size...");

    sprintf(buf, "ms %d\n", min_size);
    r = write(fd, buf, strlen(buf));

    logger->log("Activating ads_sniffer...");

    sprintf(buf, "sniffer\n");
    r = write(fd, buf, strlen(buf));

    bool mmapFoundDev = false;
    // read major number for mmap device file
    std::ifstream in("/proc/devices");
    std::string line;

    int ndev = 0;

    while (std::getline(in, line)) {
      if (line.find("ads_sniff_mmap") != -1ul) {
        mmapFoundDev = true;
        ndev = atoi(line.substr(0, line.find(' ')).c_str());
        logger->log("Found dev ads_sniff number='" + PrintfLogger::itos(ndev) +
                    "'");
        break;
      }
    }

    if (!mmapFoundDev) {
      logger->log("ads_sniff_mmap not found in /proc/devices");
      exit(1);
    }
    dev_t dev = makedev(ndev, 0);
    mknod("/dev/ads_sniff_mmap", S_IFCHR + O_RDWR, dev);
    chmod("/dev/ads_sniff_mmap", 0777);

    in.close();
  }

  logger->log("Configuring logging...");

  if (logging == "on") {
    sprintf(buf, "logging\n");
    r = write(fd, buf, strlen(buf));
  } else {
    sprintf(buf, "nologging\n");
    r = write(fd, buf, strlen(buf));
  }

  (void)r;
 }

void stop() {

  logger->log("STOPPING");

  logger->log("Stop ads userspace apps...");
  // int r = system("killall ADS");

  sleep(2);

  logger->log("Unlinking virtual devices...");
  unlink("/dev/ads_drv_setup");
  unlink("/dev/ads_sniff_mmap");

  logger->log("Unloading module via rmmod...");
  sprintf(buf, "rmmod %s/ads_netfilter.ko", path.c_str());
  int res = system(buf);
  if (res != 0) {
    logger->log("Unable to unload module!");
    exit(1);
  }
}

int main(int argc, char **argv) {

  if (argc != 2 || (strcmp(argv[1], "stop") && strcmp(argv[1], "start") &&
                    strcmp(argv[1], "restart"))) {
    cout << "tcdrv.ko configurator. Usage tcdrvctl start|stop|restart" << endl;
    return 0;
  }

  logger = new PrintfLogger();

  logger->log("reading config...");

  ConfigReader reader("module.conf");
  path = reader.getGlobalProperty("path_to_tcdrv", ".");
  iface = reader.getGlobalProperty("iface", "eth0");
  drop = reader.getGlobalProperty("drop_packets", "on");
  buf_size = reader.getGlobalProperty("sniffer_memory_map_size", 41943040);
  logging = reader.getGlobalProperty("logging", "on");
  prior = reader.getGlobalProperty("priority", "first");
  targert = reader.getGlobalProperty("targert", "forward");

  min_size = reader.getGlobalProperty("min_packet_size", 0);

  sniffer = reader.getGlobalProperty("sniffer", "on");

  if (!strcmp(argv[1], "start")) {
    start();
  } else if (!strcmp(argv[1], "stop")) {
    stop();
  } else if (!strcmp(argv[1], "restart")) {
    stop();
    sleep(2);
    start();
  }

  close(fd);
}
