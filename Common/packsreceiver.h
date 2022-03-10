/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef PACKSRECEIVER_H
#define PACKSRECEIVER_H

#include <QDebug>
#include <QList>
#include <QObject>
#include <QThread>

#include "../config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_packet.h>
#include <signal.h>
#include <sys/mman.h>
#include <time.h>

#include <iostream>
#include <queue>
#include <sstream>
#include <vector>

// my custom classes
#include "../Common/utils/DaemonService.h"
#include "../Common/utils/Service.h"

#include "../Common/utils/Logger.h"
#include "../Common/utils/NullLogger.h"
#include "../Common/utils/PrintfLogger.h"
#include "../Common/utils/SyslogLogger.h"

#include "../Common/utils/LowLevelSocket.h"
#include "../Common/utils/StdThread.h"
#include "../Common/utils/Thread.h"

#include "../Common/utils/UnixLowLevelSocket.h"

#include "../Common/utils/ConfigReader.h"
#include "../Common/utils/PlatformFactory.h"
#include "../Common/utils/UnixSemaphore.h"

//#include "../Common/ConnectionTree.h"
#include "../Common/structs.h"

#include "../PST/pst_predictor.h"

#include "../SOM/samplesom.h"
#include "../SOM/selforganizedmap.h"

using namespace std;

// forward declaration
struct DataSaved;

// this data struct we are getting from kernel module
struct DataFromKernel {
  char buffer[2000]; // for one mtu packet
  short length;
};

struct DataSaved {
  char *buffer;
  int length;
};

struct NewPacketHeader {
  int flagReady;
  int size;
};

class PacksReceiver : public StdThread {
public:
  explicit PacksReceiver();
  void run();

  void setIsLearnTcp(bool _isLearn, int _learnedProto);
  bool getIsLearnTcp();
  void setIsLearnFlow(bool _isLearn);
  bool getIsLearnFlow();

  bool getTcpAnomalyFromQueue(AnomalyNodeTCP *to_save);
  bool getFlowAnomalyFromQueue(AnomalyNodeFlow *to_save);
  bool packCanLearned(unsigned int port_dest, unsigned int port_src);
  QList<SampleSom *> getFlowLearningSamplesFromQueue();
  QList<char *> getLerningStrings(int learned_proto, int *len_to_save);
  void clearFlowLearningSamples();
  void clearLearningStrings();

  // settings
  int getTcpDepth();
  int getTcpAnomalyLimit();
  int getTcpDropPorts();
  bool getTcpGenerateRules();

  int getFlowPacksMaxCount();
  int getFlowMinCountPacksInConn();
  int getFlowAnomalyLimit();
  bool getFlowGenerateRules();
  void setFlowPacksMaxCount(int _max);

  void setCurFlowAnomaly(double _anomaly);

  void retrainPredictor(char *seq, int predictor);

signals:

public slots:

private:
  class OutputThread : public StdThread {
  public:
    OutputThread(PacksReceiver *_receiver) : StdThread() {
      receiver = _receiver;

      flow_cur_count = 0;
      flow_big_count = 0;
      flow_cur_count = 0;
      flow_diff_ip_src_count = 0;
      flow_diff_ports_count = 0;
      flow_icmp_count = 0;
      flow_little_count = 0;
      flow_low_active_conn_count = 0;
      flow_new_tcp_conn_count = 0;
      flow_size = 0;
      flow_udp_count = 0;
    }
    void run();

  private:
    PacksReceiver *receiver;

    char tcp_beg_conn = 1 + 48;
    char tcp_beg_conn_else = 63 + 48;

    int flow_cur_count;
    int flow_size; //_average;
    int flow_little_count;
    int flow_big_count;
    int flow_new_tcp_conn_count;
    int flow_udp_count;
    int flow_icmp_count;
    int flow_diff_ip_src_count;
    int flow_diff_ports_count;
    int flow_low_active_conn_count;

    // void addConnectionToTree(const char* data, int len);
    void processing_packet(const char *data, int len);
    void addStateToTcpConnection(ConnectionTreeNode *con, char new_state);
    void addStateToLearningString(ConnectionTreeNode *con, char new_state);
    void addTcpAnomalyToQueue(ConnectionTreeNode *node, double anomaly,
                              int predictor);
    bool isIpFromLAN(unsigned int ip);
    // bool packCanLearned(unsigned int port_dest, unsigned int port_src);
  };

  class KernelDataReaderThread : public StdThread {
  public:
    KernelDataReaderThread(PacksReceiver *_receiver) : StdThread() {
      receiver = _receiver;
    }
    void run();

  private:
    PacksReceiver *receiver;
  };

  //-------------------------
  // some global data
  //-------------------------
  PstPredictor *http_predictor;
  PstPredictor *ftp_predictor;
  PstPredictor *https_predictor;
  PstPredictor *ssh_predictor;
  PstPredictor *telnet_predictor;
  PstPredictor *common_predictor;

  SelfOrganizedMap *som;
  int N;
  int M;
  // int dimension;
  int Iters;
  double Radius;
  double G;
  double lambda;
  double eta;

  bool isLearnTcp;
  bool isLearnFlow;
  bool tcp_generate_rules;
  int learnedProtocol;
  int states_count;
  int tcp_anomaly_limit;
  int tcp_drop_ports;
  unsigned int my_ip;

  int flow_packs_max_count;
  int flow_min_count_packs_in_conn;
  int flow_anomaly_limit;
  int flow_som_dimension;
  bool flow_generate_rules;
  double flow_cur_anomaly;
  long flow_cur_anomalies_in_queue;
  QList<int> packs_sizes;

  static const int maxBufferLenConst = 20 * 1024 * 1024 * 2;
  int bufferLength;
  /*static*/ long mmapBufSize;
  int delay;      // buffer's delay in ms
  Logger *logger; // logger for logging

  string pathToConfig; // need for daemons

  // c-style for naming to semaphores, buffers, etc
  /*static*/ UnixSemaphore *sem_output; // sems for queue locking
  /*static*/ UnixSemaphore *sem_send;
  /*static*/ UnixSemaphore *sem_pause_kernel_reader;
  /*static*/ UnixSemaphore *sem_con_tcp;
  /*static*/ UnixSemaphore *sem_con_udp;
  /*static*/ UnixSemaphore *sem_con_icmp;
  /*static*/ UnixSemaphore *sem_is_learn_tcp;
  /*static*/ UnixSemaphore *sem_is_learn_flow;
  /*static*/ UnixSemaphore *sem_anomaly_tcp;
  /*static*/ UnixSemaphore *sem_anomaly_flow;
  /*static*/ UnixSemaphore *sem_flow_cur_anomaly;

  volatile bool needPauseKernelReader;

  // flags for thread control
  volatile bool flagStopOutput;
  volatile bool flagStopKernelReader;
  // count

  // queue
  std::queue<DataSaved *> outputQueue;
  std::queue<AnomalyNodeTCP> anomalyQueueTcp;
  std::queue<AnomalyNodeFlow> anomalyQueueFlow;
  QList<SampleSom *> flow_learning_samples;

  // conditions and corresponding mutexes for thread wakeups (new data posted to
  // queues)
  pthread_cond_t cond_kernel_data_arrive;
  pthread_mutex_t mutex_kernel_data_arrive;

  pthread_mutex_t mutex_kernel_reader_paused;
  pthread_cond_t cond_kernel_reader_paused;

  QList<ConnectionTreeNode> connections_tcp;
  QList<ConnectionTreeNode> connections_udp;
  QList<ConnectionTreeNode> connections_icmp;

  const char *protocol_from_number(int n);

  int ReaderDaemonRereadConfig();
  int ReaderDaemonStopWork();
  int ReaderDaemonWork();
  void loadSettings();
  void initPredictors();
  void initSOM();
  unsigned int ip_str_to_hl(char *ip_str);

public:
  SelfOrganizedMap *getSOM() { return som; }
};

#endif // PACKSRECEIVER_H
