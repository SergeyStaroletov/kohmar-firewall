#include "../config.h"

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <signal.h>
#include <time.h>
#include <linux/if_packet.h>
#include <sys/mman.h>

#include <queue>
#include <iostream>
#include <sstream>
#include <vector>


//my custom classes
#include "utils/DaemonService.h"
#include "utils/Service.h"

#include "utils/PrintfLogger.h"
#include "utils/SyslogLogger.h"
#include "utils/NullLogger.h"
#include "utils/Logger.h"

#include "utils/Thread.h"
#include "utils/UnixLowLevelSocket.h"
#include "utils/LowLevelSocket.h"

#include "utils/ConfigReader.h"
#include "utils/UnixSemaphore.h"
#include "utils/PlatformFactory.h"

using namespace std;

//-------------------------
//some global data
//-------------------------
const int maxBufferLenConst = 20 * 1024 * 1024 * 2; //20mb/s
int bufferLength = 0;
static long mmapBufSize = 0;
static int delay; //buffer's delay in ms
static Logger *logger; //logger for logging

string pathToConfig; //need for daemons

//c style for naming to semaphores, buffers, etc
static UnixSemaphore *sem_output = new UnixSemaphore(); //sems for queue locking
static UnixSemaphore *sem_send = new UnixSemaphore();
static UnixSemaphore *sem_pause_kernel_reader = new UnixSemaphore();

volatile bool needPauseKernelReader = false;

//flags for thread control
volatile bool flagStopOutput;
volatile bool flagStopKernelReader;
//count

//forward declaration
struct DataSaved;

//continue global data


//this data struct we are getting from kernel module
struct DataFromKernel {
    char buffer[2000]; //for one mtu packet
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

// queue
std::queue<DataSaved*> outputQueue;

//conditions and corresponding mutexes for thread wakeups (new data posted to queues)
pthread_cond_t cond_kernel_data_arrive = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex_kernel_data_arrive = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t mutex_kernel_reader_paused = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_kernel_reader_paused = PTHREAD_COND_INITIALIZER;


//return protocol name from given number
const char * protocol_from_number(int n) {
    switch (n) {
    case 0:
        return "tcp_dummy";
    case 1:
        return "icmp";
    case 2:
        return "igmp";
    case 4:
        return "ipip";
    case 6:
        return "tcp";
    case 8:
        return "egp";
    case 12:
        return "pup";
    case 17:
        return "udp";
    case 22:
        return "idp";
    case 29:
        return "tp";
    case 41:
        return "ipv6_header";
    case 43:
        return "ipv6_routing";
    case 44:
        return "ipv6_fragment";
    case 46:
        return "vsvp";
    case 47:
        return "gre";
    case 50:
        return "esp";
    case 51:
        return "ah";
    case 58:
        return "icmpv6";
    case 59:
        return "ipv6_none";
    case 60:
        return "ipv6_dstopts";
    case 92:
        return "mtp";
    case 98:
        return "encap";
    case 103:
        return "pim";
    case 108:
        return "comp";
    case 132:
        return "sctp";
    case 255:
        return "raw";
    }
    return "unknown";
}

/*
 struct ipheader {
 unsigned char ip_hl :4, ip_v :4;
 unsigned char ip_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off;
 unsigned char ip_ttl;
 unsigned char ip_p;
 unsigned short int ip_sum;
 unsigned int ip_src;
 unsigned int ip_dst;
 };
 */

//print raw packet header data
void print_packet(const char* data, int len) {
    stringstream os;

    iphdr *iph = (iphdr*) (data);
    os.clear();
    //os << "Decoding packet of size " << len << ", proto " << protocol_from_number(iph->protocol) << endl;
    int dadd, sadd, bit1, bit2, bit3, bit4;
    dadd = iph->daddr;
    sadd = iph->saddr;
    bit1 = 255 & sadd;
    bit2 = (0xff00 & sadd) >> 8;
    bit3 = (0xff0000 & sadd) >> 16;
    bit4 = (0xff000000 & sadd) >> 24;
    //os << " IP " << bit1 << "." << bit2 << "." << bit3 << "." << bit4 << ".";
    //os << "->";
    //os << dec;
//print dst ip
    bit1 = 255 & dadd;
    bit2 = (0xff00 & dadd) >> 8;
    bit3 = (0xff0000 & dadd) >> 16;
    bit4 = (0xff000000 & dadd) >> 24;
    //os << " IP " << bit1 << "." << bit2 << "." << bit3 << "." << bit4 << ".";
//print dst mac
    /*os << " mac (";
     for (int i = 0; i < 6; i++)
     os << hex << (unsigned int) mac->dst[i] << ":";
     os << ") " << endl;*/

    //os << endl;
    
    if(iph->protocol == 6)
    {
      struct tcphdr *tcp_header = (tcphdr*) (data + sizeof(iphdr));
      int ack = tcp_header->ack;
      int syn = tcp_header->syn;
      int fin = tcp_header->fin;
      int psh = tcp_header->psh;
      int urg = tcp_header->urg;
      int rst = tcp_header->rst;
      os << "ack=" << ack << " syn=" << syn << " fin=" << fin << " psh=" << psh << " urg=" << urg << " rst=" << rst;
      os << endl;
    }
    
    logger->log(os.str());
}


/*
 *
 * OutputThread wake ups on new data in queue
 *
 */
class OutputThread: public Thread {
public:
    OutputThread() :
            Thread() {
    }
    void run() {
        DataSaved *data = NULL;


        while (true) {

            if (flagStopOutput)
                break;

            if (outputQueue.empty()) {
                //waiting for data in queue
                pthread_mutex_lock(&mutex_kernel_data_arrive);
                pthread_cond_wait(&cond_kernel_data_arrive, &mutex_kernel_data_arrive);
                pthread_mutex_unlock(&mutex_kernel_data_arrive);
            }
#if DEBUG
            logger->log("queue getting data and processing...");
#endif

            sem_output->wait(); //lock
            if (!outputQueue.empty()) { //if anything exist in queue
                data = outputQueue.front(); //get it
                outputQueue.pop();
                sem_output->post(); //unlock
            } else {
                outputQueue.pop();
                sem_output->post(); //unlock
                continue;
            }

            if (!data)
                continue;
            
	    //print packets here!!!!

        //*********************************************************

            char *buf2 = data->buffer;
            int N = *((int *) buf2);
             buf2 += sizeof(int);
             logger->log("got N=" + PrintfLogger::itos(N));
             for (int p = 0; p < N; p++) {
                 logger->log("Showing packet " + PrintfLogger::itos(p + 1) + " of " + PrintfLogger::itos(N));
                 short s_len = *((short *) (buf2));
                 buf2 += sizeof(short);

                 logger->log("size=" + PrintfLogger::itos(s_len));

                 print_packet(buf2, s_len);
                 buf2 += s_len;
             }
        //**********************************************************

             delete [] data->buffer;
             delete data;

        }



    }
};

/*
 *
 * ReaderThread - reads data from kernel and put it to buffer which used by Output thread
 *
 *
 */
class KernelDataReaderThread: public Thread {

public:
    KernelDataReaderThread() :
            Thread() {
    }
    void run() {



    char *output_buf; //sender buffers
    char *output_buf_start;

    output_buf = new char[bufferLength]; //see private data later
           if (output_buf == NULL) {
               logger->log("Can't alloc memory for Remote's buffer");
               exit(1);
           }
           output_buf_start = output_buf;

        //for buffer read delay calculation
        struct timespec timetoexpire;
        struct timeval today;
        int secDelay = delay / 1000;
        int msecDelay = delay % 1000;

        unsigned int snifferLastReadIndex = 0;
        unsigned int ourLastWroteIndex = 0;

        pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
        pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

#if DEBUG
        logger->log("Reader thread allocating " + PrintfLogger::itos(bufferLength) + "b. memory for buffer...");
#endif
        char* outputBuffer = new char[bufferLength];

        if (!outputBuffer) {
            logger->log("thread: no memory!");
            return;
        }

#if DEBUG
        logger->log("Reader thread connecting to sniffer...");
#endif

        struct tpacket_req s_packet_req;

        int block_count = mmapBufSize / 4096;

        s_packet_req.tp_block_size = 4096;
        s_packet_req.tp_frame_size = 2048;
        s_packet_req.tp_block_nr = block_count;
        s_packet_req.tp_frame_nr = block_count * 2;

        /* calculate memory to mmap in the kernel */
        int size = s_packet_req.tp_block_size * s_packet_req.tp_block_nr;

        /* mmap Tx ring buffers memory */

        int fd;

        if ((fd = open("/dev/sniffer_mmap", O_RDWR | O_SYNC)) < 0) {
            perror("open");
            exit(-1);
        }

        char *ps_header_start = (char *) mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ps_header_start == (void*) -1) {
            perror("mmap");
            exit(1);
        }

        logger->log("/dev/sniffer_mmap opened");

        snifferLastReadIndex = s_packet_req.tp_frame_nr;


       output_buf_start = output_buf;
        

        char *pkt;
        iphdr *iph;

        while (true) {

            if (flagStopKernelReader)
                break;

            if (needPauseKernelReader) {
                //notify we are here
#if DEBUG
                logger->log("pausing kernel reader for new packets");
#endif
                //notify we are here
                pthread_mutex_lock(&mutex_kernel_reader_paused);
                pthread_cond_signal(&cond_kernel_reader_paused);
                pthread_mutex_unlock(&mutex_kernel_reader_paused);

                //sleep
                sem_pause_kernel_reader->wait();
                sem_pause_kernel_reader->post();

            }

           
            int N = 0;

            char * ps_header = ps_header_start;

            struct NewPacketHeader *hdr;

            //we walk through our last receiver number and
            //index that stored kernel module in memory
            //for this index ps_header_start with 0 index is used

            snifferLastReadIndex = *((int*) ps_header_start);

            //old version commented: walk from 1 to frame number

            //ps_header += s_packet_req.tp_frame_size;//move to 1
            //for (int i = 1; i < s_packet_req.tp_frame_nr; i++) {

            if (ourLastWroteIndex + 1 > s_packet_req.tp_frame_nr)
                ourLastWroteIndex = 0;
            if (snifferLastReadIndex >= s_packet_req.tp_frame_nr)
                snifferLastReadIndex = 1;

            int a = ourLastWroteIndex + 1;
            ps_header = ps_header_start + a * s_packet_req.tp_frame_size;

            int b = snifferLastReadIndex;

            bool repeatFromOneFlag = 0;

            if (snifferLastReadIndex != ourLastWroteIndex) {

                if (a > b) { //this interval has new packets
                    b = s_packet_req.tp_frame_nr;
                    repeatFromOneFlag = 1;
                }

                //printf("[A B]=[%d %d]/%d flag=%d\n\n", a, b,
                //		s_packet_req.tp_frame_nr, repeatFromOneFlag);

                output_buf = output_buf_start;
                output_buf += sizeof(int); //place for packets count
                
                for (int i = a; i <= b; i++) {
                    if (i == b)
                        if (repeatFromOneFlag) {
                            a = 1;
                            i = 0;
                            ps_header = ps_header_start + s_packet_req.tp_frame_size;
                            b = snifferLastReadIndex;
                            repeatFromOneFlag = 0;
                            continue;
                        }

                    hdr = (NewPacketHeader *) ps_header;

                    if (hdr->flagReady == 1) {
                        ourLastWroteIndex = i;

                        //here we put packet
                        //calculate IP
                        pkt = (char *) (ps_header + sizeof(NewPacketHeader));
                        iph = (iphdr*) pkt;

                        {

                            *((short*) output_buf) = hdr->size; //first put size
                            output_buf += sizeof(short);
                            memcpy(output_buf, pkt, hdr->size); //minus mac header
#if DEBUG
                            logger->log("[mmap]getting from index = " + PrintfLogger::itos(i));
                            logger->log("hder size = " + PrintfLogger::itos(hdr->size));
                            //print_packet(send_buf,hdr->size);
#endif


                            //print packet can be here
                            //print_packet(ouput_buf,hdr->size);

                            output_buf += (hdr->size);

                            N++;
                        } 
                        hdr->flagReady = 0;
                    }

                    ps_header += s_packet_req.tp_frame_size;

                }


                    if (N > 0) {
                        //add to queue
#if DEBUG
                        logger->log(" got N=" + PrintfLogger::itos(N) + " packets ...");
#endif

                        DataSaved *data_to_save = new DataSaved;

                        *((int*) output_buf_start) = N;

                        int size = output_buf - output_buf_start;
                        char *buff = new char[(size < 1024) ? 10240 : size * 10];
                        //
                        memcpy(buff, output_buf_start, size);
                        data_to_save->buffer = buff;
                        data_to_save->length = size;


                        ps_header = ps_header_start;
#if DEBUG
                        logger->log("add to queue...");
#endif
                        //we must to think which queue we must to use

                        sem_output->wait();
                        outputQueue.push(data_to_save);
                        sem_output->post();

//wake the threads
                        pthread_mutex_lock(&mutex_kernel_data_arrive);
                        pthread_cond_broadcast(&cond_kernel_data_arrive);
                        pthread_mutex_unlock(&mutex_kernel_data_arrive);
                    }
            }
            //-- this code is pthread_sleep(delay)
            gettimeofday(&today, NULL);
            timetoexpire.tv_sec = today.tv_sec + secDelay;
            long nano = (long) today.tv_usec * 1000 + (long) msecDelay * 1000000;
            if (nano > 999999999) {
                timetoexpire.tv_sec += 1;
                timetoexpire.tv_nsec = nano - 999999999;
            } else {
                timetoexpire.tv_nsec = nano;
            }
            do {
                pthread_cond_timedwait(&cond, &mutex, &timetoexpire);
                gettimeofday(&today, NULL);
                if (today.tv_sec > timetoexpire.tv_sec)
                    break;
                else {
                    if (today.tv_sec == timetoexpire.tv_sec)
                        if (today.tv_usec * 1000000 > timetoexpire.tv_nsec)
                            break;
                }
            } while (true);
            //-- end of sleep
        }
    }
};



int ReaderDaemonWork() {

    flagStopOutput = 0;
    flagStopKernelReader = 0;
    OutputThread * othread;


   
//create threads
    
    othread = new OutputThread();
    othread->start();


//kernel reader thread
    KernelDataReaderThread *thread = new KernelDataReaderThread();
    thread->start();

//wait :)
    int a;
    cin >> a;

    return 0;
}

int ReaderDaemonStopWork() {
    flagStopOutput = 1;
    flagStopKernelReader = 1;


    sleep(2);
    return 0;
}




int ReaderDaemonRereadConfig() {

    return 0;
}



int reader(int argc, char** argv) {

    string daemonName = "readerd";

    signal(SIGPIPE, SIG_IGN); //ignore SIGPIPE for send() error recovery

    cout << "Backend for send data from sniffer to remote" << endl << endl;
    cout << "see tcreaderd.conf for setup" << endl;

//know path
    char pathbuf[PATH_MAX + 1];
    char *pathres = realpath("./readerd.conf", pathbuf);
    if (!pathres) {
        perror("find config path");
        exit(1);
    }
    pathToConfig = (string) pathbuf;

    bool isDaemon = true;

    if (argc == 2) {

        if (!strcmp(argv[1], "console"))
            isDaemon = false;

        if (!strcmp(argv[1], "stop")) {
            cout << "Stopping daemon..." << endl;
            DaemonService *daemon = (DaemonService *) PlatformFactory::getInstance()->createService();
            daemon->setName(daemonName);
            try {
                daemon->stopWorker();
            } catch (ServiceException ex) {
                cout << "Stop exception :" << ex.what() << endl;
                exit(1);
            }
            cout << "Stop ok" << endl;
            exit(0);
        }
        if (!strcmp(argv[1], "reconfig")) {

            cout << "Sending reconfig signal to daemon..." << endl;
            DaemonService *daemon = (DaemonService *) PlatformFactory::getInstance()->createService();
            daemon->setName(daemonName);
            try {
                daemon->sendUserSignalToWorker();
            } catch (ServiceException ex) {
                cout << "send signal exception :" << ex.what() << endl;
                exit(1);
            }
            cout << "Send ok" << endl;
            exit(0);
        }

    }
//-----------------
    cout << "Config reading..." << endl;

    ConfigReader cfgReader(pathToConfig, true);
    if (!cfgReader.isOk()) {
        cout << "Bad config, not started. " << endl;
        return 1;
    }

    bufferLength = cfgReader.getGlobalProperty("max_buffer_memory", maxBufferLenConst);
  
    string islog = cfgReader.getGlobalProperty("logging", "on");

    if (islog == "on")
        logger = new PrintfLogger();
    else
        logger = new NullLogger();

    delay = cfgReader.getGlobalProperty("buffer_delay", 100);

    mmapBufSize = cfgReader.getGlobalProperty("sniffer_memory_map_size", 0);

    if (isDaemon) {
        //demonize

        logger->log("Switch to daemon state now (see syslog for output)...");

        if (islog == "on") {
            delete logger;
            logger = new SyslogLogger();
        }

        DaemonService *daemon = (DaemonService *) PlatformFactory::getInstance()->createService();
        daemon->setName(daemonName);
        logger->setName(daemonName);
        daemon->setLogger(logger);
        logger->log("Setup daemon...");

        try {
            daemon->setup();
        } catch (ServiceException ex) {
            logger->log(ex.what());
            exit(1);
        }

        logger->log("Start with monitoring...");
        daemon->startWithMonitoring(ReaderDaemonWork, ReaderDaemonStopWork, ReaderDaemonRereadConfig);
    } else {
    	//no daemon
        ReaderDaemonWork();

    }

    return 0;
} 
