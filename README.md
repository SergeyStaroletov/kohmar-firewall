# kohmar-firewall
Anomaly Detection System for network traffic in Realtime using Markov chains and Kohonen SOM


Variable-order Markov chain is used to represent TCP traffic states.
SOM model is used to obtain traffic blurring using some metrics, than cluster it and compare 
anomaly score with pretrained information. 

To obtain the traffic, it used self high-performance solution comprising a kernel module, packet_mmap and queues/threads 
to process the new packets. 

Initially developed for x86_64, but now it was tested only with Ubuntu/ARM64 and 5.13.0-32-generic Linux Kernel.

Work with my student Roman. 
Currently it is only in a research state. Probably, I will add some other detectors/metrics/UI and make proper evaluation of it,
but I have almost no time to work on it. Also I am interesting on some formalization of the logics and prove some theories on it.


Software architecture to be presented at <a href = "https://www.icin-conference.org">ICIN 22 conference</a>.




