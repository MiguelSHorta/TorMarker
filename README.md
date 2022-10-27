# TorMarker
 A Tor traffic watermarker and correlator that compromises the anonymization of Tor connections.  
## 1 - Tool description
TorMarker is a tool built to correlate Tor flows leveraging on induced flow watermarking and deep learning of intrinsic traffic time properties. Implemented in the context of the dissertation:

```
@mastersthesis{tormarker,
author       = {Miguel Horta},
title        = {TOR K-ANONYMITY AGAINST DEEP LEARNING WATERMARKING ATTACKS: validating a Tor k-Anonimity input circuit enforcement against a deep learning watermarking attack},
school       = {NOVA School of Science and Technology},
year         = 2022,
month        = 10, 
}
```

TorMarker is able to generate watermarked Tor synthetic flows and send them through the Tor network as a user. The tool is then able to compute the probability of these induced watermarks being present in the traffic by analysing the arrival timings between packets from captured egress Tor flows.  

It is part of a test-bench environment that enables Tor connections reinforced by a K-anonymization solution leveraging on covert input circuits, as a way to perform security evaluations on said solution named "TIR".

## 2 - Project setup

The tool is composed of two components:

### Watermarker

There are two ways to run this component: 
<ol>
<li> Since it is setup as a Java project it can be compiled and run in any Java IDE (it was implemented originally in IntelliJ). To run this component just open as a new Maven project in your preferred Java IDE and execute. If confronted by the error "error: release version 6 not supported" just alter the Java Compiler target bytecode to version 8. 

<li> It can also be executed as a Jar file. Just run the file present in "out\artifacts\Client_jar" as a Java Jar file. Keep in mind this component was originally implemented using Java JDK 17.0.1. 

</ol>

### Detector

This component is implemented as a Jupyter Notebook. To run it execute the notebook in a Python environment, making sure all used packages are available. Time peformance can be substantially improved if an Nvidea GPU is available with the necessary CUDA support installed, the first cell of the notebook provides information regarding the available devices that can be used (it will always prioritize an available GPU over a CPU).  

## 3 - Tool employment specification 

### Watermarker

The watermarker component generates artificial Tor flows and acts as the user's client. It can embed two watermark types, Rainbow or ICBW, where the watermark's amplitude value and max amplitude need to be specified.  

To use this component, first we need to edit the configuration file *config.properties* and specify the target end for the connection. This file is present in the *configuration* directory and the values to alter are the *remote_host* and *remote_port_unsecure* which specify the target IP address and port, respectively. Next, run the component and input the following specification in the terminal: < protocol: 1 > < path.pcap > < path.csv > < numberOfPackets: >50 > < watermarkType: none/rainbow/icbw > < amplitude > < maxAmplitude >. The protocol number is always 1, the other are for debugging purposes; The *path.pcap* and *path.csv* are the paths for the original Tor flows capture file and it's arrival times, respectively; *NumberOfPackets* is the number of packets that are going to be sent in the connection. The *watermarkType* specifies the type of watermark that is going to be embedded, where the *amplitude* and *maxAmplitude* values represent it's parametrizations.  

### Detector 

The detector component learns the intrinsic watermarks' timing properties and attempts to detect them in the provided flows. 

To use this component we need to edit several variables: *dataset_size* specifies the size of both capture files of regular and watermarked flows, used for training (must be multiple of the flow size); *pred_dataset_size* size of both capture files used for predictions; *flow_size* size of the flows to be extracted from the provided timing files; *watermarked_flows* and *regular_flows* are the paths of the .csv files extracted from the capture files, containing all packets' arrival timings; *watermarked_flows_prediction* *regular_flows_prediction* also the paths for the .csv files but regarding the predictions dataset. 
