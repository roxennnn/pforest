# ***pForest: In-Network Inference with Random Forests***

### Authors

    * Adrien Prost (aprost@student.ethz.ch)
    * Benno Schneeberger (bschneebe@student.ethz.ch)
    * Roberto Rossini (rrossini@ethz.ch)

### Brief summary of the project

The *pForest: In-Network Inference with Random Forests* paper presents a system which enables programmable data planes to perform real-time inference. It used a pre-trained random forest model to perform its inferences. Despite being performed in the data plane, the inference is as accurate as if it was done in software using state-of-the-art machine learning frameworks.

In the original paper, by training multiple context-dependent random forest models optimised for different parts of a flow, *pForest* can classify packets as early as possible after a flow has started. Thus, it is able to detect malicious flows, such as flows from a DDoS attack, and to act at the beginning, avoiding the attack to succeed. 

Throughout this project, we implemented a simple version of the *pForest* system. Our implementation classifies if a flow is BENIGN or MALIGN by looking at determined features of the flow itself. Differently from the original paper, we did not used context-dependent random forests but only one random forest model trained using whole flows’ features. Thus, our implementation classify packets - on average - after most of the packets’ passed through the switch. However, for some flows the classification is correct already at the first packets of the flow. For some other flows, instead, after some packets the system classify correctly the flow but  after some more packets the classification changes and it is not correct anymore. Anyways, toward the last packets, the classification turns correctly again. Thus, our implementation is pretty accurate. 

Having a correct classification in the last packets is expected because the random forest model has been trained using data of whole flows. However, it is still interesting to notice that the first packets were correctly classified even if we did not implemented context-dependent random forest model, as in the original *pForest* paper. We believe that this behaviour guarantees an even better performance in the case context-dependent model will be implemented in the future.

Acting when a malicious flow is detected is pretty straightforward. However, we did not implement this behaviour because we are just interested in how flows are classified.

We developed Python scripts to generate P4 code and to train and translate a random forest model into a sequence of match-action tables and their corresponding table entries.

### Repository Organisation

* **evaluation**: inside this folder there are all the files to reproduce our results. In particular, the `pforest_generator.py` program, the controller program `controller.py`, a selected dump of flows inside the *pcap* folder and the configuration file used by `p4run` can be found. Furthermore, in the README file is written a step-by-step guide in order to reproduce the results and evaluate the project.

* **presentation**: inside this folder there are all the presentation and demo related files.

* **report**: inside this folder there are our report and related files.

* **src**: inside this folder, all the source codes we implemented are present.

### Brief Project Explanation

Hereafter, a brief explanation of how our project works. For a detailed step-by-step guide to reproduce our results, please refer to the `README.md` file inside the **evaluation/** folder.

First, you need to run the Python script which generates all the P4 codes and the related files: 

`$ python3 generate_pforest.py num_trees max_depth [certainty]`

At this point, you can compile the P4 program using `p4run` and create the virtual network: 

`$ sudo p4run`

Secondly, you need to run the controller, in order to initialise to 0 the switch’s registers and the custom hash functions:

`$ python controller.py`

At this point everything is set and the system can be tested. Using `tcpreplay` you can send the packets from a dumped flow toward the switch, in order to let it classify the flow:

`$ tcpreplay --intf1=input_interface /path/to/pcap/file`

Using Wireshark, you can capture the packets being forwarded by the switch and check if the classification is correct or not.



