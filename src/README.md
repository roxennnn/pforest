# **Source Code**

### Folder Organization

* `randomforest/`: all the scripts and other related files used to handle random forest models are present inside this folder:
  * `storage/`: inside this folder there are 2 files (`np_data.py` & `np_dummies.py`) which are the output of `dataset_analysis.ipynb`, i.e. the analyzed dataset (which is not provided in the repository because too large; please refer to the **report** to know more about it).
  * `dataset_analysis.ipynb`: Jupyter Notebook used to analyze the dataset. The notebook loads the dataset, extract the important features for us and stores them inside a *numpy* array. Furthermore, it merges all the 'malicious’ labels to a single label __MALIGN__. Also, it cuts out the 96% of flows labeled as __BENIGN__ due to the unbalanced distribution between the 2 labels (~97% __BENIGN__, ~3% __MALIGN__) in order to have an (almost) even distribution. The analyzed dataset is saved inside the 2 files (`np_data.py` & `np_dummies.py`) inside the `storage/` folder.
  * `randomForestEncode.py`: defines functions to translate a trained random forest model into a sequence of `table_add` commands with the respective table entry values. This file is imported and used in `generator_pforest.py`.
  * `rf_model.py`: defines a function to build and train a random forest model. This function is imported and used in `generator_pforest.py`.
  * `tester.py`: defines a function to test the performance of a random forest model. This function is imported and used in `generator_pforest.py`.
* `p4_generator.py`: defines functions to generate *pForest*'s P4 code. It defines functions to generate the code for: `pforest.p4`, `headers.p4`, `parser.p4`.  This file is imported and used in `generator_pforest.py`.
* `swap_flows.py`: Python script which loads the packets from the given _.pcap_ files and impose source/destination IP addresses and transport protocol ports. The purpose of this file is to unify backward and forward flows in a single one. The output _.pcap_  files are the ones saved in `evaluation/pcap`. The input file instead is not provided, in order to provide a cleaner and lighter repository.
