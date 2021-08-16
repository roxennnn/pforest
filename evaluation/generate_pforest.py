# This Python script generates all the P4 code for the pForest project.
# Moreover, the random forest model is built, trained and translated in a sequence of 
# match-action P4 tables with the corresponding table entries.
# 2 parameters are needed: the number of trees used in the random forest model and the maximum depth of each tree.
# As optional parameter, the certainty threshold can be provided. Otherwise, the default value will be used.

import sys
import os

sys.path.append("..")	# in order to load custom functions
from src.p4_generator import generate_pforest, generate_headers, generate_parser
from src.randomforest.rf_model import build_and_train_random_forest
from src.randomforest.tester import rf_tester
from src.randomforest.randomForestEncode import rf_encoding

# Check if there are the minimum parameters
if len(sys.argv) < 3:
    print("Invalid arguments!\nPlease run the program as the following the format:\n\
$ python3 generator.py num_trees max_depth [certainty]\n\
where:\n\
	- num_trees: number of trees used in the random forest model;\n\
	- max_depth: maximum depth of the trees in the forest;\n\
	- certainty: threshold certainty value; this value could be only between 0 and 100 in order to be effective. The default value is 80.")
    exit(1)

# Value to change according to the model
num_trees = int(sys.argv[1])
max_depth = int(sys.argv[2])
if len(sys.argv) > 3:
    certainty = int(sys.argv[3])*10
else:
    certainty = 700     # default

#######################################################################################
# 								Random Forest Model 								  #
#######################################################################################

# Build and train a random forest model:
# If it does not perform well on our selected 6 flows, re-train it
# This process continues until a good model is trained or 100 models have been tested

good = False
counter = 0
rf = None

while (not good) and (counter < 100):
	counter += 1

	rf = build_and_train_random_forest(num_trees, max_depth)
	preds = rf_tester(rf)
	# Check predictions. Warning: it works only on our selected flows
	error = 0
	for p,pred in enumerate(preds):
		if p > 3:
			if pred != 1:
				error += 1
		else:
			if pred != 0:
				error += 1
	error /= 6

	if error < 0.17:	# only one error is tolerated
		good = True
		print("After", counter, "models tested, this one is good! Error rate:", error)
		
if counter == 100:
	print("No good model found. Try maybe with a fewer number of trees.")
	exit(100)

#######################################################################################
# 								Generate P4 code 									  #
#######################################################################################

# If it does not exist, create the include folder inside the p4src folder
if not os.path.isdir("./p4src/include"):
	os.mkdir("p4src/include")

generate_parser()
generate_headers(num_trees)
generate_pforest(num_trees, max_depth, certainty)
print("P4 code generated")


#######################################################################################
# 							Encode the Random Forest Model 							  #
#######################################################################################
rf_encoding(rf)
print("Random forest model encoded in table entries.")

print("DONE: pForest ready!")