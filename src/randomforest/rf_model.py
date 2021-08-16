# Training random forest model
#
# Datasets: http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/
# Code based on: https://towardsdatascience.com/random-forest-in-python-24d0893d51c0 	

import numpy as np
import sys
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

def build_and_train_random_forest(num_trees, max_depth, debug=False):
	# Import already-analyzed dataset loading saved numpy arrays
	features = np.load("../src/randomforest/storage/np_data.npy",allow_pickle=True)
	labels = np.load("../src/randomforest/storage/np_dummies.npy",allow_pickle=True)

	# Using Skicit-learn to split data into training and testing sets
	rnd_seed = (int(round(time.time() * 1000))) % 2**32 # get current time --> used for random seed
	train_features, test_features, train_labels, test_labels = train_test_split(features, labels, test_size = 0.20, random_state = rnd_seed)

	if debug:
		print('Training Features Shape:', train_features.shape)
		print('Training Labels Shape:', train_labels.shape)
		print('Testing Features Shape:', test_features.shape)
		print('Testing Labels Shape:', test_labels.shape)

	# Instantiate model with num_trees decision trees and a maximum tree depth of max_depth
	rf = RandomForestClassifier(n_estimators = num_trees, max_depth = max_depth, random_state = rnd_seed, verbose=0)
	
	# Train the model on training data
	rf.fit(train_features, train_labels)

	if debug:
		# Use the forest's predict method on the test data
		predictions = rf.predict(test_features)
		f1score = f1_score(test_labels, predictions, average = None)
		f1_score_micro = f1_score(test_labels, predictions, average = 'micro')
		print("F1 score:", f1score)
		print("F1 score micro", f1_score_micro)

	return rf
