from sklearn.ensemble import RandomForestClassifier
from sklearn import tree

import numpy as np

# Return Depth of each node, maximum depth and whether each node is a leave
def getDepthNodes(n_nodes,children_left,children_right):
	node_depth = np.zeros(shape=n_nodes, dtype=np.int64)
	is_leaves = np.zeros(shape=n_nodes, dtype=bool)
	stack = [(0, -1)]  # seed is the root node id and its parent depth
	while len(stack) > 0:
		node_id, parent_depth = stack.pop()
		node_depth[node_id] = parent_depth + 1

		# If we have a test node
		if (children_left[node_id] != children_right[node_id]):
			stack.append((children_left[node_id], parent_depth + 1))
			stack.append((children_right[node_id], parent_depth + 1))
		else:
			is_leaves[node_id] = True
	return (node_depth,np.max(node_depth),is_leaves)

# Convert a list to string
def listToString(lst):
	s = ""
	for e in lst:
		s += str(e)+" "
	return s

# Return the table add entry given the parameter
def createTableEntry(name,action,left,right):
	return "table_add "+name+" "+action+" "+left+" => "+right

# Return the prediction along with the certainty of it
def computePredictionAndCertainty(classes,value):
	val_2D = (np.array([xi[0].flatten() for xi in value]))
	indexes_max = (np.argmax(val_2D,axis=1))
	certainty = []
	
	#Certainty has been multiplied by 1000 and casted to int in order
	#to be supported by P4. It may be changed in the future for more precision 

	for i in range(len(indexes_max)):
		certainty.append(int(val_2D[i][indexes_max[i]]/
			(val_2D[i][0]+val_2D[i][1])*1000))
	return (certainty,indexes_max)


#Encode a tree in match action table
#Return a list of all entries
def encodeTree(id,decisionTree,action_node,action_leave):
	tree = decisionTree.tree_
	n_nodes = tree.node_count
	children_left = tree.children_left
	children_right = tree.children_right
	feature = tree.feature
	threshold = []
	for t in tree.threshold:
		threshold.append(int(10*t))
	(certainty,prediction) = computePredictionAndCertainty(
		decisionTree.classes_,tree.value)

	(node_depth,depth,is_leaves) = getDepthNodes(n_nodes,children_left,children_right)
	#adding the root entry
	#just need to be set to something bigger than the total number of nodes
	entries = [createTableEntry("table"+str(id)+str(0),action_node+str(id),"256 0","0 "
		+str(feature[0])+" "+str(threshold[0]))]
	for d in range(depth):
		name = "table"+str(id)+str(d+1)
		for i in np.argwhere(node_depth==d).flatten():
			if not(is_leaves[i]):
				left=""
				right=""
				
				#True corresponds to 1 and False to 0


				#children of the left node
				name_action = ""
				cl = children_left[i]
				if(is_leaves[cl]):
					left = str(i) + " 0"
					right = str(prediction[cl])+" "+str(certainty[cl])
					name_action = action_leave+str(id)
				else:
					left = str(i) + " 0"
					right = str(cl)+" "+str(feature[cl])+" "+str(threshold[cl])
					name_action = action_node+str(id)
				entry_left = createTableEntry(name,name_action,left,right)
				entries.append(entry_left)

				#children of the right node
				cr = children_right[i]
				if(is_leaves[cr]):
					left = str(i) + " 1"
					right = str(prediction[cr])+" "+str(certainty[cr])
					name_action = action_leave+str(id)
				else:
					left = str(i) + " 1"
					right = str(cr)+" "+str(feature[cr])+" "+str(threshold[cr])
					name_action = action_node+str(id)
				entry_right = createTableEntry(name,name_action,left,right)
				entries.append(entry_right)
	return entries



# Encode a Random forest in match-action tables
# The type of forest is RandomForestClassifier
# Return a list of all entries
def encodeRandomForest(forest,action_node,action_leave):
	entries = []
	for i in range(len(forest.estimators_)):
		entries.extend(encodeTree(i+1,forest.estimators_[i],action_node,action_leave))
	return entries


def rf_encoding(rf):

	#Compute the corresponding table entries
	table_entries = encodeRandomForest(rf,"action_node_tree_","action_leaf_tree_")

	#Write it to a file text
	file = open("p4src/s1-commands.txt","w+")
	file.write("table_add forward_table forward 00:00:0a:00:00:01 => 1\ntable_add forward_table forward 00:00:0a:00:00:02 => 2\n\n")
	file.writelines(entry + '\n' for entry in table_entries)
	file.close() 