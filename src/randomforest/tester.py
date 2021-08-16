# This Python script is used to test how well the Random Forest model classify flows
# If the model works fine here, then it will be implemented in P4

from scapy.all import *
from scapy.utils import rdpcap
from os import listdir
import numpy as np
from sklearn.ensemble import RandomForestClassifier

def rf_tester(rf, debug=False):
	# TCP flags constants
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	ECE = 0x40

	dir_path = "pcap/"
	outputs = []

	sorted_dir = listdir(dir_path)
	sorted_dir.sort()

	for filename in sorted_dir:
		if debug:
			print()
			print(filename)

		pkts = rdpcap(dir_path + filename)

		# Features: 
			# Reminder: all the values must be integers...
			# Averages are computed as moving average...
		IAT_min = 0
		IAT_max = 0
		IAT_avg = 0
		duration = 0
		len_min = 0
		len_max = 0
		len_avg = 0
		len_total = 0
		pkt_counter = 0
		syn_count = 0
		ack_count = 0
		psh_count = 0
		fin_count = 0
		rst_count = 0
		ece_count = 0

		# utility variables
		past_ts = 0

		# Compute flow's features
		for i,pkt in enumerate(pkts):
			pkt_counter += 1

			# Packet length
			length = len(pkt[TCP].payload) if TCP in pkt else len(pkt[UDP].payload)
			if i == 0: 				# first packet of the flow
				len_min = length
				len_max = length
				len_avg = length
				len_total = length
			else:
				if length < len_min:
					len_min = length
				if length > len_max:
					len_max = length
				len_avg = int((len_avg + length)/2)	# P4 does not handle floats
				len_total += length

			# IAT & duration
			ts = int(pkt.time)
			IAT = ts - past_ts
			if i == 1:				# second packet of the flow
				IAT_min = IAT
				IAT_max = IAT
				IAT_avg = IAT
				duration += IAT
			elif i != 0:
				if IAT < IAT_min:
					IAT_min = IAT
				if IAT > IAT_max:
					IAT_max = IAT
				IAT_avg = int((IAT_avg + IAT)/2)
				duration += IAT

			# Flags
			if TCP in pkt:
				flags = pkt['TCP'].flags
				if flags & FIN:
				    fin_count += 1
				if flags & SYN:
				    syn_count += 1
				if flags & ACK:
					ack_count += 1
				if flags & ECE:
					ece_count += 1
				if flags & PSH:
					psh_count += 1
				if flags & RST:
					rst_count += 1

			past_ts = int(pkt.time)	# update the last packet timestamp

		# print features if needed for debugging
		if debug:
			print("IAT_min", IAT_min)
			print("IAT_max", IAT_max)
			print("IAT_avg", IAT_avg)
			print("duration", duration)
			print("len_min", len_min)
			print("len_max", len_max)
			print("len_avg", len_avg)
			print("len_total", len_total)
			print("pkt_counter", pkt_counter)
			print("syn_count", syn_count)
			print("ack_count", ack_count)
			print("psh_count", psh_count)
			print("fin_count", fin_count)
			print("rst_count", rst_count)
			print("ece_count", ece_count)

		features = np.array([[duration,
							IAT_avg,
							IAT_max,
							IAT_min,
							len_min,
							len_max,
							len_avg,
							fin_count,
							syn_count,
							rst_count,
							psh_count,
							ack_count,
							ece_count,
							len_total,
							pkt_counter]])

		prediction = rf.predict(features)
		if prediction[0][0] == 1 and prediction[0][1] == 0:
			if debug:
				print("BENIGN")
			outputs.append(1)
		elif prediction[0][0] == 0 and prediction[0][1] == 1:
			if debug:
				print("MALIGN")
			outputs.append(0)
		else:
			if debug:
				print("PREDICTION", prediction)

	return outputs