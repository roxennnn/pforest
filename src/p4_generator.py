def generate_first_part():
    first_part = '''/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// Include
#include "include/headers.p4"
#include "include/parser.p4"

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {

    }
}

/************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   ******************
 ************************************************************************/

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    /*************************************************************************
     **************  R E G I S T E R  D E C L A R A T I O N  *****************
     *************************************************************************/

    // registers used to store the information about the flows
    // we use 2 registers in order to decrease errors
    register<bit<FLOW_ENTRY_WIDTH>>(BUCKET_LENGTH) flows0;
    register<bit<FLOW_ENTRY_WIDTH>>(BUCKET_LENGTH) flows1;

    /*************************************************************************
     ******** S T R U C T - B I T S T R I N G  C O N V E R S I O N ***********
     *************************************************************************/

    // Utility action to convert our flow_entry struct into a bitstring
    action struct2bitstring() {
        bit<FLOW_ENTRY_WIDTH> bitstring = meta.flow.features.ece_flag_count ++
                                        meta.flow.features.ack_flag_count ++
                                        meta.flow.features.psh_flag_count ++
                                        meta.flow.features.rst_flag_count ++
                                        meta.flow.features.syn_flag_count ++
                                        meta.flow.features.fin_flag_count ++
                                        meta.flow.features.packets_number ++
                                        meta.flow.features.total_packet_length ++
                                        meta.flow.features.packet_length_mean ++
                                        meta.flow.features.max_packet_length ++
                                        meta.flow.features.min_packet_length ++
                                        meta.flow.features.flow_IAT_min ++
                                        meta.flow.features.flow_IAT_max ++
                                        meta.flow.features.flow_IAT_mean ++
                                        meta.flow.features.flow_duration ++
                                        meta.flow.timestamp ++
                                        meta.flow.flow_id ++
                                        meta.flow.used;

        meta.bitstring = bitstring;
    }

    // Utility action to convert a bitstring into our flow_entry struct
    action bitstring2struct(){
        meta.flow.used = meta.bitstring[0:0];
        meta.flow.flow_id = meta.bitstring[32:1];
        meta.flow.timestamp = meta.bitstring[80:33];
        const int sindex = 81;
        meta.flow.features.flow_duration= meta.bitstring[sindex+IAT-1:sindex];
        const int sindex2 = sindex + IAT;
        meta.flow.features.flow_IAT_mean = meta.bitstring[sindex2 + IAT-1:sindex2];
        const int sindex3 = sindex2 + IAT;
        meta.flow.features.flow_IAT_max = meta.bitstring[sindex3 + IAT-1:sindex3];
        const int sindex4 = sindex3 + IAT;
        meta.flow.features.flow_IAT_min = meta.bitstring[sindex4 + IAT-1:sindex4];
        const int sindex5 = sindex4 + IAT;
        meta.flow.features.min_packet_length = meta.bitstring[sindex5 + PACKET_LENGTH-1:sindex5];
        const int sindex6 = sindex5 + PACKET_LENGTH;
        meta.flow.features.max_packet_length = meta.bitstring[sindex6 + PACKET_LENGTH-1:sindex6];
        const int sindex7 = sindex6 + PACKET_LENGTH;
        meta.flow.features.packet_length_mean = meta.bitstring[sindex7 + PACKET_LENGTH-1:sindex7];
        const int sindex8 = sindex7 + PACKET_LENGTH;
        meta.flow.features.total_packet_length = meta.bitstring[sindex8 + PACKET_LENGTH-1:sindex8];
        const int sindex9 = sindex8 + PACKET_LENGTH;
        meta.flow.features.packets_number = meta.bitstring[sindex9 + PACKET_NUM-1:sindex9];
        const int sindex10 = sindex9 + PACKET_NUM;
        meta.flow.features.fin_flag_count = meta.bitstring[sindex10 + FLAGS-1:sindex10];
        const int sindex11 = sindex10 + FLAGS;
        meta.flow.features.syn_flag_count = meta.bitstring[sindex11 + FLAGS-1:sindex11];
        const int sindex12 = sindex11 + FLAGS;
        meta.flow.features.rst_flag_count = meta.bitstring[sindex12 + FLAGS-1:sindex12];
        const int sindex13 = sindex12 + FLAGS;
        meta.flow.features.psh_flag_count = meta.bitstring[sindex13 + FLAGS-1:sindex13];
        const int sindex14 = sindex13 + FLAGS;
        meta.flow.features.ack_flag_count = meta.bitstring[sindex14 + FLAGS-1:sindex14];
        const int sindex15 = sindex14 + FLAGS;
        meta.flow.features.ece_flag_count = meta.bitstring[sindex15 + FLAGS-1:sindex15];
    }

    /*************************************************************************
     ********************  F E A T U R E  A C T I O N S   ********************
     *************************************************************************/

    /*************************************************************************
     **************  F E A T U R E  I N I T I A L I Z A T I O N  *************
     *************************************************************************/
    
    action init_flow_features() {
        meta.flow.features.flow_duration = 0;

        // IAT
        meta.flow.features.flow_IAT_mean = 0;
        meta.flow.features.flow_IAT_min = 0;
        meta.flow.features.flow_IAT_max = 0;

        // packet_length
        // We just want the payload: hence, we subtracts the headers bytes
        bit<PACKET_LENGTH> packet_length = standard_metadata.packet_length - ETHERNET_LENGTH - IPV4_LENGTH;
        if (hdr.ipv4.protocol == TYPE_TCP) {
            packet_length = packet_length - ((bit<PACKET_LENGTH>)hdr.tcp.dataOffset*4);
        } else {
            packet_length = packet_length - UDP_LENGTH;
        }
        meta.flow.features.min_packet_length = packet_length;
        meta.flow.features.max_packet_length = packet_length;
        meta.flow.features.packet_length_mean = packet_length;
        meta.flow.features.total_packet_length = packet_length;

        // TCP Flag counts
        if (hdr.ipv4.protocol == TYPE_TCP) {
            if (hdr.tcp.fin == 1) {
                meta.flow.features.fin_flag_count = 1;
            } else {
                meta.flow.features.fin_flag_count = 0;
            }

            if (hdr.tcp.syn == 1) {
                meta.flow.features.syn_flag_count = 1;
            } else {
                meta.flow.features.syn_flag_count = 0;
            }

            if (hdr.tcp.rst == 1) {
                meta.flow.features.rst_flag_count = 1;
            } else {
                meta.flow.features.rst_flag_count = 0;
            }

            if (hdr.tcp.psh == 1) {
                meta.flow.features.psh_flag_count = 1;
            } else {
                meta.flow.features.psh_flag_count = 0;
            }

            if (hdr.tcp.ack == 1) {
                meta.flow.features.ack_flag_count = 1;
            } else {
                meta.flow.features.ack_flag_count = 0;
            }

            if (hdr.tcp.ece == 1) {
                meta.flow.features.ece_flag_count = 1;
            } else {
                meta.flow.features.ece_flag_count = 0;
            }
        } else {
            meta.flow.features.fin_flag_count = 0;
            meta.flow.features.syn_flag_count = 0;
            meta.flow.features.rst_flag_count = 0;
            meta.flow.features.ack_flag_count = 0;
            meta.flow.features.psh_flag_count = 0;
            meta.flow.features.ece_flag_count = 0;
        }

        // packet number
        meta.flow.features.packets_number = 1;
    }

    action init_flow_entry() {
        meta.flow.used = 1;
        meta.flow.flow_id = meta.current_flow_id;
        init_flow_features();
        meta.flow.timestamp = meta.current_timestamp;
    }

    /*************************************************************************
     *******************  F E A T U R E   U P D A T E  ***********************
     *************************************************************************/

    action update_flow_features() {
        // Packet number
        meta.flow.features.packets_number = meta.flow.features.packets_number + 1;

        // Packet length updates
        // We just want the payload: hence, we subtracts the headers bytes
        bit<PACKET_LENGTH> packet_length = standard_metadata.packet_length - ETHERNET_LENGTH - IPV4_LENGTH;
        if (hdr.ipv4.protocol == TYPE_TCP) {
            packet_length = packet_length - ((bit<PACKET_LENGTH>)hdr.tcp.dataOffset*4);
        } else {
            packet_length = packet_length - UDP_LENGTH;
        }
        if(packet_length > meta.flow.features.max_packet_length){
            meta.flow.features.max_packet_length = packet_length;
        }
        if(packet_length < meta.flow.features.min_packet_length){
            meta.flow.features.min_packet_length = packet_length;
        }
        meta.flow.features.total_packet_length = meta.flow.features.total_packet_length + packet_length;

        bit<PACKET_LENGTH> old_length_mean = meta.flow.features.packet_length_mean;
        meta.flow.features.packet_length_mean = (old_length_mean + packet_length) >> 1;   // moving average

        // IAT updates
        bit<IAT> IAT_value = (bit<IAT>) (meta.current_timestamp - meta.flow.timestamp);
        if (IAT_value > meta.flow.features.flow_IAT_max){
            meta.flow.features.flow_IAT_max = IAT_value;
        }
        if (meta.flow.features.packets_number == 2) {
            meta.flow.features.flow_IAT_min = IAT_value;
        } else {
            if (IAT_value < meta.flow.features.flow_IAT_min){
                meta.flow.features.flow_IAT_min = IAT_value;
            }
        }
        bit<IAT> old_IAT_mean = meta.flow.features.flow_IAT_mean;
        meta.flow.features.flow_IAT_mean = (old_IAT_mean + IAT_value) >> 1;     // moving average

        meta.flow.features.flow_duration = meta.flow.features.flow_duration + IAT_value;

        // TCP Flag counts
        if (hdr.ipv4.protocol == TYPE_TCP) {
            if (hdr.tcp.fin == 1) {
                meta.flow.features.fin_flag_count =  meta.flow.features.fin_flag_count + 1;
            } 

            if (hdr.tcp.syn == 1) {
                meta.flow.features.syn_flag_count =  meta.flow.features.syn_flag_count + 1;
            } 

            if (hdr.tcp.rst == 1) {
                meta.flow.features.rst_flag_count =  meta.flow.features.rst_flag_count + 1;
            } 

            if (hdr.tcp.psh == 1) {
                meta.flow.features.psh_flag_count =  meta.flow.features.psh_flag_count + 1;
            } 

            if (hdr.tcp.ack == 1) {
                meta.flow.features.ack_flag_count =  meta.flow.features.ack_flag_count + 1;
            } 

            if (hdr.tcp.ece == 1) {
                meta.flow.features.ece_flag_count =  meta.flow.features.ece_flag_count + 1;
            } 
        }
    }

    action update_flow_entry(){
        update_flow_features();
        meta.flow.timestamp = meta.current_timestamp;
    }

    /*************************************************************************
     **************************  T R E E  T A B L E S  ***********************
     *************************************************************************/

    // Actions and Match-Action table according to the classification
    '''
    return first_part

#generate the two actions required for the classification
def generate_actions(id_tree):
    action_str = '''
    // Action executed when the next_node is a leaf
    action action_leaf_tree_%s(bit<1>label,bit<16>certainty) {
        meta.classification_variables.label_tree%s = label;
        meta.classification_variables.certainty_tree%s = certainty;
    }

    // Action executed when the next_node is not a leaf
    action action_node_tree_%s(bit<16> next_node,bit<4> feature_to_compare,bit<32> threshold) {
        // Store node and beq then apply the classication table again 
        meta.classification_variables.current_node_tree%s = next_node;
        bit<32> feature_used;
        
        if (feature_to_compare == 0) {
            feature_used = (bit<32>)meta.flow.features.flow_duration;
        } else if (feature_to_compare == 1) {
            feature_used = (bit<32>)meta.flow.features.flow_IAT_mean;
        } else if (feature_to_compare == 2) {
            feature_used = (bit<32>)meta.flow.features.flow_IAT_max;
        } else if (feature_to_compare == 3) {
            feature_used = (bit<32>)meta.flow.features.flow_IAT_min;
        } else if (feature_to_compare == 4) {
            feature_used = (bit<32>)meta.flow.features.min_packet_length;
        } else if (feature_to_compare == 5) {
            feature_used = (bit<32>)meta.flow.features.max_packet_length;
        } else if (feature_to_compare == 6) {
            feature_used = (bit<32>)meta.flow.features.packet_length_mean;
        } else if (feature_to_compare == 7) {
            feature_used = (bit<32>)meta.flow.features.fin_flag_count;
        } else if (feature_to_compare == 8) {
            feature_used = (bit<32>)meta.flow.features.syn_flag_count;
        } else if (feature_to_compare == 9) {
            feature_used = (bit<32>)meta.flow.features.rst_flag_count;
        } else if (feature_to_compare == 10) {
            feature_used = (bit<32>)meta.flow.features.psh_flag_count;
        } else if (feature_to_compare == 11) {
            feature_used = (bit<32>)meta.flow.features.ack_flag_count;
        } else if (feature_to_compare == 12) {
            feature_used = (bit<32>)meta.flow.features.ece_flag_count;
        } else if (feature_to_compare == 13) {
            feature_used = (bit<32>)meta.flow.features.total_packet_length;
        } else { 
            feature_used = (bit<32>)meta.flow.features.packets_number;
        }

        // Compare feature in feature_to_compare with threshold
        if ((feature_used*10) > threshold) {
            meta.classification_variables.bigger_than_threshold_tree%s = 1;
        }
        else {
            meta.classification_variables.bigger_than_threshold_tree%s = 0;
        }
    }
    ''' %(id_tree,id_tree,id_tree,id_tree,id_tree,id_tree,id_tree,)
    return action_str

#Generate the match action tables
def generate_match_action_tables(id_tree,depth):
    table_str = '''
    table table%s%s {
        key = {
            meta.classification_variables.current_node_tree%s: exact;
            meta.classification_variables.bigger_than_threshold_tree%s: exact;
        }
        actions = {
            action_node_tree_%s;
            action_leaf_tree_%s;
            NoAction;
        }
        //Set a different size depending to to size of trees
        size = %s;
        default_action = NoAction;
    }
    '''
    total_table_str = ""
    for  i in range(depth+1):
        total_table_str += table_str%(id_tree,i,id_tree,id_tree,id_tree,id_tree,2**(i),)
    return total_table_str

def generate_middle_part():
    middle_part = '''
    /*************************************************************************
     ***********************  F O R W A R D I N G  ***************************
     *************************************************************************/

    // used to allow communication between the 2 hosts
    action forward(bit<9> egress_port) {     
        standard_metadata.egress_spec = egress_port;
    }

    // default behaviour: send every packet (not from h2) to h2 
    // (in this way we can better check our classification results)
    action force_forward() {                
        standard_metadata.egress_spec = (bit<9>)2;
    }

    table forward_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            force_forward; // default
        }
        size = 256;
        default_action = force_forward;
    }

    // Very useful table use for debugging: print in the logs feature values
    table print_debug {
        key = {
            meta.flow.features.flow_duration: exact;
            meta.flow.features.flow_IAT_mean: exact;
            meta.flow.features.flow_IAT_max: exact;
            meta.flow.features.flow_IAT_min: exact;
            meta.flow.features.min_packet_length: exact;
            meta.flow.features.max_packet_length: exact;
            meta.flow.features.packet_length_mean: exact;
            meta.flow.features.total_packet_length: exact;
            meta.flow.features.packets_number: exact;
            meta.flow.features.fin_flag_count: exact;
            meta.flow.features.syn_flag_count: exact;
            meta.flow.features.rst_flag_count: exact;
            meta.flow.features.psh_flag_count: exact;
            meta.flow.features.ack_flag_count: exact;
            meta.flow.features.ece_flag_count: exact;
        }
        actions = {
            NoAction;
        }
        size = 4;
        default_action = NoAction;
    }

    /*************************************************************************
     ***********************  A P P L Y  L O G I C  **************************
     *************************************************************************/

    apply {
        // Enable forwarding in the switch
        forward_table.apply();

        // Set flow ID
        // 1st hash to compute the flow ID 
        hash(meta.current_flow_id,
            HashAlgorithm.crc32,
            (bit<16>)0,
            {hdr.ipv4.srcAddr,hdr.ipv4.dstAddr,hdr.tcp.srcPort,hdr.tcp.dstPort, hdr.ipv4.protocol},
            (bit<32>)4294967295); 

        // Set current timestamp
        meta.current_timestamp = standard_metadata.ingress_global_timestamp;

        /*******************************************************************
         **************** I N D E X  C A L C U L A T I O N S ***************
         *******************************************************************/

        // hash0
        hash(meta.index_table0,
            HashAlgorithm.crc32_custom,
            (bit<16>)0,
            {meta.current_flow_id},
            (bit<32>)BUCKET_LENGTH);

        // hash1
        hash(meta.index_table1,
            HashAlgorithm.crc32_custom,
            (bit<16>)0,
            {meta.current_flow_id},
            (bit<32>)BUCKET_LENGTH);

        // (.... continue with next hashes if needed)

        // Finding phase 
        meta.found_entry = 0;
        meta.usable0 = 0;
        meta.usable1 = 0;

        // Find a match: find existing flow: 

        // For each register : read flow contained at index and check whether match
        if(meta.found_entry == 0){
            // read the flow entry
            flows0.read(meta.bitstring,(bit<32>)meta.index_table0);
            bitstring2struct();

            // check if entry is used already
            if(meta.flow.used == 1) {
                // check if flow id matches
                if(meta.flow.flow_id == meta.current_flow_id){
                    // match found => update the features and tag flow as found
                    meta.found_entry = 1;
                    update_flow_entry();
                    struct2bitstring();
                    flows0.write((bit<32>)meta.index_table0,meta.bitstring);
                } else {
                    // no match, check if entry is still usable
                    if(meta.current_timestamp - meta.flow.timestamp > TIMEOUT_VALUE){
                        meta.usable0 = 1;
                    }
                }
            } else {
                // entry is not used : mark it as usable
                meta.usable0 = 1;
            }
        }

        // If no match found continue to next register:

        if(meta.found_entry == 0){
            // read the flow entry
            flows1.read(meta.bitstring,(bit<32>)meta.index_table1);
            bitstring2struct();

            // check if entry is used already
            if(meta.flow.used == 1) {
                // check if flow id matches
                if(meta.flow.flow_id == meta.current_flow_id){ // same here, we should update all of them accordingly: if here we have the same flowID, in all of the other tables we should have matching flowID!
                    // match found => update the features and tag flow as found
                    meta.found_entry = 1;
                    update_flow_entry();
                    struct2bitstring();
                    flows1.write((bit<32>)meta.index_table1,meta.bitstring);
                } else {
                    // no match, check if entry is still usable
                    if(meta.current_timestamp - meta.flow.timestamp > TIMEOUT_VALUE){
                        meta.usable1 = 1;
                    }
                }
            } else {
                // entry is not used : mark it as usable
                meta.usable1 = 1;
            }
        }

        // Continue for other registers if needed.... (so far: 2)


        // If no match, find a usable slot:

        // Check if the index is usable
        if(meta.found_entry == 0 && meta.usable0 == 1){
            meta.found_entry = 1;
            init_flow_entry();
            struct2bitstring();
            flows0.write((bit<32>)meta.index_table0,meta.bitstring);
        }

        if(meta.found_entry == 0 && meta.usable1 == 1){
            meta.found_entry = 1;
            init_flow_entry();
            struct2bitstring();
            flows1.write((bit<32>)meta.index_table1,meta.bitstring);
        }

        // Add here for any other register.... (so far: 2)


        /******************************************************************
         *********** C L A S S I F I C A T I O N  L O G I C ***************
         ******************************************************************/
    '''
    return middle_part

def generate_variable_initialization(number_of_trees):
    #Corresponds to the * of the first node, 
    # must be bigger than the total number of nodes
    magic_variable = 256
    varInit_str = ""
    for i in range(number_of_trees):
        varInit_str += '''
        meta.classification_variables.current_node_tree%s = %s;
        meta.classification_variables.bigger_than_threshold_tree%s = 0;
        ''' % (i+1,magic_variable,i+1,)
    return varInit_str + "\n"

def generate_applies(number_of_trees,depth):
    applies_str = ""
    for j in range(number_of_trees):
        for i in range(depth):
            applies_str += "\t"*(i+1*(i+1)+1)+"switch(table%s%s.apply().action_run){\n"%(j+1,i,)
            applies_str += "\t"*(i+1*(i+2)+1)+"action_node_tree_%s: {\n" % (j+1,)

        applies_str += "\t"*(2*i+2)+"\t\ttable%s%s.apply();\n" % (j+1,depth)
        for i in range(2*depth):
            # print(i)
            applies_str += "\t"*((2*depth)-i+1)+"}\n"
        applies_str += "\n"
    return applies_str

def generate_majority_voting(number_of_trees):
    str_majority_voting = "\t\t// Majority voting\n"
    for i in range(number_of_trees):
        str_majority_voting += "\t\tbit<1> label%s = meta.classification_variables.label_tree%s;\n"%(i+1,i+1,)
    str_majority_voting += "\n"
    for i in range(number_of_trees):
        str_majority_voting += "\t\tbit<4> l%s = (bit<4>)label%s;\n"%(i+1,i+1,)

    str_majority_voting += "\n\t\t// Classification result\n"
    str_majority_voting += "\t\tbit<1> result;\n"
    str_majority_voting +="\t\tif (("
    for i in range(number_of_trees):
        str_majority_voting += "l%s"%(i+1)
        if not(i == (number_of_trees-1)):
            str_majority_voting+="+"
    str_majority_voting += ") > %s) {"%(number_of_trees//2,)
    str_majority_voting += '''
        \tresult = 1;
        } else {
            result = 0;
        }
    '''
    return str_majority_voting

def generate_total_certainty_calculation(number_of_trees, certainty):
    str_total_certainty = '''
        // Compute the overall certainty of the current classification
        bit<32> wantedCertainty = %s*%s;
        bit<1> isAboveThreshold;
        bit<32> total_certainty=0;
        ''' % (certainty,number_of_trees,)
    for i in range(number_of_trees):
        str_total_certainty += '''
        if(label%s == result) {
            total_certainty = total_certainty + (bit<32>)meta.classification_variables.certainty_tree%s;
        } else {
            total_certainty = total_certainty + (bit<32>)(1000-meta.classification_variables.certainty_tree%s);
        }
        '''%(i+1,i+1,i+1,)

    str_total_certainty += '''
        // If the total certainty is greather than threshold value, then confirm the classification
        if (total_certainty > wantedCertainty) {
            isAboveThreshold = 1;
        } else {
            isAboveThreshold = 0;
        }

        // Write the classification results on the source mac address
        if (isAboveThreshold == 1) {
            if (result == 0) {  // Malicious flow
                hdr.ethernet.srcAddr = 0xDEADDEADC0DE;
            } else {            // Benign flow
                hdr.ethernet.srcAddr = 0xC001C001C001;
            }
        }
    '''
    return str_total_certainty

def generate_last_part():
    last_part = '''
        // Apply debug table
        print_debug.apply();
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {

    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
 ***************************  S W I T C H  *******************************
 *************************************************************************/

// Switch architecture
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
    '''
    return last_part


def generate_first_part_header():
    first_part = '''// In this code, constants, headers and other data structures are defined.
// This code will be included in our pforest.p4 code

// Usefult constants
#define BUCKET_LENGTH 16
#define FLOW_ENTRY_WIDTH 369
#define FLOW_ID_BIT_WIDTH 32
#define TIMEOUT_VALUE 42

// Header bit lengths (used to compute payload length)
// TCP is not present because we used the 'dataOffset' field in TCP header
#define ETHERNET_LENGTH 14
#define IPV4_LENGTH 20
#define UDP_LENGTH 8

// Feature dimensions
#define IAT 24
#define PACKET_LENGTH 32
#define FLAGS 8
#define PACKET_NUM 16

// Constants used in the parser
const bit<16> TYPE_IPV4 = 0x800;  
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<313> bitstring_t;

/*************************************************************************
 *********************** H E A D E R S  **********************************
 *************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

/*************************************************************************
 ********************** U T I L  S T R U C T S ***************************
 *************************************************************************/

// struct to store features data
typedef struct features {
    bit<IAT> flow_duration;
    bit<IAT> flow_IAT_mean;
    bit<IAT> flow_IAT_max;
    bit<IAT> flow_IAT_min;
    bit<PACKET_LENGTH> min_packet_length;
    bit<PACKET_LENGTH> max_packet_length;
    bit<PACKET_LENGTH> packet_length_mean;
    bit<PACKET_LENGTH> total_packet_length;
    bit<PACKET_NUM> packets_number;
    bit<FLAGS> fin_flag_count;
    bit<FLAGS> syn_flag_count;
    bit<FLAGS> rst_flag_count;
    bit<FLAGS> psh_flag_count;
    bit<FLAGS> ack_flag_count;
    bit<FLAGS> ece_flag_count;
} features_t;

// struct for saving flow data
typedef struct flow_entry{
    bit<1> used;
    bit<32> flow_id;
    bit<48> timestamp; 
    features_t features;
} flow_entry_t;
'''
    return first_part

def generate_classification_variables_struct(num_trees):
    variables1 = '''
    bit<16> current_node_tree%s;
    bit<1> bigger_than_threshold_tree%s;'''
    
    variables2 = '''
    bit<1>label_tree%s;
    bit<16>certainty_tree%s;'''
    
    struct = '''
// struct for handling classification variables
typedef struct classification_variables {
    // Current nodes for each tree"'''

    for i in range(num_trees):
        struct += variables1%(i+1,i+1,)
    struct += '\n\n\t// Label and certainty for each tree'
    for i in range(num_trees):
        struct += variables2%(i+1,i+1,)
    struct += "\n} classification_variables_t;"

    return struct

def generate_last_part_header():
    return '''\n
// metadata struct
struct metadata {
    bit<4> index_table0;
    bit<4> index_table1;
    bit<1> usable0;
    bit<1> usable1;
    flow_entry_t flow;
    bit<48> current_timestamp;
    bit<32> current_flow_id;
    bit<1> found_entry;
    classification_variables_t classification_variables;
    bit<FLOW_ENTRY_WIDTH> bitstring; 
}'''

#Generate the P4 code of pforest.p4
def generate_pforest(num_trees, max_depth, certainty):
    generated_code = ""
    ##Generate all the actions
    generated_code += generate_first_part()
    for i in range(num_trees):
        generated_code += generate_actions(i+1)
    #Generate all the tables
    generated_code += "\n\t// Classification tables"
    for i in range(num_trees):
        generated_code += generate_match_action_tables(i+1,max_depth)
    generated_code += generate_middle_part()
    generated_code += generate_variable_initialization(num_trees)
    generated_code += generate_applies(num_trees,max_depth)
    generated_code += generate_majority_voting(num_trees)
    generated_code += generate_total_certainty_calculation(num_trees, certainty)
    generated_code += generate_last_part()

    # Save the generated code
    file = open("p4src/pforest.p4","w+") 
    file.write(generated_code)
    file.close() 

def generate_headers(num_trees):
    generated_code = ""
    generated_code += generate_first_part_header()
    generated_code += generate_classification_variables_struct(num_trees)
    generated_code += generate_last_part_header()
    # Save the generated code
    file = open("p4src/include/headers.p4","w+") 
    file.write(generated_code)
    file.close() 

def generate_parser():
    generated_code = '''// In this code, the parser and the deparser of our switch are implemented
// This code will be included in our pforest.p4 code

/*************************************************************************
 ************************* P A R S E R  **********************************
 *************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        // parse packet length for features
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP : parse_tcp;
            TYPE_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);

        //Only emitted if valid
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}'''
    # Save the generated code
    file = open("p4src/include/parser.p4","w+") 
    file.write(generated_code)
    file.close() 
