# Switch controller
# This controller is used to initialize custom hash functions and to reset register values

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
import socket, struct, os

crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]

class CMSController(object):

    def __init__(self, sw_name, reset_regs):

        self.topo = Topology(db="p4src/topology.db")
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)

        self.custom_calcs = self.controller.get_custom_crc_calcs()
        self.register_num =  len(self.custom_calcs)
        self.reset_regs = reset_regs
        self.registers = []

        self.init()

    def init(self):
        self.set_crc_custom_hashes()

        if self.reset_regs :
            self.reset_registers()

        self.read_registers()
        self.print_registers()

    def reset_registers(self):
        for i in range(self.register_num):
            self.controller.register_reset("flows{}".format(i))

    def flow_to_bytestream(self, flow):
        return socket.inet_aton(flow[0]) + socket.inet_aton(flow[1]) + struct.pack(">HHB",flow[2], flow[3], 6)

    def set_crc_custom_hashes(self):
        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i+=1

    def read_registers(self):
        self.registers = []
        for i in range(self.register_num):
            self.registers.append(self.controller.register_read("flows{}".format(i)))

    def print_registers(self):
        
        for r in self.registers:
            print(r)




if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', help="switch name to configure" , type=str, required=False, default="s1")
    parser.add_argument('--reset_regs',help='if present, controller will reset values in registers',action='store_true')
    args = parser.parse_args()

    controller = CMSController(args.sw, args.reset_regs)

