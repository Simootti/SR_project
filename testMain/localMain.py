from testMain.packet_classification import *
import random

ATTEMPTS = 100  # parameter used in collect_stats()

ANALYSIS_MODE = False

''' if ANALYSIS_MODE = True
Iteratively add rules for the classifier (starting from 2 rules and up to the maximum number of rules saved in
packetClassification file); for each iteration runs ATTEMPTS time the lookup_packet_classification with random values
of fields '''
def collect_stats():
    packetClass = PacketClassification()
    max_num_of_rules = len(packetClass.get_set_of_rules())
    for i in range(2, max_num_of_rules+1):  # how many rules in classifier
        packetClass.rules_handler(packetClass.get_set_of_rules(i))
        for lookups in range(0, ATTEMPTS):
            packetClass.run_lookup_packet_classification(random_ip(), random_ip(), random_proto(), random_port(),
                                                         random_port())

''' if ANALYSIS_MODE = False
 Instantiate the classifier and run some look_ups .
 Also the number of rules in classifier is changed at run_time writing:
                                        packetClass.rules_handler(packetClass.get_set_of_rules("number of rules")) '''
def rapidTest():
    packetClass = PacketClassification()
    packetClass.run_lookup_packet_classification("131.111.0.1", "129.169.0.1", "17", "0", "4")
    packetClass.run_lookup_packet_classification("129.169.0.1", "131.111.0.1", "6", "1234","10")
    packetClass.run_lookup_packet_classification("128.128.12.17", "128.128.0.1", "1", "65535","1")
    packetClass.run_lookup_packet_classification("128.128.0.1", "195.0.0.1", "1", "65535","10")
    packetClass.run_lookup_packet_classification("197.160.0.1", "192.170.0.1", "17", "25", "50")
    packetClass.run_lookup_packet_classification("192.169.0.2", "128.128.0.1", "6", "1050","55")
    packetClass.run_lookup_packet_classification("154.128.0.1", "195.0.0.2", "17", "10","11")
    packetClass.run_lookup_packet_classification("195.0.0.1", "154.128.0.2", "17", "1","2")
    packetClass.run_lookup_packet_classification("192.168.0.1", "192.169.0.1", "6", "32","44")
    packetClass.run_lookup_packet_classification("192.169.0.2", "197.160.0.128", "6", "67","21")
    packetClass.run_lookup_packet_classification("192.168.0.130", "195.0.0.1", "17", "1","10")
    packetClass.rules_handler(packetClass.get_set_of_rules(14))
    packetClass.run_lookup_packet_classification("0.0.0.1", "0.0.0.1", "6", "1001", "999")
    packetClass.run_lookup_packet_classification("192.170.0.11", "192.169.0.12", "6", "65535", "10")
    packetClass.run_lookup_packet_classification("197.160.0.60", "195.0.0.1", "17", "65535", "10")
    packetClass.rules_handler(packetClass.get_set_of_rules(1))
    packetClass.run_lookup_packet_classification("0.0.0.1", "0.0.0.1", "1", "65535", "1")


''' The following three methods are used to create random values for the different fields '''
def random_ip():
    # These ip addresses are possible ip addresses of our topology 3
    list_possible_ip =["195.0.0.1","195.0.0.2","195.0.0.13","195.0.1.1","195.0.1.11","195.0.0.1",
                       "196.0.0.64","197.60.60.1","197.160.0.1","192.168.0.1","192.170.0.1",
                       "192.169.0.1","192.170.1.1","192.169.69.69","162.50.0.1","162.50.1.1",
                       "162.50.0.1","162.50.0.2","129.169.0.1","131.111.0.1","172.175.0.1",
                       "192.169.3.3","192.169.3.4","192.169.3.33","192.170.1.3","192.170.1.23",
                       "192.170.0.23","192.160.0.1","192.160.0.2","192.160.0.3","192.160.0.4",
                       "128.128.0.1","128.128.0.2","128.128.0.3","154.128.0.1","154.128.0.2",
                       "154.128.0.16","154.128.0.69","154.128.0.111","172.175.0.2","172.175.0.3",
                       "172.175.0.69","131.111.0.2","131.111.0.3","131.111.0.56","129.169.0.2",
                       "129.169.0.3","129.169.0.4","129.169.0.44","129.169.0.69","192.169.3.1",
                       "192.169.3.2","192.169.3.3","192.169.4.1","192.169.4.2","192.168.4.1",
                       "192.170.2.1","192.170.2.2","192.170.2.3","192.160.1.12","192.160.1.13",
                       "192.169.2.1","192.168.2.10","192.168.0.234","192.168.0.88","192.169.0.88"]
    pseudo_random_ip = random.choice(list_possible_ip)
    return pseudo_random_ip


def random_port():
    return str(random.randrange(1, 2000))


def random_proto():
    list_possible_proto = [1,6,17]
    pseudo_random_proto = random.choice(list_possible_proto)
    return str(pseudo_random_proto)


'''main method'''
if __name__ == '__main__':
    if ANALYSIS_MODE:
        collect_stats()
    else:
        rapidTest()