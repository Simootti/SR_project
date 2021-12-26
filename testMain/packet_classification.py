from precomputation_engine import *
from collections import OrderedDict
import time
import sys
#from random import shuffle
# Packet Classification parameters:
SRC_IP = 0
DST_IP = 1
PROTO = 2
SPORT = 3
DPORT = 4
ACTION = 5

# choice of algorithm
LINEAR = "Linear"
CROSSPRODUCTING_ALGORITHM = "Cross_Producting"
BITMAP_INTERSECTION = "Bitmap"
ALGORITHM_SELECTED = LINEAR

# parameters for performance analysis: in order to reduce overhead calculus, we suggest no more than one true
TOTAL_LOOKUP_TIME_EVALUATION = False       # algorithm + num_of_rules + time_interval
LOOKUP_ONE_FIELD_EVALUATION = False        # algorithm + num_of_rules + field + iterations_done + time_interval
TIME_FOR_AND_BITMAP_EVALUATION = False     # algorithm selected + num_of_rules + interval
MEMORY_EVALUATION = False                  # algorithm + num_of_rules + elements_added + memory used
ALGORITHMS_CREATION_EVALUATION = False     # algorithm + num_of_rules + time_interval

FILENAME_TOTAL_LOOKUP = "TOTAL_LOOKUPstats.txt"
FILENAME_LOOKUP_ONE_FIELD = "ONE_FIELD_LOOKUPstats.txt"
FILENAME_MEMORY_USAGE = "MEMORY_USAGEstats.txt"
FILENAME_ALGORITHMS_CREATION = "ALGORITHMCREATIONstats.txt"
FILENAME_BITMAP_TIME = "BITMAP_TIMEstats.txt"

# Other useful parameters
BINARYSEARCH = True # Enable or disable the binary search in lookup_onefield method


class PacketClassification:

    def __init__(self):     # Initialization
        # Here we save the rules
        self.array_of_rules = OrderedDict()
        # Here we saves numerical lines(field by field: what rules match each range?): Used by geometric algorithms
        self.numerical_lines = None
        # Here we save the multidimensional matrix of cross producting algorithm
        self.table = None
        # Here we save bitmaps for bitmap algorithm
        self.bitmap_lines = None
        # rules_handler initialise the array_of_rules and if needed creates matrix for crossproducting or vectors for bitmap
        # by default we instantiate the classifier with all the rules stored
        rules = self.get_set_of_rules()
        self.rules_handler(rules)

    ''' Method that returns the collection of the rules we have added.
        It' s possible to ask only for the first "num_of_rules" rules '''
    @staticmethod
    def get_set_of_rules(num_of_rules=0):  # "0" means default: all the rules will be added
        # list of rules ordered by priority
        list_of_rules = []
        list_of_rules.append(["195.0.0.1", "128.128.0.1", "6", "12-100", "1234", "allow"])                         # r01
        list_of_rules.append(["128.128.0.0/16", "195.0.0.1", "6", "1234", "*", "allow"])                           # r02
        list_of_rules.append(["128.128.12.0/24", "128.128.0.1", "1", "*", "*", "allow"])                           # r03
        list_of_rules.append(["128.128.0.1", "195.0.0.1", "1", "*", "*", "allow"])                                 # r04
        list_of_rules.append(["197.160.0.1", "192.170.0.1", "17", "25", "50", "allow"])                            # r05
        list_of_rules.append(["192.169.0.0/24", "128.128.0.1", "6", "1000-2000", "50-1000", "allow"])              # r06
        list_of_rules.append(["154.128.0.1", "195.0.0.2", "17", "10", "*", "allow"])                               # r07
        list_of_rules.append(["195.0.0.0/24", "154.128.0.0/24", "17", "*", "*", "allow"])                          # r08
        list_of_rules.append(["192.168.0.1", "192.169.0.1", "6", "32", "44", "allow"])                             # r09
        list_of_rules.append(["*", "197.160.0.0/24", "*", "67", "21-22", "allow"])                                 # r10
        list_of_rules.append(["192.168.0.0/24", "*", "17", "1", "*", "allow"])                                     # r11
        list_of_rules.append(["*", "*", "6", "1001", "999", "allow"])                                              # r12
        list_of_rules.append(["192.170.0.0/24", "192.169.0.0/24", "6", "*", "*", "allow"])                         # r13
        list_of_rules.append(["195.0.0.1", "128.128.0.1", "1", "*", "*", "allow"])                                 # r14
        list_of_rules.append(["192.160.0.0/16", "192.160.0.0/16", "1", "*", "*", "allow"])                         # r15
        list_of_rules.append(["195.0.0.0/8", "192.160.0.0/16", "6", "*", "200-500", "allow"])                      # r16
        list_of_rules.append(["162.50.0.0/16", "192.0.0.0/8", "17", "*", "*", "allow"])                            # r17
        list_of_rules.append(["192.0.0.0/8", "128.0.0.0/8", "17", "*", "100-700", "allow"])                        # r18
        list_of_rules.append(["128.0.0.0/8", "192.0.0.0/8", "1", "*", "*", "allow"])                               # r19
        list_of_rules.append(["192.160.0.0/16", "128.0.0.0/8", "1", "*", "*", "allow"])                            # r20
        list_of_rules.append(["172.175.0.0/24", "128.0.0.0/8", "6", "*", "1-1500", "allow"])                       # r21
        list_of_rules.append(["131.111.0.0/24", "195.0.0.0/8", "6", "5-200", "*", "allow"])                        # r22
        list_of_rules.append(["192.168.0.0/16", "195.0.0.0/24", "17", "*", "*", "allow"])                          # r23
        list_of_rules.append(["192.170.0.0/24", "128.0.0.0/8", "1", "*", "*", "allow"])                            # r24
        list_of_rules.append(["172.175.0.0/24", "131.111.0.0/8", "1", "*", "*", "allow"])                          # r25
        list_of_rules.append(["195.0.0.0/8", "192.168.0.0/24", "1", "*", "*", "allow"])                            # r26
        list_of_rules.append(["192.168.0.0/24", "195.0.0.0/8", "1", "*", "*", "allow"])                            # r27
        list_of_rules.append(["131.111.0.0/24", "129.169.0.0/24", "1", "*", "*", "allow"])                         # r28
        list_of_rules.append(["129.169.0.0/24", "131.111.0.0/24", "1", "*", "*", "allow"])                         # r29
        # [DEFAULT_RULE] = ["*", "*", "*", "*", "*", "deny"] added below

        # uncomment if you want to shuffle rules (also import shuffle from random library)
        #shuffle(list_of_rules)

        # instantiating the dictionary
        rules = OrderedDict()
        ended = False
        counter = 1
        while not ended and len(list_of_rules) >= 1:
            # we save the rules staring from "r01", then "r02" , "r03" and so on
            rules["r"+format(counter,'02d')] = list_of_rules[counter-1]  #'02d' means that "1" becomes "01"
            if counter == num_of_rules or counter == len(list_of_rules): # stop (if default, num_of_rules== 0 we go on until end of rules)
                ended = True
            else: counter +=1 # continue
        # adding default rule
        rules["r99"] = ["*", "*", "*", "*", "*", "deny"]
        return rules

    ''' Here we initialize or modify the classifier with the rules passed with "dictionary_of_rules" argument.
    # If the algorithm selected is bitmap or cross-producing runs pre-computation and then creates cross-product
    # table or bitmap arrays. '''
    def rules_handler(self, dictionary_of_rules):
        # initialization or re-initialization
        self.array_of_rules = dictionary_of_rules
        self.table = None
        self.bitmap_lines = None
        # various performance evaluation parameterers
        starting_time = 0
        memory_used = 0
        elements_added = 0
        if ALGORITHM_SELECTED is CROSSPRODUCTING_ALGORITHM or BITMAP_INTERSECTION:
            if ALGORITHMS_CREATION_EVALUATION: # performance evaluation
                starting_time = time.clock()
            try: # using the array_of_rules, tables for packets classification are now created
                precompute = PrecomputationEngine(self.array_of_rules)
                self.numerical_lines = precompute.geometric_precompute()
                if ALGORITHM_SELECTED == CROSSPRODUCTING_ALGORITHM:
                    self.table, elements_added, memory_used = self.crossproducting_table()
                elif ALGORITHM_SELECTED == BITMAP_INTERSECTION:
                    self.bitmap_lines, elements_added, memory_used  = self.bitmap()

                # performance evaluation
                if ALGORITHMS_CREATION_EVALUATION and starting_time is not None:
                    ending_time = time.clock()
                    interval = (ending_time - starting_time) * (10**3)  # in ms
                    self.__algorithms_time_stats(interval)
                if MEMORY_EVALUATION and ALGORITHM_SELECTED != LINEAR:
                    self.__memory_use_stats(elements_added, memory_used)

            # with the following we make sure no wrong rule is inserted
            except IllegalRuleException as e:  # IllegalRuleException defined in precomputation_engine.py
                wrong_rule = self.array_of_rules[e.name_of_rule]
                print(" error in rule " + e.name_of_rule + " " + str(wrong_rule))
                # eliminating rule and restarting algorithm
                self.array_of_rules = self.delete_rule(self.array_of_rules, e.name_of_rule)
                self.rules_handler(self.array_of_rules)
        # ending method
        print("--- Packet Classification ready: "+ ALGORITHM_SELECTED +" with "+ str(len(self.array_of_rules)) + " rules.")

    ''' Deletes the rule labelled as "name_of_rule" from the dictionary rules. It is used to eliminate wrong rules.
     The rules with lower priority shift one position up. '''
    @staticmethod
    def delete_rule(rules, name_of_rule):
        keys_list = rules.keys()
        values_list = rules.values()
        index = keys_list.index(name_of_rule)  # index of rule to delete
        values_list.pop(index)
        if len(keys_list) > 1 and index < len(keys_list):
            keys_list.pop(len(keys_list)-2)  # eliminate the last element that is not default rule!
        else:
            keys_list.pop(0)
        rules = OrderedDict()  # re-initializing
        for key in keys_list:  # in rules we create the corrected dictionary
            index = keys_list.index(key)
            rules[key] = values_list[index]
        return rules

    ###################################################################################################################
    ''' Geometric Algorithms creation '''

    ''' Instantiation of cross_producting table: a penta-dimensional matrix '''
    def crossproducting_table(self):
        # we find the maximum number of ranges possible for a field and we use that value to allocate memory for
        # a penta-dimensional array
        max_length = 0
        for field in range(SRC_IP, DPORT + 1):
            if len(self.numerical_lines[field]) > max_length:
                max_length = len(self.numerical_lines[field])
        # memory allocation for a penta-dimensional array
        table = [[[[[0 for i in range(max_length)] for j in range(max_length)] for ii in range(max_length)] for jj in
                  range(max_length)] for kk in range(max_length)]
        memory_used = 0  # for performance evaluation
        elements_added = 0  # for performance evaluation

        # all the possible SRC_IP,DST_IP,PROTO, DPORT, SPORT combinations are now added in the multi-dimensional array:
        # we need to iterate in this penta-dimensional matrix
        count1 = 0  # count1,2,3,4,5 are counter to access each position of the multi dimensional matrix
        for key1, values1 in self.numerical_lines[SRC_IP].items():
            count2 = 0
            for key2, values2 in self.numerical_lines[DST_IP].items():
                count3 = 0
                for key3, values3 in self.numerical_lines[PROTO].items():
                    count4 = 0
                    for key4, values4 in self.numerical_lines[SPORT].items():
                        count5 = 0
                        for key5, values5 in self.numerical_lines[DPORT].items():
                            # for the element [SRCIP][DSTIP][PROTO][SPORT][DPORT]: we find all the rules matching
                            temp = list(set(values1).intersection(values2))  # intersecting the rules
                            temp = list(set(temp).intersection(values3))
                            temp = list(set(temp).intersection(values4))
                            temp = list(set(temp).intersection(values5))
                            temp.sort()                                     # sorting the rules
                            if len(temp) > 0:
                                temp = temp[0]  # we get the first matching rule, the one with the highest priority
                                # assignment of the matching rule to the specific spot in the multi dimensional matrix
                                table[count1][count2][count3][count4][count5] = temp
                                # performance evaluation
                                if MEMORY_EVALUATION:
                                    memory_used += sys.getsizeof(temp)
                                    elements_added +=1
                            count5 += 1
                        count4 += 1
                    count3 += 1
                count2 += 1
            count1 += 1
        return table, elements_added, memory_used

    ''' Instantiation of bitmap_lines '''
    def bitmap(self):
        bitmap_lines = {}
        elements_added = 0  # for memory evaluation
        memory_used = 0    # for memory evaluation
        # do the bitmap field by field
        for field in (SRC_IP, DST_IP, PROTO, SPORT, DPORT):
            numerical_line = self.numerical_lines[field]
            index = 0
            bitmap_field = {}
            # given a field, for any range we need to verify what rules match it
            for range in numerical_line:
                # in bitmap_field we memorize not the  values of the range but his index (variable "index"):
                #  we save the position of the interval, for example  3 , 2 etc instead of "121-131"
                bitmap_field[index] = []
                for rule in self.array_of_rules:
                    if rule in numerical_line[range]:
                        bitmap_field[index].append(1)
                    else:
                        bitmap_field[index].append(0)
                    elements_added += 1
                    memory_used += sys.getsizeof(1)  # we are allocating space for an int (1 or 0, size not change)
                index += 1
            # saving
            bitmap_lines[field] = bitmap_field
        return bitmap_lines, elements_added, memory_used


###################################################################################################################
    ''' Lookup methods '''

    ''' This is the main method for lookup, called by sar_application. 
    It returns the rule that match the input packet '''
    def run_lookup_packet_classification(self, src_ip, dst_ip, proto, sport, dport):
        rule = None
        match = None
        # Performance evaluation parameters
        iterations = {}  # for performance evaluation
        times = {}  # for performance evaluation
        starting_time = 0  # for performance evaluation
        bitmap_time = 0  # for performance evaluation
        if TOTAL_LOOKUP_TIME_EVALUATION:  # performance evaluations
            starting_time = time.clock()

        # we run different lookups algorithms based on the selected algorithm
        try:
            if ALGORITHM_SELECTED == LINEAR:
                rule, match = self.linear_classification_lookup(src_ip, dst_ip, proto, sport, dport)
            if ALGORITHM_SELECTED == BITMAP_INTERSECTION:
                rule, match, iterations, times, bitmap_time = self.lookup_bitmap(src_ip, dst_ip, proto, sport, dport)
            if ALGORITHM_SELECTED == CROSSPRODUCTING_ALGORITHM:
                rule, match, iterations, times = self.lookup_crossproducting_table(src_ip, dst_ip, proto, sport, dport)

            #  PERFORMANCE EVALUATION:
            if TOTAL_LOOKUP_TIME_EVALUATION and starting_time is not None:
                ending_time = time.clock()
                interval = (ending_time - starting_time) * (10 ** 3)  # in ms
                self.__total_lookup_time_stats(interval)  # saving stats
            self.__look_up_one_field_stats(iterations, times)
            self.__bitmap_time_stats(bitmap_time)

            # sending response to caller
            if rule is not None and match is not None:
                # self.logger.info("  --- Packet matched rule %s. Action is %s" % (match, match[ACTION]))
                print("  --- Packet matched rule %s : %s. Action is %s" % (rule, match, match[ACTION]))
                return match[ACTION]
        # we handle all the cases for which we receive an incorrect packet
        except (ValueError, IndexError, TypeError):
            print(" --- Packet classification lookup error: invalid packet")
            return "deny"

    '''In the 3 following methods, we implement look-up for the three possible algorithms'''

    '''Look-up for cross-producting'''
    def lookup_crossproducting_table(self, ipsource, ipdest, protocol, sport, dport):
        look_up = {}
        times = {}  # for performance evaluation
        # look-up field by field
        look_up[SRC_IP], times[SRC_IP] = self.__lookup_one_field__(ipsource, SRC_IP)
        look_up[DST_IP], times[DST_IP] = self.__lookup_one_field__(ipdest, DST_IP)
        look_up[PROTO], times[PROTO] = self.__lookup_one_field__(protocol, PROTO)
        look_up[SPORT], times[SPORT] = self.__lookup_one_field__(sport, SPORT)
        look_up[DPORT], times[DPORT] = self.__lookup_one_field__(dport, DPORT)
        # getting the name of the rule saved in a particular spot in the multidimensional matrix
        name_of_rule = self.table[look_up[SRC_IP]][look_up[DST_IP]][look_up[PROTO]][look_up[SPORT]][look_up[DPORT]]
        match = self.array_of_rules[name_of_rule]
        return name_of_rule, match, look_up , times

    ''' Lookup for bitmap.'''
    def lookup_bitmap(self, ipsource, ipdest, protocol, sport, dport):
        # doing look_up field by field
        look_up = {}
        times = {}  # for performance evaluation
        # 1. look-up field by field
        look_up[SRC_IP], times[SRC_IP] = self.__lookup_one_field__(ipsource, SRC_IP)
        look_up[DST_IP], times[DST_IP] = self.__lookup_one_field__(ipdest, DST_IP)
        look_up[PROTO], times[PROTO] = self.__lookup_one_field__(protocol, PROTO)
        look_up[SPORT], times[SPORT] = self.__lookup_one_field__(sport, SPORT)
        look_up[DPORT], times[DPORT] = self.__lookup_one_field__(dport, DPORT)

        # performance evaluation for bitmap '''
        starting_time=0
        if TIME_FOR_AND_BITMAP_EVALUATION:
            starting_time = time.clock()
        # 2. getting the correspondent bit-mapping of the range matching the field (done for all the fields)
        bitmap_lookup = {}
        for field in range(SRC_IP, DPORT + 1):
            set_of_ranges = self.bitmap_lines[field]
            bitmap_lookup[field] = set_of_ranges[look_up[field]]
        # 3. and bit by bit
        flag = False
        index = 0
        while not flag:
            if bitmap_lookup[SRC_IP][index] == 1 and bitmap_lookup[DST_IP][index] == 1 \
                    and bitmap_lookup[PROTO][index] == 1 and bitmap_lookup[SPORT][index] == 1 \
                    and bitmap_lookup[DPORT][index] == 1:
                flag = True
            else:
                index += 1
        # 4. the rule to be returned is pointed by "index": its label is saved in "name_of_rule", its value in "match"
        keys = self.array_of_rules.keys()
        name_of_rule = keys[index]
        match = self.array_of_rules[name_of_rule]
        # performance evaluation and ending method
        bitmap_time=0
        if TIME_FOR_AND_BITMAP_EVALUATION and starting_time is not None:
            ending_time = time.clock()
            bitmap_time = (ending_time - starting_time) * (10**3)  # in ms
        return name_of_rule, match, look_up , times, bitmap_time

    ''' Look-up of linear classification:  done simply iterating among the rules '''
    def linear_classification_lookup(self, src_ip, dst_ip, proto, sport, dport):
        iterations_done = 0  # counts how many iterations we do before arriving to matching
        # check matching rule
        for rule in self.array_of_rules:
            iterations_done +=1
            match = self.array_of_rules[rule]
            # we convert the strings of the field in correspondent object that implement the logic of "contains"
            src_ip_rule = Ip(match[SRC_IP])
            dst_ip_rule = Ip(match[DST_IP])
            proto_rule = Protocol(match[PROTO])
            sport_rule = Port(match[SPORT])
            dport_rule = Port(match[DPORT])
            if src_ip_rule.contains(src_ip) and dst_ip_rule.contains(dst_ip) and proto_rule.contains(proto) \
                    and sport_rule.contains(sport) and dport_rule.contains(dport):
                action = match[ACTION]
                return rule, match
        # if no rule is specified for that packet
        rule = None
        match = None
        return rule, match

    ''' method called by lookup_crossproducting_table and lookup_bitmap that executes the lookup of the given field '''
    def __lookup_one_field__(self, value, field):
        # performance evaluation
        starting_time = 0
        if LOOKUP_ONE_FIELD_EVALUATION:
            starting_time = time.clock()
        # in numerical_lines the ordered ranges of the field are saved
        set_of_rules = self.numerical_lines[field]
        counter = 0
        if not BINARYSEARCH:
            if field == SRC_IP or field == DST_IP:
                for key in set_of_rules:
                    key = Ip(key)
                    if not (key.contains(value)):
                        counter += 1
                    else: break
            elif field == PROTO:
                for key in set_of_rules:
                    key = Protocol(key)
                    if not (key.contains(value)):
                        counter += 1
                    else: break
            else:  # SPORT or DPORT
                for key in set_of_rules:
                    key = Port(key)
                    if not (key.contains(value)):
                        counter += 1
                    else:
                        break
        if BINARYSEARCH:
            # associating right object
            if field == SRC_IP or field == DST_IP:
                key = Ip(value)
            elif field == PROTO:
                key = Protocol(value)
            else:
                key = Port(value)
            # calling binary_search method
            counter = self.__binary_search__(set_of_rules.keys(), 0, len(set_of_rules.keys()), key, field) # do binary search

        interval = 0  # for performance evaluation
        # performance evaluation
        if LOOKUP_ONE_FIELD_EVALUATION and starting_time is not None:
                ending_time = time.clock()
                interval = (ending_time - starting_time) * (10 ** 3)  # in ms
        # ending method
        return counter, interval

    ''' It executes the binary search, between a numerical line. it s called by lookup_one_field.
     It is a recursive method. Binary search is the fastest way to find an element in an ordered list. '''
    def __binary_search__(self, keys, start, end, value, field):   # binary search implementation
        if end >= start:
            mid = start + (end - start) // 2  # find the medium point
            # associating right object
            if field == SRC_IP or field == DST_IP:
                key = Ip(keys[mid])
            elif field == PROTO:
                key = Protocol(keys[mid])
            else:   key = Port(keys[mid])
            if key.contains(str(value)):  # if we find the value stop the algorithm, else keep doing the binary_search
                return mid
            elif key > value:
                return self.__binary_search__(keys, start, mid - 1, value, field)
            else:
                return self.__binary_search__(keys, mid + 1, end, value, field)
        else: # if not found
            return -1

    #################################################################################################
    ''' methods to save stats: see documentation '''

    def __algorithms_time_stats(self, interval):
        if ALGORITHMS_CREATION_EVALUATION and interval > 0 :
            file_object = open(FILENAME_ALGORITHMS_CREATION, "a+")
            num_of_rules = str(len(self.array_of_rules.keys()))
            file_object.write(
                ALGORITHM_SELECTED + "-" + num_of_rules + "-" + str(interval) + "\n")
            file_object.close()

    def __total_lookup_time_stats(self, interval):
        if TOTAL_LOOKUP_TIME_EVALUATION and interval > 0:
            file_object = open(FILENAME_TOTAL_LOOKUP, "a+")
            num_of_rules = str(len(self.array_of_rules.keys()))
            file_object.write(
                ALGORITHM_SELECTED + "-" + num_of_rules + "-" + str(interval) + "\n")
            file_object.close()

    def __look_up_one_field_stats(self, iterations, times):
        if LOOKUP_ONE_FIELD_EVALUATION and (ALGORITHM_SELECTED == BITMAP_INTERSECTION
                                            or ALGORITHM_SELECTED == CROSSPRODUCTING_ALGORITHM)\
                                        and times != 0 and iterations != 0:
            file_object = open(FILENAME_LOOKUP_ONE_FIELD, "a+")
            num_of_rules = str(len(self.array_of_rules.keys()))

            for field in (SRC_IP, DST_IP, PROTO, SPORT, DPORT):
                file_object.write(ALGORITHM_SELECTED + "-" + num_of_rules + "-" + str(field) + "-"
                                  + str(iterations[field]) + "-" + str(times[field]) + "\n")
            file_object.close()

    def __memory_use_stats(self, elements_added, memory_used):
        # adding data for memory evaluation
        if MEMORY_EVALUATION:
            file_object = open(FILENAME_MEMORY_USAGE, "a+")
            num_of_rules = str(len(self.array_of_rules.keys()))
            file_object.write(
                ALGORITHM_SELECTED + "-" + num_of_rules + "-" + str(elements_added) + "-" + str(memory_used) + "\n")
            file_object.close()

    def __bitmap_time_stats(self, time_used):
        if TIME_FOR_AND_BITMAP_EVALUATION and ALGORITHM_SELECTED == BITMAP_INTERSECTION and time_used > 0:
            file_object = open(FILENAME_BITMAP_TIME, "a+")
            num_of_rules = str(len(self.array_of_rules.keys()))
            file_object.write(
                ALGORITHM_SELECTED + "-" + num_of_rules + "-" + str(time_used) + "\n")
            file_object.close()
