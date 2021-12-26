from collections import OrderedDict
from packet_classification_utils import *

MAXPORT = 2 ** 16 - 1   #Defining the maximum number that a port can take
MAXPROTO = 2 ** 8 - 1   #Defining the maximum number that a protocol can take


# Packet Classification parameters:
SRC_IP = 0
DST_IP = 1
PROTO = 2
SPORT = 3
DPORT = 4
ACTION = 5


class PrecomputationEngine:

    def __init__(self, rules):      #Initializing the class PrecomputationEngine
        self.array_of_rules= rules

    ''' main method that starts pre-computation '''
    def geometric_precompute(self):
        rules = OrderedDict()
        name_of_rule = 0
        try:
            # trasforming strings of ports in object of type Port,
            # strings of IPs in object of type Ip ,
            # strings of protocols in object of type Protocol
            for name_of_rule in self.array_of_rules:
                new_rule = [0, 0, 0, 0, 0]
                rule = self.array_of_rules[name_of_rule]
                new_rule[SRC_IP] = Ip(rule[SRC_IP])
                new_rule[DST_IP] = Ip(rule[DST_IP])
                new_rule[PROTO] = Protocol(rule[PROTO])
                new_rule[SPORT] = Port(rule[SPORT])
                new_rule[DPORT] = Port(rule[DPORT])
                rules[name_of_rule] = new_rule

            rule_matched = {}
            # For each field (SRC_IP , DST_IP , PROTO , SPORT , DPORT) i create a list containing all the possible respective range value
            # and matched rules.
            # Look in geometric_precompute_onefield for the implementation
            for field in (SRC_IP, DST_IP):
                rule_matched[field] = self.geometric_precompute_one_field(rules, field, "0.0.0.1", "255.255.255.255")
            rule_matched[PROTO] = self.geometric_precompute_one_field(rules, PROTO, str(0), str(MAXPROTO))
            for field in (SPORT, DPORT):
                rule_matched[field] = self.geometric_precompute_one_field(rules,field, str(0), str(MAXPORT))
        # catching possible errors
        except (ValueError, IndexError, TypeError):
            # rethrowing exception of the wrong rule
            raise IllegalRuleException(name_of_rule)
        # ending method
        return rule_matched

    ''' method called field by field that creates a numerical line '''
    def geometric_precompute_one_field(self, rules, field, min_value, max_value):
        # taking the elements of a given field (SRC_IP , DST_IP , PROTO , SPORT , DPORT )
        # from all the existing rules and saving these elements in list "numerical_line"
        numerical_line = [min_value, max_value]  # list
        for iterator in sorted(rules):  # I scan all the rules
            rule = rules[iterator]
            temp_var = (rule[field])
            if temp_var.is_range:                           # If the value corresponding to the field is a range i save on the numerical_line
                numerical_line.append(temp_var.starting)    # both starting point and ending point of the range
                numerical_line.append(temp_var.ending)

            else:
                numerical_line.append(temp_var.starting)

        # removing duplicates
        numerical_line = list(set(numerical_line))

        # sorting
        if field in (PROTO, SPORT, DPORT):
            # converting string to integer
            temp = [int(x) for x in numerical_line]
            numerical_line = temp
            numerical_line.sort()                   # Sorting integers in numerical_line
            # converting integer to string
            temp = [str(x) for x in numerical_line]
            numerical_line = temp

        if field in (SRC_IP, DST_IP):
            # converting string to ip
            temp = [ipaddress.ip_address(x) for x in numerical_line]
            numerical_line = temp
            numerical_line.sort()                   # Sorting IPs in numerical_line
            # converting IPs to string
            temp = [str(x) for x in numerical_line]
            numerical_line = temp

        rule_matched = self.one_field_first_step(rules, field, numerical_line)

        # Creation of the intervals between values
        intervals =  self.one_field_second_step(numerical_line, rule_matched, max_value, field)
        return intervals

    ''' in the following, two methods that creates the numerical line '''
    def one_field_first_step(self, rules, field, numerical_line):
        # Mapping rules and values (exact values)
        rule_matched = {}  # dictionary
        for value in numerical_line:  # for each value in numerical_line
            rule_matched[value] = []  # adding the value as a key
            for key, rule in rules.items():  # compare with the rules
                if rule[field].is_range:
                    if rule[field].contains(value):
                        rule_matched[value].append(key)
                elif not rule[field].is_range:
                    if value.__eq__(rule[field].starting):
                        rule_matched[value].append(key)
        return rule_matched

    def one_field_second_step(self, numerical_line, rule_matched, max_value, field):
        # The dictionary in which we will add ranges or exact values (as keys) and all the correspondent rules matching(values)
        intervals = OrderedDict()

        i = 0  # iterator of the numerical line
        ended = False  # false while is iterating
        point_already_added = False
        while (ended == False):
            # We are particularly interested in ranges: each  range has 2 vertexes: point A (beginning) and point B (end)
            # It is crucial to avoid overlays of intervals: so we have to foresee if we have to save A and/or B.
            # So every range could start in A or A+1 and end in B or B-1
            # Possible cases for which we have to save point A explicitly (same for B)
            #   1) there is an exact match in A? we have to save A
            #   2) the very unlucky case: there is a rule r1 ending in A and another one r2 starting in A (see below)
            #  Else is not necesssary (and because we want to save as less as ranges possible, we do not save A)

            # Every point will have its set of rules matching
            A = numerical_line[i]
            A_point_rules = rule_matched.get(A)
            B = []  # initialized below
            B_point_rules = []

            # AB_range_rules: rules belonging to both A and B are the rules of this range
            AB_range_rules = []

            if not A.__eq__(max_value):
                B = numerical_line[i + 1]
                B_point_rules = rule_matched.get(B)
                # AB_range_rules: rules belonging to both A and B are the rules of this range
                AB_range_rules = list(set(A_point_rules).intersection(B_point_rules))
                AB_range_rules.sort()

            # exact matches for A: if there exists at least one rule belonging to A not in AB
            rules_specifics_of_A = list(set(A_point_rules) - set(AB_range_rules))
            rules_specifics_of_A.sort()

            if point_already_added:  # point_already_added explained below
                point_already_added = False
                A_incremented = self.increment(A, field)
                if A_incremented.__eq__(B) == False:
                    # if true no intervals existing between A and B (A, B consecutive!)
                    # now we prepare element A+1 that will be considered in the next iteration
                    rule_matched[A_incremented] = AB_range_rules
                    numerical_line.insert(i + 1, A_incremented)

            elif rules_specifics_of_A.__len__() > 0:  # there are rules specific of A: We have to save A in intervals{}
                intervals[A] = A_point_rules
                # the rule of the range AB, will start from A+1
                A_incremented = self.increment(A, field)
                if A_incremented.__eq__(B) == False:  # if true no intervals existing between A and B (A, B consecutives!)
                    # if some rules match B they already are in B!
                    # we have to prepare element A+1 that will be considered in the next iteration
                    rule_matched[A_incremented] = AB_range_rules
                    numerical_line.insert(i + 1, A_incremented)

            else:
                # the range will start from A: what about B?
                # analyzing possible cases for which we will need to save B and end interval in B-1:
                #   1) there are exact rules for B.
                #   2) B has no exact match but a new rule starts in B:
                #       (If we have to save B , we will save it when in next iteration will become A)
                # otherwise, the rules of B are a subset of A (every rule of B is in A) and we can end interval in B

                rules_specifics_of_B = list(set(B_point_rules) - set(AB_range_rules))
                rules_specifics_of_B.sort()
                if rules_specifics_of_B.__len__() > 0:  # not empty
                    # current range will end in B-1
                    B_decremented = self.decrement(B, field)
                    # considering the case B-1 == A. Range [A, B-1] becomes a point and B will be saved in next iteration
                    if (B_decremented.__eq__(A)):
                        intervals[A] = A_point_rules
                    else:  # save range [A, B-1]
                        intervals[A + "-" + B_decremented] = AB_range_rules

                else:  # interval will be [A, B]
                    intervals[A + "-" + B] = AB_range_rules
                    # next interval will start from B+1: we have to avoid it to be added on next iteration
                    point_already_added = True

            # ending cycle
            if A.__eq__(max_value):  # last range
                ended = True
            elif B.__eq__(max_value) & point_already_added == True:
                ended = True
            i += 1
        return intervals

    ''' useful methods needed in one_field_second_step '''
    @staticmethod
    def decrement(string, field):
        if field in (PROTO, SPORT, DPORT):  #Decrement value for protocol and ports
            # converting string to integer
            number= int(string)
            # reconverting integer to string
            return str(number -1)
        if field in (SRC_IP, DST_IP):       #Decrement value for IPs
            ip = Ip(string)
            return ip.decrement()

    @staticmethod
    def increment(string, field):
        if field in (PROTO, SPORT, DPORT):  #Increment value for protocol and ports
            # converting string to integer
            number= int(string)
            # reconverting integer to string
            return str(number +1)
        if field in (SRC_IP, DST_IP):       #Increment value for IPs
            if string != "255.255.255.255":
                ip = Ip(string)
                return ip.increment()
            return 0

########################################################################################################################
''' Exception Created in order to handle errors if a rule in the classifier takes illegal values '''
class IllegalRuleException(Exception):
    def __init__(self, name_of_rule):
        self.name_of_rule = name_of_rule