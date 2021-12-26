
#File containing the classes of the five fields that make up the packetclassification and the ipadress class to manage the ipadress


MAXPORT = 2 ** 16 - 1 # maximum voices that the port field can have
MAXPROTO = 2 ** 8 - 1 # maximum voices that the protocol field can have

''' The port class was made in order to manage the port field inputs from the rules of packetclassification '''
class Port:
    def __init__(self, value):
        # The first thing we analyze when the port field input comes from a specific rule is
        # to see if the function includes all possible ports (with the asterisk) or an interval of value or specific value.
        if value == "*":
            # If the port field input is asterisk then we give it a range between 0 e MAXPORT
            self.is_range = True
            self.starting_as_int = 0
            self.ending_as_int = MAXPORT
            self.starting = str(0)
            self.ending = str(MAXPORT)
        elif '-' in value:
            # If the port field input is a range then we take the first value as starting and the second one as ending
            self.starting = value.split("-", 1)[0]
            self.ending = value.split("-", 1)[1]
            self.is_range = True
            self.starting_as_int = int(self.starting)
            self.ending_as_int = int(self.ending)
            # Here we manage the possible errors that can occur when the port field input is range. The possible errors we can incur are:
            # 1) if in the range,the first value is greater then second
            # 2) if the program has entered the same in the if even if it is not a range but a specific value
            if self.starting_as_int > self.ending_as_int:
                temp = self.ending
                self.ending = self.starting
                self.starting = temp
                self.starting_as_int = int(self.starting)
                self.ending_as_int = int(self.ending)
            if  self.starting_as_int == self.ending_as_int:
                    self.is_range = False
        else: # If the port field input is a specific value ( not a range)
            self.starting = value
            self.ending = value
            self.ending_as_int = int(value)
            self.starting_as_int = int(value)
            self.is_range = False
        # if the values are outside the range set by the port field we raise an exception
        if self.starting_as_int <= 0 | self.starting_as_int > MAXPORT | self.ending_as_int <= 0 | self.ending_as_int > MAXPORT:
            raise ValueError

   #Given a value as argument,contains return true if the value is inside(or equal to) the range of this object, false otherwise
    def contains(self, value_as_string):
            temp = int(value_as_string)
            return  self.starting_as_int <= temp <= self.ending_as_int

    #__gt__ and __lt__ are used to overload of '<' and '>' logical operators so that we can compare port objects
    def __gt__(self, other):
        return self.ending_as_int > other.starting_as_int

    def __lt__(self, other):
        return self.starting_as_int < other.ending_as_int

    #__str__ and __repr__ are used to describe the object as string
    def __str__(self):
        if not self.is_range:
            return self.starting
        else:
            return self.starting + "-" + self.ending

    def __repr__(self):
        if self.ending == self.starting:
            return "port: " + self.starting
        if self.ending != self.starting:
            return "port range: " + self.starting + "-" + self.ending

''' The protocol class was made in order to manage the protocol field inputs from the rules of packetclassification'''
class Protocol:
    def __init__(self, value):
        # The first thing we analyze when the protocol field input comes from a specific rule is
        # to see if the function includes all possible protocols (with the asterisk) or an interval of value or specific value.
        if value == "*":
            # If the protocol field input is asterisk then we give it a range between 0 e MAXPROTO
            self.is_range = True
            self.starting_as_int = 0
            self.ending_as_int = MAXPROTO
            self.starting = str(0)
            self.ending = str(MAXPROTO)
        elif '-' in value:
            # If the protocol field input is a range then we take the first value as starting and the second one as ending
            self.starting = value.split("-", 1)[0]
            self.ending = value.split("-", 1)[1]
            self.is_range = True
            self.starting_as_int = int(self.starting)
            self.ending_as_int = int(self.ending)
            # Here we manage the possible errors that can occur when the protocol field input is range. The possible errors we can incur are:
            # 1) if in the range,the first value is greater then second
            # 2) if the program has entered the same in the if even if it is not a range but a specific value
            if self.starting_as_int > self.ending_as_int:
                temp = self.ending
                self.ending = self.starting
                self.starting = temp
                self.starting_as_int = int(self.starting)
                self.ending_as_int = int(self.ending)
            if self.starting_as_int == self.ending_as_int:
                self.is_range = False
        else:
            # If the program enter here if the protocol field input is a specific value
            self.starting = value
            self.ending = value
            self.is_range = False
            self.starting_as_int = int(self.starting)
            self.ending_as_int = int(self.ending)
        # if the values are outside the range set by the protocol field we raise an exception
        if self.starting_as_int <= 0 | self.starting_as_int > MAXPROTO | self.ending_as_int <= 0 | self.ending_as_int > MAXPROTO:
            raise ValueError

    # Given a value as argument,contains return true if the value is inside(or equal to) the range of this object, false otherwise
    def contains(self, value_as_string):
            temp = int(value_as_string)
            return self.starting_as_int <= temp <= self.ending_as_int

    # __gt__ and __lt__ are used to overload of '<' and '>' logical operators so that we can compare protocol objects
    def __gt__(self, other):
        return self.ending_as_int > other.starting_as_int

    def __lt__(self, other):
        return self.starting_as_int < other.ending_as_int

    # __str__ and __repr__ are used to describe the object as string
    def __str__(self):
        if not self.is_range:
            return self.starting
        else:
            return self.starting + "-" + self.ending

    def __repr__(self):
        if self.ending == self.starting:
            return "protocol: " + self.starting
        if self.ending != self.starting:
            return "protocol range: " + self.starting + "-" + self.ending


'''The Ip class was made in order to manage the ipaddress field inputs from the rules of packetclassification  '''
class Ip:

    def __init__(self, value):
        # The first thing we analyze when the ipaddress field input comes from a specific rule is
        # to see if the function includes all possible ipaddress (with the asterisk) or an interval of ipaddress
        # or ipaddress with subnet mask or specific ipaddress.
        if value == "*":
            # If the ipaddress field input is asterisk then we give it a range between 0.0.0.0 e 255.255.255.255
            self.is_range = True
            self.starting_as_ip = ipaddress.ip_address("0.0.0.1")
            self.ending_as_ip = ipaddress.ip_address("255.255.255.255")
            self.starting = "0.0.0.1"
            self.ending = "255.255.255.255"
        elif '/' in value:
            # If the ipaddress field input is an ipaddress with subnet mask then manage it as a range
            # between the minimum and the maximum of the subnet
            self.starting = value.split("/", 1)[0]
            netmask = value.split("/", 1)[1]
            self.starting_as_ip = ipaddress.ip_start_of_range(self.starting, netmask)
            self.starting = str(self.starting_as_ip)
            self.ending_as_ip = ipaddress.ip_end_of_range(self.starting, netmask)
            self.ending = str(self.ending_as_ip)
            self.is_range = True
        elif '-' in value:
            # If the ipaddress field input is a range then we take the first ipaddress as starting and the second one as ending
            self.starting = value.split("-", 1)[0]
            self.ending = value.split("-", 1)[1]
            self.starting_as_ip = ipaddress.ip_address(self.starting)
            self.ending_as_ip  = ipaddress.ip_address(self.ending)
            self.is_range = True
        else:
            # If the ipaddress field input is a range then we take the first ipaddress as starting and the second one as ending
            self.starting = value
            self.ending = value
            self.starting_as_ip = ipaddress.ip_address(self.starting)
            self.ending_as_ip = ipaddress.ip_address(self.ending)
            self.is_range = False

    # Given a value as argument,contains return true if the value is inside(or equal to) the range of this object, false otherwise
    def contains(self, value_as_string):
            temp = ipaddress.ip_address(value_as_string)
            return self.starting_as_ip <= temp <= self.ending_as_ip

    # With this functions, we manage the increase and decrease of ipaddress objects
    def increment (self):
        ip = self.starting_as_ip
        return  ip.add_integer(1)

    def decrement(self):
        ip = self.starting_as_ip
        return ip.subtract_integer(1)

    # __gt__ and __lt__ are used to overload of '<' and '>' logical operators so that we can compare ipaddress objects
    def __gt__(self, other):
        return self.ending_as_ip > other.starting_as_ip

    def __lt__(self, other):
        return self.starting_as_ip < other.ending_as_ip

    # __str__ and __repr__ are used to describe the object as string
    def __str__(self):
        if not self.is_range:
            return self.starting
        else:
            return self.starting + "-" + self.ending

    def __repr__(self):
        if self.ending == self.starting:
            return "ip: " + self.starting
        if self.ending != self.starting:
            return "ip: " + self.starting + "-" + self.ending


'''  The class ipadress was made in order to manage all ip adresses in this program.
  Can be considered as a tool of class Ip: class Ip is the only class that uses ipaddress'''
class ipaddress:
    def __init__(self, string_address):
        # Here let's define how an ip address is formed (number.number.number.number)
        self.string_address= string_address
        self.first_byte = int(string_address.split(".", 3)[0])
        self.second_byte =  int(string_address.split(".", 3)[1])
        self.third_byte = int(string_address.split(".", 3)[2])
        self.fourth_byte = int(string_address.split(".", 3)[3])
        # If a byte is out of range , raise an exception
        if not(0 <= self.first_byte <= 255 and 0 <= self.second_byte <= 255
                and 0 <= self.third_byte <= 255 and 0 <= self.fourth_byte <= 255):
            raise ValueError

    # __gt__ is used to overload of '>' logical operator
    def __gt__(self, other):
        if self.first_byte > other.first_byte:
            return True
        elif self.first_byte == other.first_byte:
            if self.second_byte > other.second_byte:
                return True
            elif self.second_byte == other.second_byte:
                if self.third_byte > other.third_byte:
                    return True
                elif self.third_byte == other.third_byte:
                    return self.fourth_byte > other.fourth_byte
        return False

    # __eq__ is used to overload of '=' logical operator
    def __eq__(self, other):
        return self.string_address.__eq__(other)

    # __ge__ is used to overload of '>=' logical operator
    def __ge__(self, other):
        return self > other or self == other

    # __lt__ is used to overload of '!>=' logical operator
    def __lt__(self, other):
        return not (self > other or self == other)

    # __le__ is used to overload of '<=' logical operator
    def __le__(self, other):
       return  self < other or self == other

    # __ne__ is used to overload of '!<=' logical operator
    def __ne__(self, other):
        return  not self == other


    # __str__ and __repr__ are used to describe the object as string
    def __str__(self):
        return self.string_address

    def __repr__(self):
        return self.string_address

    # Let's define how an ip address is composed in terms of size, implicitly defined by subtraction and addition:
    # 1) In add_integer we manage adding integers to an ipaddress and how the various parts of the ip address are connected
    # 2) In subtract_integer we manage subtracting to an ipaddress and how the various parts of the ip address are connected
    def add_integer(self, integer):
        fourth_byte = (self.fourth_byte + integer) % 256
        remainder = (self.fourth_byte + integer) / 256
        third_byte = (self.third_byte + remainder) % 256
        remainder = (self.third_byte + remainder) / 256
        second_byte = (self.second_byte + remainder) % 256
        remainder = (self.second_byte + remainder) / 256
        first_byte = (self.first_byte + remainder) % 256
        new_string = str(first_byte)+"." + str(second_byte)+"."+ str(third_byte)+"."+ str(fourth_byte)
        return new_string

    def subtract_integer(self, integer):
        first_byte = self.first_byte
        second_byte = self.second_byte
        third_byte =  self.third_byte
        fourth_byte = self.fourth_byte

        if self.fourth_byte!=0:
            fourth_byte =self.fourth_byte-integer
        else:
            fourth_byte = 255
            if self.third_byte != 0:
                third_byte =self.third_byte - integer
            else:
                third_byte = 255
                if self.second_byte != 0:
                    second_byte = self.second_byte- integer
                else:
                    second_byte = 255
                    if self.first_byte != 0:
                        first_byte = self.first_byte - integer
                    else:
                        first_byte = 0

        new_string = str(first_byte)+"." + str(second_byte)+"."+ str(third_byte)+"."+ str(fourth_byte)
        return new_string

    # Three methods for forming the creation of addresses:
    # 1) defines the specific value of the IP address
    # 2) defines starting element of a range:
    #       we find the starting value of a IP range and instantiating it as and returning it as an ipaddress object
    # 3) defines ending element of a range:
    #       we find the ending value of a IP range and instantiating it as and returning it as an ipaddress object

    @staticmethod
    def ip_address(string_address):
        ip = ipaddress(string_address)
        return ip

    # methods that given a range returns the instantiated ipaddress object of the first element of the range
    @staticmethod
    def ip_start_of_range(string_address, net_length):
        # separating byte by byte
        net_length = int(net_length)
        byte = []
        byte.append(int(string_address.split(".", 3)[0]))
        byte.append(int(string_address.split(".", 3)[1]))
        byte.append(int(string_address.split(".", 3)[2]))
        byte.append(int(string_address.split(".", 3)[3]))

        # with the following we make sure we get the first element of the range
        byte_index = net_length / 8
        remainder = net_length % 8
        power = 8 - remainder
        temporary_index = byte[byte_index] / (2 ** power)
        byte[byte_index] = temporary_index * (2 ** power)
        if remainder == 0:  # we point to the previous byte: the last of net-id (necessary for next steps)
            byte_index += -1

        # putting to 0 bytes of subnet-id
        for i in range(byte_index+1, 4):
            byte[i] = 0
        new_string = str(byte[0])+"." + str(byte[1])+"."+ str(byte[2])+"."+ str(byte[3])
        ip = ipaddress(new_string)
        return ip

    # methods that given a range returns the instantiated ipaddress object of the first element of the range
    @staticmethod
    def ip_end_of_range(string_address, net_length):
        #separating byte by byte
        net_length = int(net_length)
        byte = []
        byte.append(int(string_address.split(".", 3)[0]))
        byte.append(int(string_address.split(".", 3)[1]))
        byte.append(int(string_address.split(".", 3)[2]))
        byte.append(int(string_address.split(".", 3)[3]))
        # with the following we make sure we get the first element of the range
        byte_index = net_length / 8
        remainder = net_length % 8
        power = 8 - remainder
        if remainder != 0:
            byte[byte_index] += (2 ** power) -1
        else: # reminder=0; we point to the previous byte: the last of net-id (necessary for next steps)
            byte_index += -1

        # putting to 255 bytes of subnet-id
        for i in range(byte_index+1, 4):
            byte[i] = 255

        #returning the ipaddress object
        new_string = str(byte[0])+"." + str(byte[1])+"."+ str(byte[2])+"."+ str(byte[3])
        ip = ipaddress(new_string)
        return ip