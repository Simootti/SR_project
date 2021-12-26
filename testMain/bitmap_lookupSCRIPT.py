import matplotlib.pyplot as plt
from collections import OrderedDict


FILENAME_ONE_FIELD = "ONE_FIELD_LOOKUPstats.txt"
FILENAME_LOOKUP = "TOTAL_LOOKUPstats.txt"
FILENAME_BITMAP = "BITMAP_TIMEstats.txt"

DIM = 5


def get_sorted_averages(stats):
    average_stats= OrderedDict()
    for key in stats:
        list_temp = stats[key]
        average = sum(list_temp) / float(len(list_temp))
        average_stats[key]= average
    #ordering (at first keys, then values)
    keys= average_stats.keys()
    keys.sort() #sort keys
    values = []
    for key in keys:
        values.append(average_stats[key])

    return keys, values


def read_one_field():
    file_to_read = open(FILENAME_ONE_FIELD, "r")
    lines = file_to_read.readlines()
    stats = OrderedDict()
    for line in lines:
        temp = line.split("\n", 1)[0]
        algorithm = temp.split("-", 4)[0]  # ignored
        num_of_rules = int(temp.split("-", 4)[1])
        field = int(temp.split("-", 4)[2])  # ignored
        iterations_used = int(temp.split("-", 4)[3])  # ignored
        time_used = float(temp.split("-", 4)[4])

        if stats.has_key(num_of_rules):
            list_temp = stats[num_of_rules]
            list_temp.append(time_used)
        else:
            list_temp = [time_used]
            stats[num_of_rules] = list_temp

    time_key, time_value = get_sorted_averages(stats)
    file_to_read.close()
    return time_key, time_value

def total_lookup_bitmap():
    file_to_read = open(FILENAME_LOOKUP, "r")
    lines = file_to_read.readlines()
    stats = OrderedDict()
    for line in lines:
        temp = line.split("\n", 1)[0]
        algorithm = temp.split("-", 2)[0]
        num_of_rules = int(temp.split("-", 2)[1])
        total_time = float(temp.split("-", 2)[2])
        if algorithm== "Bitmap":
            if stats.has_key(num_of_rules):
                list_temp = stats[num_of_rules]
                list_temp.append(total_time)
            else:
                list_temp = [total_time]
                stats[num_of_rules] = list_temp

    file_to_read.close()
    bitmap_key, bitmap_value = get_sorted_averages(stats)
    return bitmap_key, bitmap_value


def read_bitmap_part():
    file_to_read = open(FILENAME_BITMAP, "r")
    lines = file_to_read.readlines()
    stats = OrderedDict()
    for line in lines:
        temp = line.split("\n", 1)[0]
        algorithm = temp.split("-", 2)[0]
        num_of_rules = int(temp.split("-", 2)[1])
        total_time = float(temp.split("-", 2)[2])
        if algorithm == "Bitmap":
            if stats.has_key(num_of_rules):
                list_temp = stats[num_of_rules]
                list_temp.append(total_time)
            else:
                list_temp = [total_time]
                stats[num_of_rules] = list_temp

    file_to_read.close()
    bitmap_key, bitmap_value = get_sorted_averages(stats)
    return bitmap_key, bitmap_value


if __name__ == '__main__':

    time_onefield_keys , time_onefield_values = read_one_field()
    bitmap_key, bitmap_value = total_lookup_bitmap()
    bitmap_part_key, bitmap_part_value = read_bitmap_part()

    fig = plt.figure(3)
    temp = [5 * x for x in time_onefield_values]
    plt.plot(bitmap_key, bitmap_value, label="total lookup time")
    plt.plot(time_onefield_keys, temp, label="first term")
    plt.plot(bitmap_part_key, bitmap_part_value, label="second term")
    plt.ylabel('average time [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    fig.savefig("foo.png")
    plt.grid(True)
    plt.show()

    fig = plt.figure(4)
    plt.plot(bitmap_part_key, bitmap_part_value, label="2 term")
    plt.ylabel('average time [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    plt.grid(True)
    #fig.savefig("foo2.png")
    plt.show()