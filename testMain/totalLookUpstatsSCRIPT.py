import matplotlib.pyplot as plt
from collections import OrderedDict

FILENAME_LOOKUP = "TOTAL_LOOKUPstats.txt"


def get_sorted_averages(stats):
    # doing the average
    average_stats= OrderedDict()
    for key in stats:
        list_temp = stats[key]
        average = sum(list_temp) / float(len(list_temp))
        average_stats[key]= average
    # ordering (at first keys, then values)
    keys = average_stats.keys()
    keys.sort()  # sort keys
    values = []
    for key in keys:
        values.append(average_stats[key])

    return keys, values



if __name__ == '__main__':

    file_to_read = open(FILENAME_LOOKUP, "r")
    lines = file_to_read.readlines()

    linear = OrderedDict()
    bitmap = OrderedDict()
    crossproduct = OrderedDict()

    for line in lines:
        temp= line.split("\n", 1)[0]
        algorithm = temp.split("-", 2)[0]
        num_of_rules = int(temp.split("-", 2)[1])
        total_time = float(temp.split("-", 2) [2])
        # we take the right dictionary in which we will add this data
        if algorithm == "Linear":
            stats= linear  # pointer lo linear dictionary
        if algorithm == "Bitmap":
            stats = bitmap
        if algorithm == "Cross_Producting":
            stats= crossproduct

        if stats.has_key(num_of_rules):
            list_temp = stats[num_of_rules]
            list_temp.append(total_time)
        else:
            list_temp = [total_time]
            stats[num_of_rules] = list_temp

    file_to_read.close()

    linear_key , linear_value = get_sorted_averages(linear)
    bitmap_key , bitmap_value = get_sorted_averages(bitmap)
    crossproduct_key , crossproduct_value = get_sorted_averages(crossproduct)



    '''
    plt.figure(1)
    plt.plot(linear_key, linear_value)
    plt.ylabel('average time for lookup [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.show()

    plt.figure(2)
    plt.plot(bitmap_key, bitmap_value)
    plt.ylabel('average time for lookup [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.show()

    plt.figure(3)
    plt.plot(crossproduct_key, crossproduct_value)
    plt.ylabel('average time for lookup [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.show()
    '''

    fig = plt.figure(4)
    plt.plot(bitmap_key, bitmap_value, label= "bitmap")
    plt.plot(crossproduct_key, crossproduct_value, label = "crossproduct")
    plt.plot(linear_key, linear_value, label = "linear")
    plt.ylabel('average time for lookup [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    plt.grid(True)
    fig.savefig("foo.png")
    plt.show()


    fig2= plt.figure(6)
    plt.plot(bitmap_key, bitmap_value, label="bitmap")
    plt.plot(crossproduct_key, crossproduct_value, label="crossproduct")
    plt.ylabel('average time for lookup [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    plt.grid(True)
    fig2.savefig("foo2.png")
    plt.show()
