import matplotlib.pyplot as plt
from collections import OrderedDict

FILENAME_LOOKUP = "ALGORITHMCREATIONstats.txt"


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

    bitmap = OrderedDict()
    crossproduct = OrderedDict()

    for line in lines:
        temp= line.split("\n", 1)[0]
        algorithm = temp.split("-", 2)[0]
        num_of_rules = int(temp.split("-", 2)[1])
        total_time = float(temp.split("-", 2) [2])
        # we take the right dictionary in which we will add this data
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

    bitmap_key , bitmap_value = get_sorted_averages(bitmap)
    crossproduct_key , crossproduct_value = get_sorted_averages(crossproduct)



    plt.figure(2)
    plt.plot(bitmap_key, bitmap_value,  label= "bitmap")
    plt.ylabel('average time for update [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.grid(True)
    plt.legend()
    plt.show()

    plt.figure(3)
    crossproduct_value = [ x/1000 for x in crossproduct_value]
    plt.plot(crossproduct_key, crossproduct_value, label = "cross-producting")
    plt.ylabel('average time for update [s]')
    plt.xlabel("number of rules in the classifier")
    plt.grid(True)
    plt.legend()
    plt.show()

    plt.figure(4)
    plt.plot(bitmap_key, bitmap_value, label= "bitmap")
    plt.plot(crossproduct_key, crossproduct_value, label = "cross-producting")
    plt.ylabel('average time for update [s]')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    plt.show()


