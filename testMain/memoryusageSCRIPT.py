import matplotlib.pyplot as plt
from collections import OrderedDict

FILENAME_MEMORY = "MEMORY_USAGEstats.txt"
DIM = 5


def get_sorted_averages(stats):
    #doing the average for any rule
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


if __name__ == '__main__':

    file_to_read = open(FILENAME_MEMORY, "r")
    lines = file_to_read.readlines()

    #num of elem
    linear_n = OrderedDict()
    bitmap_n = OrderedDict()
    crossproduct_n = OrderedDict()


    for line in lines:
        temp= line.split("\n", 1)[0]
        algorithm = temp.split("-", 3)[0]
        num_of_rules = int(temp.split("-", 3)[1])
        elements_added = int(temp.split("-", 3) [2])
        memory_used = int(temp.split("-", 3) [3])
        #choice of dictionary
        if algorithm == "Linear":
            stats_n= linear_n
        if algorithm == "Bitmap":
            stats_n = bitmap_n
        if algorithm == "Cross_Producting":
            stats_n= crossproduct_n

        # num of elements
        if stats_n.has_key(num_of_rules):
            list_temp = stats_n[num_of_rules]
            list_temp.append(elements_added)
        else:
            list_temp = [elements_added]
            stats_n[num_of_rules] = list_temp


    linear_key , linear_value = get_sorted_averages(linear_n)
    bitmap_key , bitmap_value = get_sorted_averages(bitmap_n)
    crossproduct_key , crossproduct_value = get_sorted_averages(crossproduct_n)


    '''
    plt.figure(1)
    plt.plot(linear_key, linear_value)
    plt.ylabel('average time for lookup [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.show()
    '''


    '''
    plt.figure(2)
    plt.plot(bitmap_key, bitmap_value, label= "bitmap: experimental")
    theoretical_bitmap = [(DIM * x**2) for x in crossproduct_key ]
    plt.plot(bitmap_key, theoretical_bitmap, label ="bitmap: theoretical")
    plt.ylabel('average memory used in terms of number of elements')
    plt.xlabel("number of rules in the classifier")
    memorysize= [(192 * x) for x in bitmap_value]
    plt.legend()
    plt.show()
    '''
    print(len(crossproduct_key), len(crossproduct_value), len(bitmap_value), len(bitmap_key))
    '''
    plt.figure(3)
    plt.plot(crossproduct_key, crossproduct_value, label = "crossproduct :experimental")
    theoretical_crossproduct = [ x**DIM for x in crossproduct_key ]
    plt.plot(crossproduct_key[0:30],theoretical_crossproduct[0:30], label ="cross-product: theoretical")
    plt.ylabel('average memory used in terms of number of elements')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    plt.show()

    plt.figure(4)
    #plt.plot(linear_key, linear_value, label = "linear")
    plt.plot(crossproduct_key, crossproduct_value, label = "crossproduct")
    plt.plot(crossproduct_key, bitmap_value, label= "bitmap")
    plt.ylabel('average memory [ms]')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    plt.show()

    plt.figure(5)
    plt.plot(crossproduct_key, crossproduct_value, label="crossproduct :experimental")
    theoretical_crossproduct = [x ** DIM for x in crossproduct_key]
    plt.plot(crossproduct_key[0:30], theoretical_crossproduct[0:30], label="cross-product: theoretical")
    plt.ylabel('average memory used in terms of number of elements')
    plt.xlabel("number of rules in the classifier")
    plt.legend()
    plt.show()
    '''

    theoretical_crossproduct = [x ** DIM for x in crossproduct_key]



    plt.figure(6)
    fig, ax1 = plt.subplots()
    ax1.plot(crossproduct_key, crossproduct_value, label="crossproduct :experimental")
    ax1.plot(crossproduct_key[0:30], theoretical_crossproduct[0:30], 'r', label="cross-product: theoretical")
    ax1.set_xlabel("number of rules in the classifier")
    # Make the y-axis label, ticks and tick labels match the line color.
    ax1.set_ylabel('average memory used in terms of number of elements', color='b')
    ax1.ticklabel_format(style='plain', useOffset=False)  #style = 'plain'
    ax2 = ax1.twinx()
    cross_theor = [x*51 for x in theoretical_crossproduct]
    ax2.plot(crossproduct_key, cross_theor, 'r')
    ax2.ticklabel_format(style='plain', useOffset=False)  #style = 'plain'
    ax2.set_ylabel('byte occupancy', color='r')
    ax2.tick_params('byte', colors='r')
    fig.tight_layout()
    plt.show()