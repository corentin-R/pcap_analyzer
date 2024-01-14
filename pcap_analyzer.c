/**
 * @file main.c
 * @brief Packet processing and analysis program using libpcap.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

/* Maximum of differents IP per time slot */
#define MAX_IPS 1000
/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
/* Time slot duration in seconds*/
#define TIME_SLOT_SECONDS 10

/**
 * @struct IpEntry
 * @brief Structure to store IP addresses and their count.
 */
typedef struct
{
    struct in_addr ip; /**< IP address */
    uint32_t count;    /**< Count of occurrences */
} IpEntry;

IpEntry IpEntries[MAX_IPS] = {0}; /**< Array to store IP entries */
uint32_t num_ip_entries = 0;      /**< Number of IP entries in the array */

/**
 * @brief Swap two IpEntry elements.
 * @param a Pointer to the first IpEntry.
 * @param b Pointer to the second IpEntry.
 */
void swap(IpEntry *a, IpEntry *b)
{
    fprintf(stderr, "%s: START\n", __func__);
    IpEntry t = *a;
    *a = *b;
    *b = t;
    fprintf(stderr, "%s: END\n", __func__);
}

/**
 * @brief Partition function for quicksort.
 * @param array Array to be partitioned.
 * @param low Low index.
 * @param high High index.
 * @return Partition point.
 */
int partition(IpEntry array[], int low, int high)
{
    /* select the rightmost element as pivot */
    uint32_t pivot = array[high].count;

    /* pointer for greater element */
    int i = (low - 1);

    fprintf(stderr, "%s: START\n", __func__);

    /* traverse each element of the array */
    /* compare them with the pivot */
    for (int j = low; j < high; j++)
    {
        if (array[j].count >= pivot)
        {

            /* if element smaller than pivot is found */
            /* swap it with the greater element pointed by i */
            i++;

            /* swap element at i with element at j */
            swap(&array[i], &array[j]);
        }
    }

    /* swap the pivot element with the greater element at i */
    swap(&array[i + 1], &array[high]);

    fprintf(stderr, "%s: END, result = %d\n", __func__, (i + 1));

    /* return the partition point */
    return (i + 1);
}

/**
 * @brief Perform quicksort on an array of IpEntry.
 * @param array Array to be sorted.
 * @param low Low index.
 * @param high High index.
 */
void quick_sort(IpEntry array[], int low, int high)
{
    fprintf(stderr, "%s: START\n", __func__);
    if (low < high)
    {
        /* find the pivot element such that */
        /* elements smaller than pivot are on left of pivot */
        /* elements greater than pivot are on right of pivot */
        int pi = partition(array, low, high);

        /* recursive call on the left of pivot */
        quick_sort(array, low, pi - 1);

        /* recursive call on the right of pivot */
        quick_sort(array, pi + 1, high);
    }
    fprintf(stderr, "%s: END\n", __func__);
}

/**
 * @brief Print the results of IP analysis for a given time slot.
 * @param first_timestamp The timestamp of the first packet.
 */
void print_results(time_t first_timestamp)
{
    fprintf(stderr, "%s: START\n", __func__);
    printf("%ld\n", first_timestamp);
    printf("----------------\n");
    for (uint32_t i = 0; i < num_ip_entries; i++)
    {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(IpEntries[i].ip.s_addr), ip_str, INET_ADDRSTRLEN);
        printf("%s : %d\n", ip_str, IpEntries[i].count);
    }
    printf("\n");
    fprintf(stderr, "%s: END\n", __func__);
}

/**
 * @brief Process a packet, updating IP entry counts and handling time slots.
 * @param header Packet header.
 * @param packet Packet data.
 * @param packet_number Packet number.
 */
void process_packet(const struct pcap_pkthdr *header, const u_char *packet, uint64_t packet_number)
{
    struct ip *ip_header;
    static time_t first_timestamp = 0;
    time_t current_timestamp = header->ts.tv_sec;
    uint32_t index = 0;
    uint8_t ip_found = 0;

    fprintf(stderr, "%s: START\n", __func__);

    /* Initialize 1st time */
    if (first_timestamp == 0)
    {
        fprintf(stderr, "%s: Init 1st time\n", __func__);
        first_timestamp = current_timestamp;
    }

    /* Retrieve IP header */
    ip_header = (struct ip *)(packet + SIZE_ETHERNET);

    if (num_ip_entries >= MAX_IPS)
    {
        fprintf(stderr, "Exceeded maximum number of time entries.\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "%s: Current timestamp=[%ld]\n", __func__, current_timestamp);
    fprintf(stderr, "%s: First timestamp=[%ld]\n", __func__, first_timestamp);

    /* Print results and begin new time slot */
    if (current_timestamp >= (first_timestamp + TIME_SLOT_SECONDS))
    {
        fprintf(stderr, "%s: New time slot\n", __func__);

        /* Order the elements */
        quick_sort(IpEntries, 0, num_ip_entries - 1);

        /* Print data for this time slot */
        print_results(first_timestamp);

        /* Reset current buffer */
        first_timestamp += TIME_SLOT_SECONDS;
        memset(IpEntries, 0, MAX_IPS * sizeof(IpEntry));
        num_ip_entries = 0;
    }

    /* Use current time slot */
    fprintf(stderr, "%s: Packet[%ld], IP src=[%s]\n", __func__, packet_number, inet_ntoa(ip_header->ip_src));

    for (uint32_t i = 0; i < num_ip_entries; i++)
    {
        if (IpEntries[i].ip.s_addr == ip_header->ip_src.s_addr)
        {
            index = i;
            ip_found = 1;
            break;
        }
    }

    if (ip_found == 0)
    {
        fprintf(stderr, "%s: First time we see IP [%s]\n", __func__, inet_ntoa(ip_header->ip_src));
        IpEntries[num_ip_entries].ip = ip_header->ip_src;
        IpEntries[num_ip_entries].count = 1;
        num_ip_entries++;
    }
    else
    {
        IpEntries[index].count++;
        fprintf(stderr, "%s: This is the %d time we see IP [%s] during this time slot\n", __func__, IpEntries[index].count, inet_ntoa(ip_header->ip_src));
    }

    fprintf(stderr, "%s: END\n", __func__);
}

/**
 * @brief Main function to read a pcap file and analyze the packets.
 * @param argc Number of command line arguments.
 * @param argv Command line arguments.
 * @return EXIT_SUCCESS if successful, EXIT_FAILURE otherwise.
 */
int main(int argc, char *argv[])
{
    int rc = EXIT_FAILURE;
    struct pcap_pkthdr header;
    const u_char *packet;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle;
    uint64_t packet_number = 0;

    fprintf(stderr, "%s: START\n", __func__);

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        goto EXIT;
    }

    /* Open pcap file */
    handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Could not open pcap file '%s': %s\n", argv[1], errbuf);
        goto EXIT;
    }

    /* Process each packet */
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        packet_number++;
        process_packet(&header, packet, packet_number);
    }

    rc = EXIT_SUCCESS;

EXIT:
    if (handle != NULL)
    {
        pcap_close(handle);
    }

    fprintf(stderr, "%s: END, rc = %d\n", __func__, rc);
    return rc;
}
