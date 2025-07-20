/* vim: set et ts=4 sw=4: */
#include <stdio.h>
#include <assert.h>
#include "bmc_common.h"
#include "bpf_userspace_helpers.h"

struct memcached_udp_header {
    __be16 request_id;
    __be16 seq_num;
    __be16 num_dgram;
    __be16 unused;
    char data[];
} __attribute__((__packed__));

#define MEMCD_HDR_SIZE sizeof(struct memcached_udp_header)

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

/* static int stats_map_fd; */
static int kcache_map_fd;
static bool initilized = false;

/* Initialize the things we need for BMC tx path. For example the map handles
 * */
int bmc_initilize(void)
{
    int ret = find_map_by_name("map_kcache");
    if (ret < 0) {
        return -1;
    }
    kcache_map_fd = ret;
    initilized = true;
    return 0;
}

static int bmc_update_cache(char *payload, char *data_end)
{
  int ret;
  u32 hash = FNV_OFFSET_BASIS_32;

  // compute the key hash
  for (unsigned int off = 6; off-6 < BMC_MAX_KEY_LENGTH && payload+off+1 <= data_end && payload[off] != ' '; off++) {
    hash ^= payload[off];
    hash *= FNV_PRIME_32;
  }

  /* printf("hash: %u\n", hash); */
  u32 cache_idx = hash % BMC_CACHE_ENTRY_COUNT;
  struct bmc_cache_entry e;
  ret = bpf_map_lookup_elem(kcache_map_fd, &cache_idx, &e);
  if (ret != 0 ) {
	  printf("failed to lookup element\n");
      return -1;
  }
  struct bmc_cache_entry *entry = &e;

  if (entry->valid && entry->hash == hash) { // cache is up-to-date; no need to update
    int diff = 0;
    for (unsigned int off = 6; off-6 < BMC_MAX_KEY_LENGTH && payload+off+1 <= data_end && off < entry->len && (payload[off] != ' ' || entry->data[off] != ' '); off++) {
      if (entry->data[off] != payload[off]) {
        diff = 1;
        break;
      }
    }
    if (diff == 0) {
	printf("cache is already up to date!\n");
      return 0;
    }
  }

  unsigned int count = 0;
  entry->len = 0;
  // store the reply from start to the '\n' that follows the data
  for (unsigned int j = 0; j < BMC_MAX_CACHE_DATA_SIZE && payload+j+1 <= data_end && count < 2; j++) {
    entry->data[j] = payload[j];
    entry->len++;
    if (payload[j] == '\n')
      count++;
  }

  if (count == 2) { // copy OK
    entry->valid = 1;
    entry->hash = hash;
    bpf_map_update_elem(kcache_map_fd, &cache_idx, entry, BPF_F_LOCK);
  } else {
	  printf("failed to update the cache\n");
  }

  return 0;
}

int bmc_tx_filter_main(char *buffer, uint16_t size)
{
  if (!initilized) {
    printf("bmc not ready\n");
    return 0;
  }

  // frag
  char *payload = buffer + 14 + 20 + 8 + MEMCD_HDR_SIZE;
  char *data_end = buffer + size;

  uint16_t payload_size = data_end - payload;
  /* printf("payload_size: %u\n", payload_size); */

  // if the size exceeds the size of a cache entry do not bother going further
  if (payload_size > BMC_MAX_CACHE_DATA_SIZE + MEMCD_HDR_SIZE)
    return 0;

  if (payload+5+1 <= data_end && payload[0] == 'V' && payload[1] == 'A' && payload[2] == 'L'
      && payload[3] == 'U' && payload[4] == 'E' && payload[5] == ' ') { // if this is a GET reply

    /* struct bmc_stats stats; */
    /* ret = bpf_map_lookup_elem(stats_map_fd, &zero, &stats); */
    /* if (ret != 0) { */
    /*   return -1; */
    /* } */
    /* stats.get_resp_count++; */
    /* bpf_map_update_elem(stats_map_fd, &zero, &stats, BPF_EXIST); */

    // bpf_tail_call(skb, &map_progs_tc, BMC_PROG_TC_UPDATE_CACHE);
    int ret = bmc_update_cache(payload, data_end);
    if (ret != 0) {
        return ret;
    }
  } else {
    printf("not a value response!\n%s\n", payload);
  }

  return 0;
}
