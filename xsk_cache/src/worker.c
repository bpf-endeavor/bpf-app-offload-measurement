#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "log.h"
#include "config.h"
#include "worker.h"
#include "checksum.h"

struct memcached_udp_header {
    __be16 request_id;
    __be16 seq_num;
    __be16 num_dgram;
    __be16 unused;
    char data[];
} __attribute__((__packed__));

#define SERVER_PORT 11211
#define MAX_KEY_SIZE 255
#define MAX_RESP_SIZE 1500
#define MIN_FRAME_SIZE (sizeof(struct ethhdr) \
		+ sizeof(struct iphdr) \
		+ sizeof(struct udphdr) \
		+ sizeof(struct memcached_udp_header))


static const struct memcached_udp_header *get_memcd_hdr(const uint8_t *raw, size_t size)
{
	if (size < MIN_FRAME_SIZE)
		return NULL;
	const struct ethhdr *eth = (struct ethhdr *)raw;
	const struct iphdr *ip = (struct iphdr *)(eth + 1);
	const struct udphdr *udp = (struct udphdr *)(ip + 1);
	const struct memcached_udp_header *mcd = (struct memcached_udp_header *)(udp + 1);

	if (eth->h_proto != ntohs(ETH_P_IP))
		return NULL;
	if (ip->protocol != IPPROTO_UDP)
		return NULL;
	if (ip->ihl != 5)
		return NULL;
	if (udp->dest != ntohs(SERVER_PORT))
		return NULL;
	return mcd;
}

// 2048 bytes of random characters
static const char *const random_string =
"rxrwrcehuueptnszmrcrhjzierzttcbqxgojbikrekkfavkujjfxmfvhkrkenbeebpjwht"
"zigogrfvugefbczqvlkdvunvjtolvaejhpcdyqtskfbofteulibapcgnsdskdauquudzli"
"ixlsyozzlnhxupgrnxomafocqvnhgynyeymfhbjvvltajtdbwpqdpvmslbdipbzollyikn"
"jeqbyakvwglhqxawmoevdpqjyufbzijrkokmzqkitnxgnlqrffbxozoexmkbpudphhhbzn"
"oeuomgojnhzjggncmrdotrghqpjfazgolawaftszzbkoaoymeqaazdnoycikcfibmfbera"
"lzekjngkrdnxzvzqfyxpptgdpalukklhiewxfrltnbppmdgnccyxkyglndisxfszrimeuj"
"oeedqtiqypmhdpjbvwaiyqgzybrvedcpeinjqzhugdjijyeqqbjuxladrbywodwbqbskpd"
"qpuczyqwlxkgpkkborbzawqxlvyfdvzwziuzrlhoubzhyntzhkfwqoruxbugzinnjbvjgl"
"hirllnxnxekubpkanpksnqqwhmjtlncsypbgpcxgtsknmvkhsnmxoldsdldtcuxgxjwnfc"
"ikcfaxojzrcefqirgcyzgyhdakppsqkshceabsnfhrhfrxrohlyuuxwjdhknsfltdrgqga"
"wmjovncjpuityathioufzolxfhgtnydbtfzyepmqbuznzbimdvytwnkjfzzccrltgsctyf"
"osjxrsjbjczwtoxwvskdomuywiazjxqasgpvklzxpqddewhtzhmyahaorfhujzyexffdgu"
"lwnplhofysjzpxruxopzxsddfkjcsfpkgfvqkltkodqvlzftvogcqljtymqrijarywzlzp"
"jcoxfjtuvbpqbgklxtinrpkeukbowptytlsldgtmrepafwpfahdickabdjvnadmmefloef"
"kqbsxbyrtmrdfkahcacxzjsoxbdqnycrguwcvzmkgamhqudopzunzgrcgtiefbaqgymovx"
"xfikfmgeoocmawbbegwrvtyrlckgfsqvwybxslcphkuvatvovqnvzdijkmpurblerwqvfo"
"igdderuiedduubglpkqjzohgapduxoreujcsklqqbdwtlosykgxcmzjarzmnhjdrqgsrzr"
"yjqgjxrimmnqysdgfcbtesovhyvaocptmoqkbrczyokzcnwqfkmlkzoajcywickirlblns"
"ylpxhzkkxizerkktmqiiysemasutagptgjqyoauxtveagbpalbyphmftihemtelvoaevbn"
"jruphpzzxrryjoinppoekwselocxfzgacoodttsjfrdafeiagrwhjkhmzvfzqvekykqydc"
"gbpmejjkrqehqefyewjhaybskzcznnwyjziqbyrslterhgtclrnrdnfpdjtzpplaeazqit"
"ksghfmxitamtltfdeqwdjghrkngequddzylizcfnhzffvwjdgrcrcgketyvjdflpimztpu"
"iktguthnpxaxqurrtuddqsknbsbadifiexhgrvwlkbhtzpridbgnwsinadpnemjnzhqtqw"
"wnjyeieuwqsyfhccvdumxqrlidxhrkpxigixoeclxunalcqiudbsfvoobujaghudauiwlm"
"jdcifphwkekjrxzhqghbwojrmzdoshvyngqpyzvxetvbgfrqgmgfczzcgxsrebfhqjhjon"
"bnhtzibntoskvbcuwajwehoqksrcvqtzscthtolkboudiwwtqzpuvlvbswidhyahlpxhdq"
"acqtezubpqufhjjbafyfndimljxarfcpuaumygikfmatcsblymudshttknnznmyyhsallb"
"sskclceiptepijfhoickmvnpwtmrzdbgoltyonodbgnahaimpfyymjnmwjoewmpgslvavr"
"tbuqihrkyqigiopysjvjikhjajckgpwumkhsbdaunqzuwaqyhtmctighbonpnyjqepkefg"
"hbrihxnngrdakbuutn";

static void add_header_to_resp_buffer(worker_t *w, uint16_t payload_size)
{
	struct ethhdr *eth = (struct ethhdr *)w->req.buffer;
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	struct memcached_udp_header *mcd = (struct memcached_udp_header *)(udp + 1);

	struct ethhdr *r_eth = (struct ethhdr *)w->resp.buffer;
	struct iphdr *r_ip = (struct iphdr *)(r_eth + 1);
	struct udphdr *r_udp = (struct udphdr *)(r_ip + 1);
	struct memcached_udp_header *r_mcd = (struct memcached_udp_header *)(r_udp + 1);

	memcpy(&r_eth->h_source, &eth->h_dest, 6);
	memcpy(&r_eth->h_dest,   &eth->h_source, 6);
	memcpy(&r_eth->h_proto,  &eth->h_proto, 2);

	memcpy(&r_ip->saddr, &ip->daddr, 4);
	memcpy(&r_ip->daddr, &ip->saddr, 4);
	r_ip->ihl = 5;
	r_ip->version = 4;
	r_ip->tos = 0;
	r_ip->tot_len = htons(20 + 8 + sizeof(*r_mcd) + payload_size); // <--
	r_ip->id = 0;
	r_ip->frag_off = 0;
	r_ip->ttl = 64;
	r_ip->protocol = IPPROTO_UDP;
	r_ip->check = 0; // <--
	r_ip->check = compute_ip_checksum((uint16_t *)r_ip, 20);

	memcpy(&r_udp->source, &udp->dest, 2);
	memcpy(&r_udp->dest, &udp->source, 2);
	r_udp->len = htons(8 + sizeof(*r_mcd) + payload_size);
	r_udp->check = 0; // <--

	*r_mcd = *mcd; // copy exactly
}

static int prepare_response(worker_t *w, const char *key, size_t key_len)
{
	int key_value;
	sscanf(key, "%d", &key_value);

	char *payload = (char *)w->resp.buffer + MIN_FRAME_SIZE;
	int value_size = 0;
	const char *text = NULL;
	char value_size_str[8];

	if (key_value == 0) {
		// not fitting inside bmc
		value_size = 1100;
		text = random_string;
	} else if (key_value == 1) {
		// fitting inside bmc
		value_size = 1000;
		text = random_string + 500;
	} else {
		DEBUG("unexpected key\n");
		return 1;
	}


	int tmp = snprintf(value_size_str, 8, "%u", value_size);
	if (tmp < 0) {
		ERROR("failed converting response size to string\n");
		return 1;
	}
	uint16_t payload_size = 6 + 1 + 2 + 5 + tmp + key_len + value_size;
	if (payload_size + MIN_FRAME_SIZE > MAX_RESP_SIZE) {
		ERROR("response to large");
		return 1;
	}
	/* DEBUG("key: %s (%d) --> payload size: %d\n", key, key_len, payload_size); */

	// Copy headers and swap addresses
	add_header_to_resp_buffer(w, payload_size);

	char *p = payload;
	// VALUE <key> <flags> <bytes> [<cas unique>]\r\n
	// <data block>\r\n
	// END\r\n
	memcpy(p, "VALUE ", 6);
	p += 6;

	memcpy(p, key, key_len);
	p += key_len;
	p[0] = ' '; p += 1;

	p[0] = '0'; p[1] = '0'; p += 2; // flag
	p[0] = ' '; p += 1;

	memcpy(p, value_size_str, tmp);
	p += tmp;

	p[0] = '\r'; p[1] = '\n'; p += 2; // \r\n

	// data block
	memcpy(p, text, value_size);
	p += value_size;
	p[0] = '\r'; p[1] = '\n'; p += 2; // \r\n

	memcpy(p, "END\r\n", 5);
	p += 5;

	w->resp.size = MIN_FRAME_SIZE + payload_size; // headers + payload
	return 0;
}

void *worker_main(void *_arg)
{
	INFO("worker starting ...\n");
	worker_t *self = (worker_t *)_arg;
	uint64_t wakeup_signal;
	char *key = malloc(MAX_KEY_SIZE+1);
	self->resp.buffer = malloc(MAX_RESP_SIZE);
	self->resp.size = 0;
	if (key == NULL) {
		ERROR("failed to allocate key-buffer\n");
		return (void *)1;
	}
	while (!config.terminate) {
		// block until notified from dispatcher
		int ret = read(self->wakeup_fd, &wakeup_signal, sizeof(uint64_t));
		/* DEBUG("worker awaken ...\n"); */
		if (ret == -1) {
			ERROR("Something went wrong while blocking on the wakeup fd\n");
			continue;
		}
		// Get the raw frame of request
		const size_t frame_size = self->req.size;
		const void *const raw = self->req.buffer;
		const struct memcached_udp_header *mcd;
		// Check it is UDP and for our service
		mcd = get_memcd_hdr(raw, frame_size);
		if (mcd == NULL) {
			DEBUG("unexpected packet!\n");
			self->status_ = DROP;
			continue;
		}
		uint16_t num_dgram = ntohs(mcd->num_dgram);
		if (num_dgram != 1) {
			DEBUG("unexpected number of datagrams (%d)\n", num_dgram);
			self->status_ = DROP;
			continue;
		}
		const char *query = (char *)(mcd + 1);
		if (strncmp(query, "get ", 4) != 0) {
			DEBUG("unsupported command\n");
			self->status_ = DROP;
			continue;
		}
		const char *key_ptr = query + 4;
		const size_t off = MIN_FRAME_SIZE + 4;
		const size_t remaining = frame_size - off;
		size_t key_len = 0;
		for (key_len = 0; key_len < MAX_KEY_SIZE && key_len < remaining; key_len++) {
			if (key_ptr[key_len] == ' ' || key_ptr[key_len] == '\r')
				break;
		}
		memcpy(key, key_ptr, key_len);
		key[key_len] = '\0'; // null termiante the key string
		if (prepare_response(self, key, key_len) != 0) {
			self->status_ = DROP;
			continue;
		}
		self->status_ = TRANSMIT;
		continue;
	}
	free(self->resp.buffer);
	return NULL;
}
