#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>

struct route_table_entry* rtable;
int length_rtable;

typedef struct pack {
	char buf[MAX_PACKET_LEN];
	int interface;
	size_t len;
} pack;

typedef struct Cache_node {
	uint32_t dest_ip;
	uint8_t mac[6];
	queue packs;
	struct Cache_node *next;
} Cache_node;

Cache_node *cache = NULL;
Cache_node *packs = NULL;

// I am looking for the best route in the routing table.
struct route_table_entry *get_best_route(uint32_t ip_dest) {

	struct route_table_entry *best_route = NULL;
	for (int i = 0; i < length_rtable; i++) {
		if ((rtable[i].prefix & rtable[i].mask) == (ip_dest & rtable[i].mask)) {
			if (best_route == NULL) {
				best_route = &rtable[i];
			} 
			else if (ntohl(rtable[i].mask) > ntohl(best_route->mask)) {
				best_route = &rtable[i];
			}
		}
	}
	return best_route;
}


Cache_node* enqueue_cache(Cache_node **head, u_int32_t dest_ip) {
	Cache_node *new_node = (Cache_node *) calloc(1, sizeof(Cache_node));
	new_node->dest_ip = dest_ip;
	
	if (*head == NULL) {
		*head = new_node;
	}
	else {
		new_node->next = *head;
		*head = new_node;
	}
	return new_node;
}

// function through which I send the predestined packets to the given IP (used when I
// receive an ARP reply packet)
void send_packs(u_int32_t ip, uint8_t mac[]) {
	Cache_node *curr = packs;
	Cache_node *prev = NULL;
	while (curr != NULL) {
		if (curr->dest_ip == ip) {
			while (!queue_empty(curr->packs)) {
				pack *p = (pack *) queue_deq(curr->packs);
				struct ether_header *eth_hdr = (struct ether_header *) p->buf;
					memcpy(eth_hdr->ether_dhost, mac, 6);				
					send_to_link(p->interface, p->buf, p->len);
					free(p);
			}
			if (prev != NULL) {
				prev->next = curr->next;
			}
			free(curr);
			break;
		}
		prev = curr;
		curr = curr->next;
	}
}

void free_list(Cache_node *head) {
	Cache_node *curr = head;
	while (curr != NULL) {
		head = head->next;
		free(curr);
		curr = head;
	}
}

// Function where I search for a node in the cache by ip
Cache_node *search_node(u_int32_t dest_ip, Cache_node *head) {
	Cache_node *curr = head;
	while (curr != NULL) {
		if (curr->dest_ip == dest_ip) {
			return curr;
		}
		curr = curr->next;
	}
	return NULL;
}

// function in which I build the ARP request
void send_req(struct route_table_entry *best_router) {
	char buf[MAX_PACKET_LEN];
 
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	eth_hdr->ether_type = htons(0x0806);
	memset(eth_hdr->ether_dhost, 255, 6);
	get_interface_mac(best_router->interface, eth_hdr->ether_shost);

	struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
	memset(arp_hdr->tha, 0, 6);

	arp_hdr->spa = inet_addr(get_interface_ip (best_router->interface));
	arp_hdr->tpa = best_router->next_hop;

	send_to_link(best_router->interface, buf, sizeof(struct ether_header) + sizeof (struct arp_header));
}

// function in which I build the ICMP header
void unreachable_pack(struct ether_header* eth_hdr, struct iphdr* ip_hdr, int interface, uint8_t type) {
	char unreached_pack[sizeof(struct ether_header) + sizeof (struct iphdr) + sizeof(struct icmphdr)];

	struct ether_header* eth_unreached = (struct ether_header*) unreached_pack;
	struct iphdr* ip_unreached = (struct iphdr*) (unreached_pack + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *) (unreached_pack + sizeof(struct ether_header) + sizeof(struct iphdr));

	memcpy(eth_unreached->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_unreached->ether_shost);
	eth_unreached->ether_type = htons(0x0800);

	ip_unreached->daddr = ip_hdr->saddr;
	ip_unreached->saddr = ip_hdr->daddr;
	ip_unreached->frag_off = 0;
	ip_unreached->tos = 0;
	ip_unreached->protocol = 1;
	ip_unreached->ttl = 64;
	ip_unreached->check = checksum((uint16_t*) ip_hdr, sizeof(struct iphdr));
	ip_unreached->version = 4;
	ip_unreached->ihl = 5;
	ip_unreached->id = htons(1);
	ip_unreached->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, unreached_pack, sizeof(struct ether_header) + sizeof (struct iphdr) + sizeof(struct icmphdr));
			
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");
	length_rtable = read_rtable(argv[1], rtable);

	
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (ntohs(eth_hdr->ether_type) == 0x0800) {

			// check the checksum and TTL for the received packet and if they are not correct I
			// send them back to the source (ICMP), otherwise I update them for further use

			struct iphdr *ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));
			if (checksum((uint16_t*) ip_hdr, sizeof(struct iphdr)) != 0) {
				continue;
			}

			if (ip_hdr->ttl <= 1) {
				unreachable_pack(eth_hdr, ip_hdr, interface, 11);
				continue;
			}
			uint16_t old_sum = ip_hdr->check;
			uint8_t old_ttl = ip_hdr->ttl;

			ip_hdr->ttl--;
			ip_hdr->check = ~(~old_sum + ~((u_int16_t)old_ttl) + (uint8_t)ip_hdr->ttl) - 1;

			// I find the best route based on the destination IP address and if it doesn't exist I send the packet back.

			struct route_table_entry* best_router = get_best_route(ip_hdr->daddr);
			if (best_router == NULL) {
				unreachable_pack(eth_hdr, ip_hdr, interface, 3);
				continue;
			}

			// if I received an ICMP packet as a request, I send it back to the source
			struct icmphdr *reply = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (reply != NULL && inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
				if (reply->type == 8) {
					unreachable_pack(eth_hdr, ip_hdr, interface, 0);
					continue;
				}
			}

			// I search the cache to see if there is an IP address after the next hop of the best route.
			Cache_node *arp = search_node(best_router->next_hop, cache);

			// if I don't find it, I have to send a request to get the mac address (I use an auxiliary "cache")
			if (arp == NULL) {
				send_req(best_router);
				get_interface_mac(best_router->interface, eth_hdr->ether_shost);

				pack *p = (pack *) calloc(1, sizeof(pack));
				memcpy(p->buf, buf, len);
				p->interface = best_router->interface;
				p->len = len;

				Cache_node *pack_node = search_node(best_router->next_hop, packs);
				
				if (pack_node == NULL) {

					pack_node = enqueue_cache(&packs, best_router->next_hop);
					pack_node->packs = queue_create();
				}
				queue_enq(pack_node->packs, p);
			}

			else {

				// the package is in the cache so I'm sending it

				memcpy(eth_hdr->ether_dhost, arp->mac, 6);
				get_interface_mac(best_router->interface, eth_hdr->ether_shost);
				send_to_link(best_router->interface, buf, len);
			}
		}
		else if (ntohs(eth_hdr->ether_type) == 0x0806) {
	
			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
			if (htons(arp_hdr->op) == 1) {

				// I build my reply to send when I
				// arrive at my destination

				if (inet_addr(get_interface_ip (interface)) != arp_hdr->tpa) {
					continue;
				}
				char reply_buf[MAX_PACKET_LEN];
				struct ether_header *eth_hdr_reply = (struct ether_header *) reply_buf;
				
				eth_hdr_reply->ether_type = htons(0x0806);
				memcpy(eth_hdr_reply->ether_dhost, arp_hdr->sha, 6); 
				get_interface_mac(interface, eth_hdr_reply->ether_shost);


				struct arp_header *arp_hdr_reply = (struct arp_header *) (reply_buf + sizeof(struct ether_header));
				arp_hdr_reply->htype = htons(1);
				arp_hdr_reply->ptype = htons(0x0800);
				arp_hdr_reply->hlen = 6;
				arp_hdr_reply->plen = 4;
				arp_hdr_reply->op = htons(2);

				memcpy(arp_hdr_reply->sha, eth_hdr_reply->ether_shost, 6); 
				memcpy(arp_hdr_reply->tha, arp_hdr->sha, 6);

				arp_hdr_reply->spa = arp_hdr->tpa;
				arp_hdr_reply->tpa = arp_hdr->spa;
				send_to_link(interface, reply_buf, sizeof(struct ether_header) + sizeof (struct arp_header));
			}
			else if(htons(arp_hdr->op) == 2) {

				// if I received a reply, I send all packets destined for this address and also add it
				// to the cache

				Cache_node* cache_node = enqueue_cache(&cache, arp_hdr->spa);
				memcpy(cache_node->mac, arp_hdr->sha, 6);

				send_packs(arp_hdr->spa, arp_hdr->sha);
			}
		}
	}
	free_list(cache);
	free_list(packs);
	free(rtable);
}

