import scapy.all as scapy

def process_packet(packet):
	packet.show()

a= scapy.sniff(Protocol='OpenFlow')
#for packet in PcapReader('capture.pcap'):
print(a)


#if __name__ == "__main__":
#	main()
