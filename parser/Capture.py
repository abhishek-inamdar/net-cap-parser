class Packet:
    __slots__ = 'line1', 'byteList', 'id', \
                'destination_mac', 'source_mac', 'dest_mac_type', \
                'ether_type', 'ether_length', 'layer2_type'

    def __init__(self, line1, line2):
        self.line1 = line1
        self.byteList = [l.strip() for l in line2.split('|') if l.strip()]
        self.id = self.byteList[0]
        del self.byteList[0]

        # layer 2 values
        dest_mac_start = self.byteList.__getitem__(0)
        if dest_mac_start == '01':
            self.dest_mac_type = 'Multicast'
        elif dest_mac_start == 'ff':
            self.dest_mac_type = 'Broadcast'
        else:
            self.dest_mac_type = 'Unicast'

        self.destination_mac = ''
        for i in range(6):
            self.destination_mac = self.destination_mac + self.byteList.__getitem__(i) + ':'
        self.destination_mac = self.destination_mac[:-1]

        self.source_mac = ''
        for i in range(6, 12):
            self.source_mac = self.source_mac + self.byteList.__getitem__(i) + ':'
        self.source_mac = self.source_mac[:-1]

        deciderHex = self.byteList.__getitem__(12) + self.byteList.__getitem__(13)
        decider10 = int(deciderHex, 16)

        if decider10 <= 1500:
            self.ether_length = decider10
            self.ether_type = None
            self.layer2_type = 'IEEE 802.3 Ethernet'
        else:
            self.ether_length = None
            self.ether_type = deciderHex
            self.layer2_type = 'Ethernet II'

    def __str__(self):
        string = '\tType = ' + self.layer2_type \
                 + '\n\tDestination MAC Address = ' + self.destination_mac + ' (' + self.dest_mac_type + ')' \
                 + '\n\tSource MAC Address = ' + self.source_mac

        if self.layer2_type == 'Ethernet II':
            string = string + self.get_ethernet_2_data()
        else:
            string = string + self.get_802_data()
        return string + '\n'

    def get_byte_length(self):
        return len(self.bytes)

    def get_ethernet_2_data(self):
        protocol_type = ''
        if self.ether_type == '0806':
            protocol_type = 'ARP'
        elif self.ether_type == '0800':
            protocol_type = 'IPv4'
        else:
            protocol_type = 'Unknown'
        string = '\n\tType = ' + protocol_type + '(' + self.ether_type + ')'
        return string

    def get_802_data(self):
        string = '\n\tLength= ' + str(self.ether_length)
        string = string + self.get_802_2_header_data()
        if self.byteList.__getitem__(17) + self.byteList.__getitem__(18) == '0000':
            string = string + '\n\tProtocol Identifier: Spanning Tree Protocol (0x0000)'
            string = string + self.get_STP_data()
        else:
            string = string + '\n\tProtocol Identifier: Unknown'
        return string

    def get_802_2_header_data(self):
        string = '\n\tDSAP = ' + '(0x' + self.byteList.__getitem__(14) + ')'
        string = string + '\n\tSSAP = ' + '(0x' + self.byteList.__getitem__(15) + ')'
        string = string + '\n\tControl = ' + '(0x' + self.byteList.__getitem__(16) + ')'
        return string

    def get_STP_data(self):
        string = '\n\tProtocol Version Identifier = ' + '(0x' + self.byteList.__getitem__(19) + ')'
        string = string + '\n\tBPDU Type = ' + '(0x' + self.byteList.__getitem__(20) + ')'
        string = string + '\n\tBPDU flags = ' + '(0x' + self.byteList.__getitem__(21) + ')'

        string = string + '\n\tRoot identifier:'
        root_total_str = self.byteList.__getitem__(22) + self.byteList.__getitem__(23)
        root_total = int(root_total_str, 16)
        root_extension = int(root_total_str[1:], 16)
        string = string + '\n\t\tRoot Bridge Priority: ' + str(root_total - root_extension)
        string = string + '\n\t\tRoot Bridge System ID Extension: ' + str(root_extension)
        string = string + '\n\t\tRoot Bridge System ID: '
        for i in range(24, 30):
            string = string + self.byteList.__getitem__(i) + ':'
        string = string[:-1]

        cost_str = ''
        for i in range(30, 34):
            cost_str = cost_str + self.byteList.__getitem__(i)
        string = string + '\n\tRoot Cost: ' + str(int(cost_str, 16))

        string = string + '\n\tBridge identifier:'
        bridge_total_str = self.byteList.__getitem__(34) + self.byteList.__getitem__(35)
        bridge_total = int(bridge_total_str, 16)
        bridge_extension = int(bridge_total_str[1:], 16)
        string = string + '\n\t\tBridge Priority: ' + str(bridge_total - bridge_extension)
        string = string + '\n\t\tBridge System ID Extension: ' + str(bridge_extension)
        string = string + '\n\t\tBridge System ID: '
        for i in range(36, 42):
            string = string + self.byteList.__getitem__(i) + ':'
        string = string[:-1]

        string = string + '\n\tPort identifier:' + '(0x' \
                 + self.byteList.__getitem__(42) + self.byteList.__getitem__(43) + ')'

        string = string + '\n\tMessage Age: ' + str(int(self.byteList.__getitem__(44), 16))

        string = string + '\n\tMax Age: ' + str(int(self.byteList.__getitem__(46), 16))

        string = string + '\n\tHello Time: ' + str(int(self.byteList.__getitem__(48), 16))

        string = string + '\n\tForward Delay: ' + str(int(self.byteList.__getitem__(50), 16))

        string = string + '\n\tPadding: '
        for i in range(52, len(self.byteList)):
            string = string + self.byteList.__getitem__(i)

        return string


class Capture:
    __slots__ = 'packets',

    def __init__(self, packets):
        self.packets = packets

    def get_packet_count(self):
        return len(self.packets)
