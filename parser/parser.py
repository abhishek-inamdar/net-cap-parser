"""
file: parser.py
description: This program will parse K-12 Text file of Network Packet Capture
    and print the field representation as per standards.
    Protocols Covered: 802.2, 802.3, STP, ARP, ICMP, IGMP, IPv4, TCP, UDP.
language: python3
author: Abhishek Inamdar (ai2363@rit.edu)
"""
import sys


class STP(object):
    __slots__ = 'byteList', 'versionId', 'bType', 'bFlag', 'rootPriority', \
                'rootSysIdExt', 'rootSysId', 'cost', 'bridgePriority', \
                'bridgeSysIdExt', 'bridgeSysId', 'portId', 'messageAge', \
                'maxAge', 'helloTime', 'delay', 'padding'

    def __init__(self, byteList):
        self.byteList = byteList
        self.versionId = byteList[0]
        self.bType = byteList[1]
        self.bFlag = byteList[2]
        root_total_str = byteList[3] + byteList[4]
        root_total = int(root_total_str, 16)
        root_extension = int(root_total_str[1:], 16)
        self.rootPriority = root_total - root_extension
        self.rootSysIdExt = root_extension
        self.rootSysId = ''
        for i in range(5, 11):
            self.rootSysId += self.byteList[i] + ':'
        self.rootSysId = self.rootSysId[:-1]
        cost_str = ''
        for i in range(11, 15):
            cost_str = cost_str + self.byteList[i]
        self.cost = int(cost_str, 16)

        bridge_total_str = byteList[15] + byteList[16]
        bridge_total = int(bridge_total_str, 16)
        bridge_extension = int(bridge_total_str[1:], 16)
        self.bridgePriority = bridge_total - bridge_extension
        self.bridgeSysIdExt = bridge_extension
        self.bridgeSysId = ''
        for i in range(17, 23):
            self.bridgeSysId += byteList[i] + ':'
        self.bridgeSysId = self.bridgeSysId[:-1]
        self.portId = byteList[23] + byteList[24]
        self.messageAge = int(byteList[25], 16)
        self.maxAge = int(byteList[26] + byteList[27], 16)
        self.helloTime = int(byteList[28] + byteList[29], 16)
        self.delay = int(byteList[30] + byteList[31], 16)
        self.padding = ''
        for i in range(32, len(byteList)):
            self.padding += byteList[i]

    def __str__(self):
        string = '\n\tProtocol Version Identifier = ' + '(0x' + self.versionId + ')'
        string += '\n\tBPDU Type = ' + '(0x' + self.bType + ')'
        string += '\n\tBPDU flags = ' + '(0x' + self.bFlag + ')'
        string += '\n\tRoot identifier:'
        string += '\n\t\tRoot Bridge Priority: ' + str(self.rootPriority)
        string += '\n\t\tRoot Bridge System ID Extension: ' + str(self.rootSysIdExt)
        string += '\n\t\tRoot Bridge System ID: ' + self.rootSysId
        string += '\n\tRoot Cost: ' + str(self.cost)
        string += '\n\tBridge identifier:'
        string += '\n\t\tBridge Priority: ' + str(self.bridgePriority)
        string += '\n\t\tBridge System ID Extension: ' + str(self.bridgeSysIdExt)
        string += '\n\t\tBridge System ID: ' + self.bridgeSysId
        string += '\n\tPort identifier:' + '(0x' + self.portId + ')'
        string += '\n\tMessage Age: ' + str(self.messageAge)
        string += '\n\tMax Age: ' + str(self.maxAge)
        string += '\n\tHello Time: ' + str(self.helloTime)
        string += '\n\tForward Delay: ' + str(self.delay)
        string += '\n\tPadding: ' + self.padding
        return string


class Packet802(object):
    __slots__ = 'byteList', 'ether_length', 'dsap', 'ssap', 'control', 'pId', \
                'pDesc', 'stp'

    def __init__(self, byteList):
        self.byteList = byteList
        self.ether_length = int(byteList[0] + byteList[1], 16)
        self.dsap = byteList[2]
        self.ssap = byteList[3]
        self.control = byteList[4]
        self.pId = byteList[5] + byteList[6]
        if self.pId == '0000':
            self.pDesc = 'Spanning Tree Protocol'
            self.stp = STP(byteList[7:])
        else:
            self.pDesc = 'Unknown'

    def __str__(self):
        string = '\n\tLength= ' + str(self.ether_length)
        string += '\n\tDSAP = ' + '(0x' + self.dsap + ')'
        string += '\n\tSSAP = ' + '(0x' + self.ssap + ')'
        string += '\n\tControl = ' + '(0x' + self.control + ')'
        string += '\n\tProtocol Identifier: ' + self.pDesc + '(0x' + self.pId + ')'
        if self.stp:
            string += str(self.stp)
        return string


class ARP(object):
    __slots__ = 'byteList', 'hwType', 'hwDesc', 'pType', 'pDesc', 'hwSize', \
                'pSize', 'opCode', 'srcMAC', 'srcIP', 'destMAC', 'destIP', \
                'padding'

    def __init__(self, byteList):
        self.byteList = byteList
        self.hwType = int(byteList[0] + byteList[1], 16)
        if self.hwType == 1:
            self.hwDesc = 'Ethernet'
        else:
            self.hwDesc = 'Unknown'
        self.pType = byteList[2] + byteList[3]
        if self.pType == '0800':
            self.pDesc = 'IPv4'
        else:
            self.pDesc = 'Unknown'
        self.hwSize = int(byteList[4], 16)
        self.pSize = int(byteList[5])
        self.opCode = int(byteList[6] + byteList[7], 16)

        self.srcMAC = ''
        for i in range(8, 14):
            self.srcMAC += byteList[i] + ':'
        self.srcMAC = self.srcMAC[:-1]

        self.srcIP = ''
        for i in range(14, 18):
            self.srcIP += str(int(byteList[i], 16)) + '.'
        self.srcIP = self.srcIP[:-1]

        self.destMAC = ''
        for i in range(18, 24):
            self.destMAC += byteList[i] + ':'
        self.destMAC = self.destMAC[:-1]

        self.destIP = ''
        for i in range(24, 28):
            self.destIP += str(int(byteList[i], 16)) + '.'
        self.destIP = self.destIP[:-1]

        self.padding = ''
        for i in range(28, len(byteList)):
            self.padding += byteList[i]

    def __str__(self):
        string = '\n\tHardware Type: '
        string += self.hwDesc + '(' + str(self.hwType) + ')'
        string += '\n\tProtocol Type: ' + self.pDesc + '(0x' + self.pType + ')'
        string += '\n\tHardware size: ' + str(self.hwSize)
        string += '\n\tProtocol size: ' + str(self.pSize)
        string += '\n\tOpcode: '
        if self.opCode == 1:
            string += 'request'
        elif self.opCode == 2:
            string += 'reply'
        string += ' (' + str(self.opCode) + ')'
        string += '\n\tSender MAC Address: ' + self.srcMAC
        string += '\n\tSender IP Address: ' + self.srcIP
        string += '\n\tTarget MAC Address: ' + self.destMAC
        string += '\n\tTarget IP Address: ' + self.destIP
        if len(self.padding) > 0:
            string += '\n\tPadding: ' + self.padding

        return string


class ICMP(object):
    __slots__ = 'byteList', 'type', 'typeDesc', 'code', 'checksum', 'id', \
                'seqNum'

    def __init__(self, byteList):
        self.byteList = byteList
        self.type = int(self.byteList[0], 16)
        if self.type == 0:
            self.typeDesc = 'Echo Reply'
        elif self.type == 3:
            self.typeDesc = 'Destination Unreachable'
        elif self.type == 4:
            self.typeDesc = 'Source Quench'
        elif self.type == 5:
            self.typeDesc = 'Redirect'
        elif self.type == 8:
            self.typeDesc = 'Echo Request'
        elif self.type == 11:
            self.typeDesc = 'Time Exceeded'
        elif self.type == 12:
            self.typeDesc = 'Parameter Problem'
        elif self.type == 13:
            self.typeDesc = 'Timestamp'
        elif self.type == 14:
            self.typeDesc = 'Timestamp Reply'
        elif self.type == 15:
            self.typeDesc = 'Information Request'
        elif self.type == 16:
            self.typeDesc = 'Information Reply'
        else:
            self.typeDesc = 'Unknown'

        self.code = int(byteList[1], 16)
        self.checksum = byteList[2] + byteList[3]
        self.id = byteList[4] + byteList[5]
        self.seqNum = byteList[6] + byteList[7]
        if self.type == 0:
            # TODO Add code for response time
            pass

    def __str__(self):
        string = '\n\tICMP:'
        string += '\n\tType: ' + str(self.type) + ' ' + self.typeDesc
        string += '\n\tCode: ' + str(self.code)
        string += '\n\tChecksum: ' + '(0x' + self.checksum + ')'
        string += '\n\tIdentifier: ' + '(0x' + self.id + ')'
        string += '\n\tSequence Number: ' + '(0x' + self.seqNum + ')'
        # data_len = len(self.byteList) - 42
        # string += '\n\tData: (' + str(data_len) + ' bytes)\n\t\t'
        # for i in range(42, len(self.byteList)):
        #     string += self.byteList[i]
        return string


class IGMP(object):
    __slots__ = 'byteList', 'type', 'typeDesc', 'maxRespTime', \
                'maxRespTimeHex', 'checksum', 'groupAddress'

    def __init__(self, byteList):
        self.byteList = byteList
        self.type = byteList[0]
        if self.type == '11':
            self.typeDesc = 'Membership Query'
        elif self.type == '16':
            self.typeDesc = 'Membership Report'
        elif self.type == '17':
            self.typeDesc = 'Leave Group'
        elif self.type == '12':
            self.typeDesc = 'Membership Report'
        elif self.type == 'ff':
            self.typeDesc = 'Hello'
        else:
            self.typeDesc = 'Unknown'
        self.maxRespTimeHex = byteList[1]
        self.maxRespTime = int(byteList[1], 16) / 10
        self.checksum = byteList[2] + byteList[3]
        self.groupAddress = ''
        for i in range(4, 8):
            self.groupAddress += str(int(self.byteList[i], 16)) + '.'
        self.groupAddress = self.groupAddress[:-1]

    def __str__(self):
        string = '\n\tIGMP:'
        string += '\n\tType: ' + self.typeDesc + ' ' + '(0x' + str(self.type) + ')'
        if self.type == '11' or self.type == '16' or self.type == '17':
            string += '\n\tMax Resp. Time: ' + str(self.maxRespTime) + ' sec ' + '(0x' + self.maxRespTimeHex + ')'
        else:
            string += '\n\tReserved: ' + '(0x' + self.maxRespTimeHex + ')'
        string += '\n\tChecksum: ' + '(0x' + self.checksum + ')'
        string += '\n\tAddress: ' + self.groupAddress
        return string


class TCP(object):
    __slots__ = 'byteList', 'srcPort', 'destPort', 'seqNumRaw', 'ackNumRaw', \
                'headerLen', 'flagsHex', 'window', 'checksum', 'urgentPtr', \
                'optHex', 'optByteLen', 'flagsBin', \
                'data', \
                'fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ecn', 'cwr', 'nonce', \
                'MSSKind', 'MSSLen', 'MSSValue', 'NOP1Kind', 'NOP2Kind', \
                'SACKKind', 'SACKLen'

    def __init__(self, byteList):
        self.byteList = byteList
        self.srcPort = int(byteList[0] + byteList[1], 16)
        self.destPort = int(byteList[2] + byteList[3], 16)
        self.seqNumRaw = int(byteList[4] + byteList[5] + byteList[6] + byteList[7], 16)
        self.ackNumRaw = int(byteList[8] + byteList[9] + byteList[10] + byteList[11], 16)
        self.headerLen = int(byteList[12][:1], 16)
        self.flagsHex = byteList[12][1:] + byteList[13]
        self.flagsBin = "{0:12b}".format(int(self.flagsHex, 16))
        for i in range(0, len(self.flagsBin)):
            if self.flagsBin[i] != ' ':
                bValue = bool(int(self.flagsBin[i]) == 1)
            else:
                bValue = False
            if i == 11:
                self.fin = bValue
            elif i == 10:
                self.syn = bValue
            elif i == 9:
                self.rst = bValue
            elif i == 8:
                self.psh = bValue
            elif i == 7:
                self.ack = bValue
            elif i == 6:
                self.urg = bValue
            elif i == 5:
                self.ecn = bValue
            elif i == 4:
                self.cwr = bValue
            elif i == 3:
                self.nonce = bValue

        self.window = int(byteList[14] + byteList[15], 16)
        self.checksum = byteList[16] + byteList[17]
        self.urgentPtr = int(byteList[18] + byteList[19], 16)
        self.optByteLen = (self.headerLen * 4) - 20
        if self.optByteLen >= 4:
            self.MSSKind = int(byteList[20], 16)
            self.MSSLen = int(byteList[21], 16)
            self.MSSValue = int(byteList[22] + byteList[23], 16)
        if self.optByteLen >= 5:
            self.NOP1Kind = int(byteList[24], 16)
        if self.optByteLen >= 6:
            self.NOP2Kind = int(byteList[25], 16)
        if self.optByteLen >= 8:
            self.SACKKind = int(byteList[26], 16)
            self.SACKLen = int(byteList[27], 16)

        self.data = ''
        if len(byteList) <= 64:
            for i in range(self.headerLen * 4, len(byteList)):
                self.data += byteList[i]
        else:
            for i in range(self.headerLen * 4, 64):
                self.data += byteList[i]
            self.data += '...'

    def __str__(self):
        string = '\n\tTCP:'
        string += '\n\tSource Port: ' + str(self.srcPort)
        string += '\n\tDestination Port: ' + str(self.destPort)
        string += '\n\tSequence Number raw: ' + str(self.seqNumRaw)
        string += '\n\tAcknowledgement Number raw: ' + str(self.ackNumRaw)
        string += '\n\tHeader Length: ' + str(self.headerLen * 4) + ' bytes ' + '(' + str(self.headerLen) + ')'
        string += '\n\tFlags: ' + '(0x' + self.flagsHex + ')'
        string += '\n\t\tNonce: ' + str(self.nonce)
        string += '\n\t\tCongestion Window Reduced (CWR): ' + str(self.cwr)
        string += '\n\t\tECN-Echo: ' + str(self.ecn)
        string += '\n\t\tUrgent: ' + str(self.urg)
        string += '\n\t\tAcknowledgement: ' + str(self.ack)
        string += '\n\t\tPush: ' + str(self.psh)
        string += '\n\t\tReset: ' + str(self.rst)
        string += '\n\t\tSYN: ' + str(self.syn)
        string += '\n\t\tFIN: ' + str(self.fin)

        string += '\n\tWindow: ' + str(self.window)
        string += '\n\tChecksum: ' + '(0x' + self.checksum + ')'
        string += '\n\tUrgent Pointer: ' + str(self.urgentPtr)
        if self.optByteLen > 0:
            string += '\n\tOptions: ' + str(self.optByteLen) + ' bytes'
            if self.optByteLen >= 4:
                string += '\n\t\tMaximum Segment size: ' + str(self.MSSValue) + ' bytes'
                string += '\n\t\t\tKind: Maximum Segment Size (' + str(self.MSSKind) + ')'
                string += '\n\t\t\tLength: ' + str(self.MSSLen)
                string += '\n\t\t\tMSS Value: ' + str(self.MSSValue)
            if self.optByteLen >= 5:
                string += '\n\t\tNo-Operation (NOP)'
                string += '\n\t\t\tKind: No-Operation (' + str(self.NOP1Kind) + ')'
            if self.optByteLen >= 6:
                string += '\n\t\tNo-Operation (NOP)'
                string += '\n\t\t\tKind: No-Operation (' + str(self.NOP2Kind) + ')'
            if self.optByteLen >= 8:
                string += '\n\t\tSACK Permitted'
                string += '\n\t\t\tKind: SACK Permitted (' + str(self.SACKKind) + ')'
                string += '\n\t\t\tLength: ' + str(self.SACKLen)
        if self.data:
            string += '\n\tData: ' + self.data
        return string


class UDP(object):
    __slots__ = 'byteList', 'srcPort', 'destPort', 'len', 'payloadLen', 'checksum', \
                'data'

    def __init__(self, byteList):
        self.byteList = byteList
        self.srcPort = int(byteList[0] + byteList[1], 16)
        self.destPort = int(byteList[2] + byteList[3], 16)
        self.len = int(byteList[4] + byteList[5], 16)
        self.payloadLen = self.len - 8
        self.checksum = byteList[6] + byteList[7]
        self.data = ''
        for i in range(8, self.len):
            self.data += byteList[i]

    def __str__(self):
        string = '\n\tUDP:'
        string += '\n\tSource Port: ' + str(self.srcPort)
        string += '\n\tDestination Port: ' + str(self.destPort)
        string += '\n\tLength: ' + str(self.len)
        string += '\n\tChecksum: ' + '(0x' + self.checksum + ')'
        string += '\n\tUDP Payload: (' + str(self.payloadLen) + ' bytes)'
        return string


class IP(object):
    __slots__ = 'byteList', 'v', 'headerLen', 'dsf', 'totalLen', 'id', 'idHex', \
                'flag', 'flagHex', 'offset', 'ttl', 'protocolId', 'protocolDesc', \
                'headerChecksum', 'srcIP', 'destIP', 'protocol', 'data', 'dataLen'

    def __init__(self, byteList):
        self.byteList = byteList
        self.v = int(byteList[0][:1], 16)
        self.headerLen = int(byteList[0][1:], 16)
        self.dsf = byteList[1]
        self.totalLen = int(byteList[2] + byteList[3], 16)
        self.idHex = byteList[4] + byteList[5]
        self.id = int(self.idHex, 16)
        self.flag = int(byteList[6][:1], 16)
        self.flagHex = byteList[6]

        # TODO: Confirm below offset calculation, it works, but doesn't make sense
        binary = "{:8b}".format(int(byteList[6] + byteList[7], 16))
        bLen = len(binary)
        offsetStart = 0
        if bLen > 12:
            offsetStart = bLen - 12
        offsetBin = binary[offsetStart:] + '000'
        self.offset = int(offsetBin, 2)

        self.ttl = int(byteList[8], 16)
        self.protocolId = int(byteList[9], 16)
        if self.protocolId == 1:
            self.protocolDesc = 'ICMP'
            if self.flag != 2:
                self.protocol = ICMP(byteList[self.headerLen * 4:self.totalLen])
            else:
                self.protocol = None
        elif self.protocolId == 2:
            self.protocolDesc = 'IGMP'
            if self.flag != 2:
                self.protocol = IGMP(byteList[self.headerLen * 4:self.totalLen])
            else:
                self.protocol = None
        elif self.protocolId == 6:
            self.protocolDesc = 'TCP'
            if self.flag != 2:
                self.protocol = TCP(byteList[self.headerLen * 4:self.totalLen])
            else:
                self.protocol = None
        elif self.protocolId == 17:
            self.protocolDesc = 'UDP'
            if self.flag != 2:
                self.protocol = UDP(byteList[self.headerLen * 4:self.totalLen])
            else:
                self.protocol = None
        else:
            self.protocolDesc = 'Unknown'
            self.protocol = None

        self.headerChecksum = byteList[10] + byteList[11]

        self.srcIP = ''
        for i in range(12, 16):
            self.srcIP += str(int(byteList[i], 16)) + '.'
        self.srcIP = self.srcIP[:-1]

        self.destIP = ''
        for i in range(16, 20):
            self.destIP += str(int(self.byteList[i], 16)) + '.'
        self.destIP = self.destIP[:-1]

        if self.flag == 2:
            self.data = ''
            self.dataLen = 0
            for i in range(self.headerLen * 4, len(byteList)):
                self.data += byteList[i]
                self.dataLen += 1
        else:
            self.data = None
            self.dataLen = 0

    def __str__(self):
        string = '\n\tIP version: ' + str(self.v)
        string += '\n\tIP Header Length: ' + str(self.headerLen * 4) + ' bytes ' + '(' + str(self.headerLen) + ')'
        string += '\n\tDifferentiated Service Field: ' + '(0x' + self.dsf + ')'
        string += '\n\tTotal length: ' + str(self.totalLen)
        string += '\n\tIdentification: ' + '(0x' + self.idHex + ')' + ' (' + str(self.id) + ')'
        string += '\n\tFlags: ' + '(0x' + self.flagHex + ')'
        string += '\n\tFragment Offset: ' + str(self.offset)
        string += '\n\tTime to Live: ' + str(self.ttl)
        string += '\n\tProtocol: ' + self.protocolDesc + ' (' + str(self.protocolId) + ')'
        string += '\n\tHeader Checksum: ' + '(0x' + self.headerChecksum + ')'
        string += '\n\tSource Address: ' + self.srcIP
        string += '\n\tDestination Address: ' + self.destIP
        if self.protocol is not None:
            string += str(self.protocol)
        if self.data is not None:
            string += '\n\tData (' + str(self.dataLen) + ' bytes)'
            string += '\n\tData: ' + self.data
            pass
        return string


class Ethernet2(object):
    __slots__ = 'byteList', 'ether_type', 'arp', 'ip'

    def __init__(self, byteList):
        self.byteList = byteList
        self.ether_type = byteList[0] + byteList[1]
        if self.ether_type == '0806':
            self.arp = ARP(byteList[2:])
        elif self.ether_type == '0800':
            self.ip = IP(byteList[2:])
        else:
            pass

    def __str__(self):
        string = '\n\tType: '
        if self.ether_type == '0806':
            string += 'ARP' + '(0x' + self.ether_type + ')'
            string += str(self.arp)
        elif self.ether_type == '0800':
            string += 'IPv4' + '(0x' + self.ether_type + ')'
            string += str(self.ip)
        else:
            string += 'Unknown' + '(' + self.ether_type + ')'
        return string


class Packet(object):
    __slots__ = 'line1', 'byteList', 'id', 'destination_mac', 'source_mac', \
                'dest_mac_type', 'layer2_type', 'packet802', 'packetEther'

    def __init__(self, line1, line2):
        self.line1 = line1
        self.byteList = [l.strip() for l in line2.split('|') if l.strip()]
        self.id = self.byteList[0]
        del self.byteList[0]

        dest_mac_start = self.byteList[0]
        if dest_mac_start == '01':
            self.dest_mac_type = 'Multicast'
        elif dest_mac_start == 'ff':
            self.dest_mac_type = 'Broadcast'
        else:
            self.dest_mac_type = 'Unicast'

        self.destination_mac = ''
        for i in range(6):
            self.destination_mac = self.destination_mac + self.byteList[i] + ':'
        self.destination_mac = self.destination_mac[:-1]

        self.source_mac = ''
        for i in range(6, 12):
            self.source_mac = self.source_mac + self.byteList[i] + ':'
        self.source_mac = self.source_mac[:-1]

        deciderHex = self.byteList[12] + self.byteList[13]
        decider10 = int(deciderHex, 16)

        if decider10 <= 1500:
            self.packet802 = Packet802(self.byteList[12:])
            self.layer2_type = 'IEEE 802.3 Ethernet'
        else:
            self.packetEther = Ethernet2(self.byteList[12:])
            self.layer2_type = 'Ethernet II'

    def __str__(self):
        string = '\tFrame Type: ' + self.layer2_type \
                 + '\n\tDestination MAC Address: ' + self.destination_mac + ' (' + self.dest_mac_type + ')' \
                 + '\n\tSource MAC Address: ' + self.source_mac

        if self.layer2_type == 'Ethernet II':
            string += str(self.packetEther)
        else:
            string += str(self.packet802)
        return string + '\n'

    def get_byte_length(self):
        return len(self.byteList)


class Capture(object):
    __slots__ = 'packets',

    def __init__(self, packets):
        self.packets = packets

    def get_packet_count(self):
        return len(self.packets)


def get_file_data(file_path):
    cap_file_lines = []
    with open(file_path, 'rt') as cap_file:
        for line in cap_file:
            cap_file_lines.append(line)
    return cap_file_lines


def get_capture(dataLines):
    line1_offset = 2
    line2_offset = 3
    packet_offset = 4
    i = 1
    line1 = ''
    packets = []
    for line in dataLines:
        if i % packet_offset == line1_offset:
            line1 = line
        if i % packet_offset == line2_offset:
            packets.append(Packet(line1, line))
            line1 = ''
        i = i + 1
    return Capture(packets)


def main():
    if len(sys.argv) != 2:
        print("Usage: parser.py <filePath>")
    else:
        data_lines = get_file_data(sys.argv[1])
        capture = get_capture(data_lines)
        i = 1
        for packet in capture.packets:
            # if 1 <= i <= 5:
            print('Frame ' + str(i))
            print(packet)
            i = i + 1


if __name__ == '__main__':
    main()
