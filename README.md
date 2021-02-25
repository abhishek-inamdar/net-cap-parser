Networking Capture Parser

Python program file named parser.py (Usage: parser.py<space><file path of text file>). This program takes 1 argument as the file path for the text-based network data capture file. Program expects text file to be in a particular format as shown below.

+---------+---------------+----------+
03:09:24,762,913   ETHER
|0   |60|67|20|2c|5c|ca|9c|2a|70|01|ec|f4|08|00|45|08|00|34|3f|27|40|00|39|06|1d|c3|26|45|ee|10|c0|a8|0f|d4|00|50|c5|35|80|ad|63|3d|be|e2|f1|93|80|10|00|f5|d9|22|00|00|01|01|05|0a|be|e2|f1|92|be|e2|f1|93|


Each 4 lines in the text-based file will contain information for 1 packet. Multiple packets can be present in a file. When executed successfully, program will print output to Standard output in following format:
Dataset:	number of packets						
		      Protocol distribution
		      Max, min and average size packet in terms of bytes

Packet:		timestamp
		      Delta time from last packet
		      Process the first 64 bytes of the packet – all fields and their meanings

Program will be able to handle following standard protocols: 802.2, 802.3, ARP, ICMP, IGMP, IPv4, TCP, UDP, STP.

Program output Explanation:
Dataset:
  Protocol distribution will contain set of all identified protocols in a given capture file. Note that output may not be in a particular order.
  Max, min size of packet will exclude the preamble and CRC data from the calculation
  Average size is rounded to two decimal points
Packet:
  Timestamp and delta time is in the format HH:MM:SS.f (HH – zero padded 24-Hour value, MM – zero padded Minute value, SS – zero padded seconds value, and f – microseconds value)
  For certain fields appropriate hexadecimal values are shown in the format ‘(0xHex)’
  Certain upper layer protocols and other protocols which are not mentioned above will not be parsed by the program, for e.g., from a provided capture file of DHCP protocol, program will parse each packet till UDP protocol. DHCP protocol will be considered as UDP protocol Data.
