import pyshark

all_results = "results/results.csv"

def analyze_packet(cap, device_IP, results_file):
  open_connections = 0
  total_length = 0
  packet_count = 0
  errors = 0

  starts = []
  connection_attempts = []
  closed_attempts = []

  clock_address = []

  for packet in cap:
    try:
      end_time = packet.frame_info.time_epoch
      #We want to log what the device does after it fails to make a connection
      if open_connections >= 1:
        #For finding average packet length
        total_length += int(packet.length)
        packet_count += 1

      if packet.transport_layer == "TCP":
          source_address = packet.ip.src
          destination_address = packet.ip.dst
          #SYN/ACK stuff
          if packet.tcp.flags == "0x00000002":
              #print(packet.frame_info.number, source_address, destination_address)
              flag = 0
              for item in starts:
                  if (item[2] == destination_address): #We don't need to record SYN that already exist
                      flag = 1
                      break
              else:
                starts.append([packet.frame_info.number, source_address, destination_address])
                connection_attempts.append([destination_address, 1, packet.frame_info.time_epoch, "None"]) #Keep track of the number of connections
              if flag == 1: #Makes an attempt to re-contant the IP address
                for item in connection_attempts:
                  if item[0] == destination_address:
                    item[1] += 1
                    #Once 3 unsucessful attempts are made to connect to an IP consider it "failed"
                    if item[1] == 2:
                      open_connections += 1
                    break
                
          elif packet.tcp.flags == "0x00000012":
              for item in starts:
                  if item[2] == source_address:
                      #No longer need to record this as being unconnected
                      if item[1] > 3:
                        open_connections -= 1
                      starts.remove(item) #Remove all ACK with a SYN/ACK
                      #Log item, number of attempted connections, time started, time ended
                      for item2 in connection_attempts:
                        if item2[0] == source_address:
                          if item2[1] > 1:
                            item2[3] = packet.frame_info.time_epoch #Time when connection successful
                            closed_attempts.append(item2)
                          connection_attempts.remove(item2)
                          break
                      break
                    
      #NTP - clock synchronization
      elif "NTP" in str(packet.layers) and packet.ip.src == device_IP :
        source_address = packet.ip.src
        destination_address = packet.ip.dst
        if not(destination_address in clock_address):
          clock_address.append(destination_address)
  ##    else:
  ##      print(str(packet.layers))
      
    except:
      errors += 1
      print(errors)
      #print(packet)

  if packet_count > 1:
    average_length = total_length / packet_count
  
  for item in connection_attempts:
    closed_attempts.append(item)

  to_write = ""
  time = 0

  #Unclosed handshakes
  if len(starts) > 0:
    to_write += ("Unclosed handsakes are:\n")
    for item in starts:
        to_write += str(item[1]) + " -> " + str(item[2]) + "\n"

  #Failed connections
  if len(closed_attempts) > 0:
    to_write += "\n\nDestination IPs with multiple attempts to access are:"
    total_attemtps = 0
    for item in closed_attempts:
      if (item[2] != "None" and item[3] != "None"):
        time = float(item[3]) - float(item[2])
      else:
        time = float(end_time) - float(item[2])
      to_write += "\nDestination IP: " + str(item[0]) + "\nAttempted Connections: " + str(item[1]) + "\nConnections starting at: " + str(item[2]) + "\nConnections ending at: " + str(item[3]) + "\nTime Between Connection start and end: " + str(time) + "\n\n"
      total_attemtps += item[1]
    #Total
    to_write += "Total attempted connections: " + str(total_attemtps) + "\n\n"
    #Average Packet Length
    to_write += "Average Packet Length while missing a connection: " + str(average_length) + "\n\n"
  else:
    total_attempts = 0
    average_length = 0

  #Clock sync
  if len(clock_address) > 0:
    to_write += "Destinations for clock sync are: \n"
    for item in clock_address:
      to_write += str(item) + "\n"




  file_name = "results/" + results_file + ".txt"
  output_file = open(file_name, "w")
  output_file.write(to_write)
  output_file.close()

  if len(closed_attempts) > 0:
    start_packet = closed_attempts[0]
    if (start_packet[2] != "None" and start_packet[3] != "None"):
        disconnected_time = float(start_packet[3]) - float(start_packet[2])
    else:
        disconnected_time = float(end_time) - float(start_packet[2])
    output_file = open(all_results, "a")
    to_write = "\n" + results_file + "," + str(total_attemtps) + "," + str(average_length) + "," + str(disconnected_time)
    output_file.write(to_write)
    output_file.close()
  else:
    print("No Failed Connections for ", file_name)

  print("Results saved in: ", file_name)


##cap = pyshark.FileCapture('data/2018-07-31-15-15-09-192.168.100.113.pcap')
##device_IP = "192.168.100.113"
##results_file = "192.168.100.113-1"
##analyze_packet(cap,device_IP,results_file)

##cap = pyshark.FileCapture('data/2018-10-03-15-22-32-192.168.100.113.pcap')
##device_IP = "192.168.100.113"
##results_file = "192.168.100.113-2"
##analyze_packet(cap,device_IP,results_file)

for i in range(1,10):
  file = ("data/2018-07-20-17-31-20-192.168.100.108_0000{0}.pcapng".format(i))
  cap = pyshark.FileCapture(file)
  device_IP = "192.168.100.108"
  results_file = ("192.168.100.108-1_{0}".format(i))
  analyze_packet(cap,device_IP,results_file)

for i in range(10,100):
  file = ("data/2018-07-20-17-31-20-192.168.100.108_000{0}.pcapng".format(i))
  cap = pyshark.FileCapture(file)
  device_IP = "192.168.100.108"
  results_file = ("192.168.100.108-1_{0}".format(i))
  analyze_packet(cap,device_IP,results_file)


##cap = pyshark.FileCapture('data/2019-01-10-14-34-38-192.168.1.197.pcap')
##device_IP = "192.168.1.197"
##results_file = "192.168.1.197-1"
##analyze_packet(cap,device_IP,results_file)
##
##try:
##  cap = pyshark.FileCapture('data/2018-07-20-17-31-20-192.168.100.108.pcap')
##  device_IP = "192.168.100.108"
##  results_file = "192.168.100.108-1"
##  analyze_packet(cap,device_IP,results_file)
##except:
##  print("Failed" + str(results_file))
##
##
##try:
##  cap = ("data/2018-05-21_capture.pcap")
##  device_IP = "192.168.2.5"
##  results_file = "192.168.2.5-1"
##  analyze_packet(cap,device_IP,results_file)
##except:
##  print("Failed" + str(results_file))
##
##try:
##  cap = ("data/2018-07-25-10-53-16-192.168.100.111.pcap")
##  device_IP = "192.168.100.111"
##  results_file = "192.168.100.111-1"
##  analyze_packet(cap,device_IP,results_file)
##except:
##  print("Failed" + str(results_file))
