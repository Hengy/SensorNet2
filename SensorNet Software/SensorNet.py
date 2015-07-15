#!/usr/bin/python2.7    

'''
Control software for the SensorNet home automation and sensor network.

Created on Jul 11, 2015

Author: Matt Hengeveld
E-mail: mrhengeveld@gmail.com
'''

import ConfigParser
import argparse
import datetime
import logging
from multiprocessing import Process
import os
import select
import signal
import socket
import sys
import threading
import time


#---------------------------------------------------------------------
# Global variables
#---------------------------------------------------------------------
VERBOSE = False # Verbose mode

exit_flag = 0

#---------------------------------------------------------------------
# Logging and verbose mode print function
#---------------------------------------------------------------------
def printv(level, stmnt, verbose=False):
    
    t_epoch = time.time()
    t_stamp = datetime.datetime.fromtimestamp(t_epoch).strftime('%Y-%m-%d %H:%M:%S')
    
    log_stmnt = '[' + t_stamp + '] ' + stmnt

    # Log using appropriate level
    if (level.lower() == 'debug'):
        logging.debug(log_stmnt)
    elif (level.lower() == 'info'):
        logging.info(log_stmnt)
    elif (level.lower() == 'warning'):
        logging.warning(log_stmnt)
    elif (level.lower() == 'error'):
        logging.error(log_stmnt)
    elif (level.lower() == 'critical'):
        logging.critical(log_stmnt)
    
    # Print if verbose mode is enabled
    global VERBOSE
    if (VERBOSE or verbose):
        print level.upper() + ' ' + log_stmnt

#---------------------------------------------------------------------
# Process for SensorNet service discovery
#---------------------------------------------------------------------
def srv_dscv_process(VERBOSE, LOG_LEVEL, multicast_ip, multicast_port, ip_local, 
                     port_client_comm, port_node_comm):
    '''
    Service discovery subprocess.
    '''
    
    # Enable logging unless disabled
    if (LOG_LEVEL > -1):
        logging.basicConfig(filename='sensornet_service_discovery.log', format='%(levelname)s %(message)s', level=LOG_LEVEL)
    
#     if (VERBOSE):
    printv('info', 'Starting service discovery process on multicast group {0}, port {1}'.format(multicast_ip, multicast_port), VERBOSE)
        
    # Multicast UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind to socket - all interfaces
    sock.bind(('',multicast_port))
    
    # Make sure socket is reusable
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Add socket to multicast group
    group = socket.inet_aton(multicast_ip)
    iface = socket.inet_aton('239.255.0.1')
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group+iface)
    
    # Wait for UDP packet
    while True:
        printv('info', 'Listening for UDP packets...', VERBOSE)
        msg, address = sock.recvfrom(1024)
        
        msg_str = str(msg)

        printv('debug', 'Recieved message from {0}'.format(address), VERBOSE)
        printv('debug', 'Message: {0}'.format(msg_str), VERBOSE)
        
        # DEBUGGING ONLY -------------------------------------------------------------------------
        if (msg_str.startswith('Kill31415')): # If kill message received, exit
            if (VERBOSE):
                print 'Kill message received. Killing service discovery subprocess.'
            break
        # DEBUGGING ONLY -------------------------------------------------------------------------
        
        
        # Service discovery for control clients
        elif (msg_str.startswith('SensorNet_Discover_Client')):
            # If client wants to connect, send address back
            client_ip = msg_str[msg_str.find(':')+1 : msg_str.find(':',27)]
            client_port = msg_str[msg_str.find(':',27)+1 : len(msg_str)]
            printv('debug', 'Responding to client with IP {0} on port {1}'.format(client_ip, client_port), VERBOSE)
            
            # Send back TCP connection details
            msg_resp = 'SensorNet_Server_Details:{0}:{1}'.format(ip_local,port_client_comm)
            sock.sendto(msg_resp, (client_ip,int(client_port)))
                  
            
        # Service discovery for nodes
        elif (msg_str.startswith('SensorNet_Discover_Node')):
            # If node wants to connect, send address back
            node_ip = msg_str[msg_str.find(':')+1 : msg_str.find(':',25)]
            node_port = msg_str[msg_str.find(':',25)+1 : len(msg_str)]
            printv('debug', 'Responding to node with IP {0} on port {1}'.format(node_ip, node_port), VERBOSE)
            
            # Send back TCP connection details
            msg_resp = 'SensorNet_Server_Details:{0}:{1}'.format(ip_local,port_node_comm)
            sock.sendto(msg_resp, (node_ip,int(node_port)))
     
     
    printv('info', 'Service discovery subprocess exiting...', VERBOSE)
    
    sock.close()
    
    sys.exit()
            
    
#---------------------------------------------------------------------
# Main program
#---------------------------------------------------------------------
def main():
    '''
    Main. 
    Parse config file(s) and command-line args.
    Start subprocesses.
    '''
    
    # Signal handler
    signal.signal(signal.SIGINT, sigHandler)
    
    #---------------------------------------------------------------------
    # Parse configuration parameters
    #---------------------------------------------------------------------
    PORT_DISCOVERY = 0  # Multicast port
    MULTICAST_GRP = ''  # Multicast group ip
    
    PORT_CLIENT_COMM = 0     # Control client communication port
    
    PORT_NODE_COMM = 0  # Node communication port

    IP_LOCAL = '192.168.0.102'       # Local IP
    
    LOG_LEVEL = logging.INFO        # Log level INFO by default
    
    # Setup config file parser
    config = ConfigParser.RawConfigParser()    
    config.read('sensornet.cfg')
    
    # Read default parameters from config file
    LOG_LEVEL = config.get('default_config', 'log_level')
    PORT_DISCOVERY = config.getint('default_config', 'port_discovery')
    MULTICAST_GRP = config.get('default_config', 'multicast_addr')
    PORT_CLIENT_COMM = config.getint('default_config', 'port_client_comm')
    PORT_NODE_COMM = config.getint('default_config', 'port_node_comm')
    
    # Setup command line argument parser
    parser = argparse.ArgumentParser(description='Control software for the'
                                                 ' SensorNet home automation'
                                                 ' and sensor network.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose mode.')
    parser.add_argument('-l', '--log_level', default=LOG_LEVEL,
                        help='Set logging level. Defailt is INFO. Options are:'
                             ' DEBUG, INFO, WARNING, ERROR, CRITICAL')
    parser.add_argument('-dl', '--disable_logging', action='store_true',
                        help='Disables logging.')
    parser.add_argument('-pd', '--port_discovery', default=PORT_DISCOVERY,
                        type=int,
                        help='UDP port for service discovery by control '
                             'client.')   
    parser.add_argument('-m', '--multicast_addr', default=MULTICAST_GRP,
                        help='UDP multicast address.')
    parser.add_argument('-pc', '--port_client_comm', default=PORT_CLIENT_COMM,
                        type=int,
                        help='TCP port for control client communication.')
    parser.add_argument('-pn', '--port_node_comm', default=PORT_NODE_COMM,
                        type=int,
                        help='TCP port for node communication') 
    
    # Parse args
    args = parser.parse_args('-v -l DEBUG'.split())
    
    if (args.verbose):    
        global VERBOSE
        VERBOSE = True
    if (args.port_discovery):
        PORT_DISCOVERY = args.port_discovery
    if (args.multicast_addr):
        MULTICAST_GRP = args.multicast_addr
    
    # Determine logging level
    if (args.log_level):
        if (args.log_level == 'DEBUG'):
            LOG_LEVEL = logging.DEBUG
        elif (args.log_level == 'INFO'):
            LOG_LEVEL = logging.INFO
        elif (args.log_level == 'WARNING'):
            LOG_LEVEL = logging.WARNING
        elif (args.log_level == 'ERROR'):
            LOG_LEVEL = logging.ERROR
        elif (args.log_level == 'CRITICAL'):
            LOG_LEVEL = logging.CRITICAL
    
    # Enable logging unless disabled
    if (args.disable_logging):
        LOG_LEVEL = -1
    else:
        logging.basicConfig(filename='sensornet.log', format='%(levelname)s %(message)s', level=LOG_LEVEL)
    
    
    #---------------------------------------------------------------------
    # Main program
    #---------------------------------------------------------------------
    printv('info','Starting SensorNet...')
    
    srv_dscv_p = Process(target=srv_dscv_process, args=(VERBOSE,LOG_LEVEL,
                                                        MULTICAST_GRP,
                                                        PORT_DISCOVERY,IP_LOCAL,
                                                        PORT_CLIENT_COMM,
                                                        PORT_NODE_COMM,
                                                        ))
    printv('info','Process started')
    srv_dscv_p.start()
    
    
    #---------------------------------------------------------------------
    # Client and node socket communication setup
    #---------------------------------------------------------------------
    # TCP server socket for client communication
    sock_client_comm = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_client_comm.bind((IP_LOCAL,PORT_CLIENT_COMM))
    sock_client_comm.listen(5)
    sock_client_comm.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # TCP server socket for node communication
    sock_node_comm = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_node_comm.bind((IP_LOCAL,PORT_NODE_COMM))
    sock_node_comm.listen(5)
    sock_node_comm.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
      
    #---------------------------------------------------------------------
    # Main loop
    #---------------------------------------------------------------------
    global exit_flag
    
    while not exit_flag:
        # Select socket with data
        data_sockets, _, _ = select.select([sock_client_comm,sock_node_comm],
                                           [],[])
        
        if data_sockets:
            if (sock_client_comm in data_sockets):
                client_conn, client_addr = sock_client_comm.accept()
                client_data = client_conn.recv(1024)
                printv('debug','Client data: {0}'.format(client_data))
                
                # Create new thread to handle client
                
            elif (sock_node_comm in data_sockets):
                node_conn, node_addr = sock_node_comm.accept()
                node_data = node_conn.recv(1024)
                printv('debug','Node data: {0}'.format(node_data))
                
                # Create new thread to handle node
            
    
    
    srv_dscv_p.join()
    
    sock_client_comm.close()
    sock_node_comm.close()
    
    printv('info','SensorNet shutting down...')
    
 
#---------------------------------------------------------------------
# Signal handler
#---------------------------------------------------------------------   
def sigHandler(signal, frame):
    
    global exitFlag
    
    print "Exiting gracefully..."
    
    exitFlag = 1
    
    sys.exit(0)
    

if __name__ == '__main__':
    main()
    sys.exit()