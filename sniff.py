#! /usr/bin/env python

__author__  = "David Olano"
__version__ = "1.0"
__email__   = "david.olano@estudiante.uam.es"
__status__  = "production"

'''DNP3 traffic monitoring system using Scapy and DNP3Lib.py'''

import signal
import sys
import time
import math
import threading
import ConfigParser 
import collections

from scapy.all import * # Scapy dependences
import DNP3_Lib         # DNP3 extension for Scapy
import IPfunctions      # Functions used for IP calculations
import resultsDisplay   # Final results display 
import alarmSystem      # Alarm and monitoring

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

''' Sniffer and packet processor '''

def sniffer():
    sniff(count=0, iface="eth0", prn = pkt_action, store=0) 


def pkt_action(pkt):
    #Process every packet, updates values and rises and alert if necessary 

    global pkt_counter
    global IP_counter
    global TCP_counter
    global UDP_counter
    global DNP3_counter
    global function_code_counter
    global IPRangeWindow
    global IPRangeThreatValue
    global DFCWindow
    global DFCFlagThreatValue
    global writeWindow
    global writeThreatValue
    global clearObjectsWindow
    global clearObjectsThreatValue
    global clearObjectsWindowCold
    global clearObjectsThreatValueCold
    global resetWindow
    global resetThreatValue
    global initializeDataWindow
    global initializeDataThreatValue
    global appTerminationDataWindow
    global appTerminationThreatValue 
    global deleteWindow 
    global deleteThreatValue 
    global captureConfigWindow 
    global captureConfigThreatValue
    global functionCodeThreat

    pkt_counter+=1

    ''' IP checks '''

    if pkt.haslayer(IP) == 1:
        IP_counter+=1

        ipsrc = pkt[IP].src
        ipdst = pkt[IP].dst
        ip_range=IPfunctions.calculate_ip_range(ipsrc,ipdst) 

        if ipdst == "255.255.255.255": 
            alarmSystem.singlePacketAttack(1,'High')
        
        if (ip_range > int(config.get('Thresold','ip_max_range'))): 
            IPRangeThreatValue = alarmSystem.threatPonderate(1,IPRangeWindow,2)

        else:
            IPRangeThreatValue = alarmSystem.threatPonderate(0,IPRangeWindow,2)
            
    ''' TCP application checks '''

    if pkt.haslayer(TCP) == 1:
        TCP_counter+=1
            
    ''' UDP application checks '''

    if pkt.haslayer(UDP) == 1:
        UDP_counter+=1

    ''' DNP3 application checks '''

    if pkt.haslayer(DNP3) == 1:
        #pkt.show() #Debug
        DNP3_counter+=1

        ''' Start check '''
        start_value = pkt.START
            
        if start_value != 1380: #1380 = 0x564 
            alarmSystem.singlePacketAttack(4,'Critical')

        ''' Length check (Incomplete) '''
        check_value = pkt.LENGTH 

        ''' DFC control check '''
        DFC_value = pkt.CONTROL.FCV         
        
        if DFC_value == 1:
            DFCFlagThreatValue = alarmSystem.threatPonderate(1,DFCWindow,3)
        
        else:
            DFCFlagThreatValue = alarmSystem.threatPonderate(0,DFCWindow,3)
            
        ''' Pseudo Transport Layer Check '''

        if pkt.haslayer(DNP3_Lib.DNP3Transport):

            if (pkt.FIR != None and pkt.FIR == 1):
                # FIR detected. This version doesn't manage this parameter.
                pass
            
            if (pkt.FIN != None and pkt.FIN == 1):
                # FIN detected. This version doesn't manage this parameter.
                pass

        ''' Function codes check '''

        if (pkt.haslayer(DNP3_Lib.DNP3ApplicationResponse) 
            or pkt.haslayer(DNP3_Lib.DNP3ApplicationRequest)):

            if pkt.FUNC_CODE is not None:
                if (pkt.FUNC_CODE < 0 or pkt.FUNC_CODE > 131):
                    alarmSystem.singlePacketAttack(5,'Critical')
        
                else: 
                    aux = appfunction_code_counter.pop(pkt.FUNC_CODE)
                    aux+=1
                    appfunction_code_counter.insert(pkt.FUNC_CODE,aux)

                    if pkt.FUNC_CODE == 2: #Write function 
                        writeThreatValue = alarmSystem.threatPonderate(1,
                                                            writeWindow,6)
            
                    else:
                        writeThreatValue = alarmSystem.threatPonderate(0, 
                                                            writeWindow,6)

                    if pkt.FUNC_CODE == 13: #Reset function (Cold restart)
                        coldResetThreatValue = alarmSystem.threatPonderate(1,
                                                           coldResetWindow,14)
            
                    else:
                        coldResetThreatValue = alarmSystem.threatPonderate(0,
                                                           coldResetWindow,14)

                    if pkt.FUNC_CODE == 14: #Reset function (Warm restart)
                        resetThreatValue = alarmSystem.threatPonderate(1,
                                                            resetWindow,7)
            
                    else:
                        resetThreatValue = alarmSystem.threatPonderate(0,
                                                            resetWindow,7)

                    if pkt.FUNC_CODE == 15: #Initialize data function
                        initializeDataThreatValue = (
                            alarmSystem.threatPonderate(1,
                                    initializeDataWindow,8))
            
                    else:
                        initializeDataThreatValue = (
                            alarmSystem.threatPonderate(0,
                                    initializeDataWindow,8))

                    if pkt.FUNC_CODE == 18: #App termination function
                        appTerminationThreatValue = alarmSystem.threatPonderate(
                                                   1,appTerminationDataWindow,9)
            
                    else:
                        appTerminationThreatValue = alarmSystem.threatPonderate(
                                                   0,appTerminationDataWindow,9)

                    if pkt.FUNC_CODE == 27: #Delete file function
                        deleteThreatValue = alarmSystem.threatPonderate(1,
                                                           deleteWindow,10)
            
                    else:
                        deleteThreatValue = alarmSystem.threatPonderate(0,
                                                           deleteWindow,10)   

                    if pkt.FUNC_CODE == 129: #If DNP3 packet is an answer
                        if pkt.IIN.CONFIG_CORRUPT == 1: #Fifth bit of IIN set
                            captureConfigThreatValue = (
                                alarmSystem.threatPonderate(1,
                                        captureConfigWindow,11))
            
                        else:
                            captureConfigThreatValue = (
                                alarmSystem.threatPonderate(0,
                                        captureConfigWindow,11))  

                    if pkt.FUNC_CODE == 9: #Clear objects function (warm)
                        clearObjectsThreatValue = (
                            alarmSystem.threatPonderate(1,
                                     clearObjectsWindow,12))
            
                    else:
                        clearObjectsThreatValue = (
                            alarmSystem.threatPonderate(0,
                                     clearObjectsWindow,12))

                    if pkt.FUNC_CODE == 10: #Clear objects function (cold)
                        clearObjectsdThreatValueCold = (
                            alarmSystem.threatPonderate(1,
                                 clearObjectsWindowCold,13))
            
                    else:
                        clearObjectsThreatValueCold = (
                            alarmSystem.threatPonderate(0,
                                 clearObjectsWindowCold,13))                     

                    functionCodeThreat = (clearObjectsThreatValueCold + 
                                         clearObjectsThreatValue + 
                                         captureConfigThreatValue + 
                                         deleteThreatValue + 
                                         appTerminationThreatValue + 
                                         resetThreatValue + 
                                         coldResetThreatValue + 
                                         initializeDataThreatValue + 
                                         writeThreatValue)

    totalThreatStatus = (IPRangeThreatValue + 
                         DFCFlagThreatValue + 
                         functionCodeThreat)
 
    if totalThreatStatus > 100: #Upper limit
        totalThreatStatus = 100
    #print totalThreatStatus #Debug

    alarmSystem.checkStatus(totalThreatStatus)


''' Main program''' 

if __name__ == "__main__":

    ''' Initializations '''

    config=ConfigParser.ConfigParser() #Reference values in config.ini
    config.read("config.ini")  

    pkt_counter = 0
    TCP_counter = 0
    IP_counter = 0
    DNP3_counter = 0
    UDP_counter = 0
    windowLength = 0
    appfunction_code_counter = []
    for i in range (131):
        appfunction_code_counter.append(0)

    windowLength = int(config.get('Constants','windowLength'))   
    dnp3_port = config.get('Constants','dnp3_port') #Port assigned to DNP3

    IPRangeWindow = collections.deque(maxlen = windowLength)
    IPRangeThreatValue = 0
    DFCWindow = collections.deque(maxlen = windowLength)
    DFCFlagThreatValue = 0
    writeWindow = collections.deque(maxlen = windowLength)
    writeThreatValue = 0
    clearObjectsWindow = collections.deque(maxlen = windowLength)
    clearObjectsThreatValue = 0
    clearObjectsWindowCold = collections.deque(maxlen = windowLength)
    clearObjectsThreatValueCold = 0
    resetWindow = collections.deque(maxlen = windowLength)
    resetThreatValue = 0
    coldResetWindow = collections.deque(maxlen = windowLength)
    coldResetThreatValue = 0
    initializeDataWindow = collections.deque(maxlen = windowLength)
    initializeDataThreatValue = 0
    appTerminationDataWindow = collections.deque(maxlen = windowLength)
    appTerminationThreatValue = 0
    deleteWindow = collections.deque(maxlen = windowLength)
    deleteThreatValue = 0
    captureConfigWindow = collections.deque(maxlen = windowLength)
    captureConfigThreatValue = 0
    functionCodeThreat = 0

    DNP3 = DNP3_Lib.DNP3 #Reference to DNP3 class defined in DNP3_Lib 

    init_time = time.time()

    ''' Bindings for DNP3 if the TCP traffic comes or goes to dnp3_port '''

    bind_layers(TCP, DNP3, dport = dnp3_port)
    bind_layers(TCP, DNP3, sport = dnp3_port)

    ''' Sniffing and call to pkt_action function '''

    print 'Sniffing process started. To stop it, press Ctrl+C'

    alarmSystem.initialize()

    sniffer() #Calls to sniffer 

    ''' Final results display after sniffing'''

    if KeyboardInterrupt:

        stop_time = time.time()

        print '\nSniffer stopped by keystroke.'
        print '\n#### Final results ####'
        
        if pkt_counter == 0:
            print ('No packets sniffed in', 
                   round((stop_time-init_time),3), 'seconds.')

        else:
            IP_percent = ((resultsDisplay.divide_float(IP_counter,
                                                       pkt_counter))*100)
            TCP_percent = ((resultsDisplay.divide_float(TCP_counter,
                                                        pkt_counter))*100)
            UDP_percent = ((resultsDisplay.divide_float(UDP_counter,
                                                        pkt_counter))*100)

            print 'Time elapsed:', round((stop_time-init_time),3), 'seconds.'
            print 'Packets sniffed:', pkt_counter
            print '- IP packets:', IP_counter, 'Percent:', IP_percent,'%'
            print '---- TCP packets:', TCP_counter, 'Percent:', TCP_percent,'%'
            print '---- UDP packets:', UDP_counter, 'Percent:', UDP_percent,'%'
            print 'DNP3 messages:', DNP3_counter
            resultsDisplay.appFunctionCode(appfunction_code_counter)
            

