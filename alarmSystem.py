__author__  = "David Olano"

''' Alarm system functions '''

import FSM  
import datetime
import resultsDisplay
import ConfigParser 
import collections

alarmCodeList = {
    1: "IPBroadcastMessage",
    2: "AnormalIPRange",
    3: "DFCFlagAttack",
    4: "LinkLayerFuzzing-InvalidStart",
    5: "ApplicationLayerFuzzing-InvalidFunctionCode",
    6: "WriteFunctionDetected",
    7: "ResetFunctionAttack",
    8: "InitializeDataFunctionAttack",
    9: "AppTerminationFunctionAttack",
    10: "DeleteFunctionAttack",
    11: "CaptureConfigurationAttack",
    12: "ClearObjectsAttack",
    13: "ClearObjectsAttackCold",
    14: "ColdResetFunctionAttack",
    }

config=ConfigParser.ConfigParser()
config.read("config.ini")  

def initialize():
    global current_state
    global previousTotalThreatValue

    initial_state = 1

    print '\tDetected\tSeverity\tTime'
    print '\t--------\t--------\t----'
    
    current_state = "Low"
    previousTotalThreatValue = 0


def singlePacketAttack(code,severity):
    global current_state

    print ('ALERT:\t', alarmCodeList[code] , '\t', 
           severity , '\t', datetime.datetime.now())

    alarm_action = "rise"
    current_state = FSM.alarm_FSM(current_state,alarm_action)


def threatPonderate(alarmValue,queue,attackType):
    if (attackType == 1 or attackType == 2 or attackType == 7 
        or attackType == 8 or attackType == 10 or attackType == 12):
        severity = "High"

    elif (attackType == 3 or attackType == 4 or attackType == 5 
          or attackType == 9 or attackType == 11 
          or attackType == 13 or attackType == 14):
        severity = "Critical"

    elif attackType == 6: 
        severity = "Normal"

    if alarmValue == 1:
        print 'ALERT:\t', alarmCodeList[attackType] , '\t', severity , '\t', datetime.datetime.now()

    queue.extend([alarmValue])
    #print queue # Debug

    ocurrencies = queue.count(1)

    alarmCodeList[attackType]
    attackFactor = float(config.get('AttackFactors',alarmCodeList[attackType]))
    windowLength = int(config.get('Constants','windowLength'))

    if len(queue) == windowLength: #Waits until the queue is full

        lastRepetitions=[]
        i=0
        
        while i<3:
            lastRepetitions.append(queue[i])
            i+=1

        nearRepetitions = lastRepetitions.count(1)
    
        if nearRepetitions == 0:
            nearRepetitions = 1 #Mathematical adjustment

        frequencyFactor = resultsDisplay.divide_float(ocurrencies,windowLength)
        threatValue = frequencyFactor * attackFactor * nearRepetitions**2

        return threatValue

    else:

        return 0


def checkStatus(totalThreatValue):
    global current_state
    global previousTotalThreatValue

    if current_state == "Low":
        thresold = 20
    elif current_state == "Medium":
        thresold = 40
    elif current_state == "High":
        thresold = 60
    elif current_state == "Critical":
        thresold = 80

    if totalThreatValue >= previousTotalThreatValue:
        if current_state != "Critical":      
            if totalThreatValue > thresold:
                alarm_action = "rise"
                current_state = FSM.alarm_FSM(current_state,alarm_action)

    else:
        if totalThreatValue < (thresold-20):
            if thresold == 20:
                current_state = "Low"
            else:
                alarm_action = "decrease"
                current_state = FSM.alarm_FSM(current_state,alarm_action)
    
    previousTotalThreatValue = totalThreatValue

     

        

