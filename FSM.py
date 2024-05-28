__author__  = "David Olano"

''' Finite State Machine used in the alarm system '''

import datetime

def alarm_FSM(previous_state, alarm):
    if previous_state == "Low":
        current_state = low_transition(alarm)
    elif previous_state == "Medium":
        current_state = medium_transition(alarm)
    elif previous_state == "High":
        current_state = high_transition(alarm)
    elif previous_state == "Critical":
        current_state = critical_transition(alarm)
    else:
        print('Critical error. Not valid alarm status!')
        sys.exit()

    print('EVENT:\tCurrent alarm status is:', \
           current_state, '\t', datetime.datetime.now())

    return current_state


def low_transition(alarm): 
    if alarm == 'rise':
        newState = "Medium"

    elif alarm == 'decrease':
        newState = "Low"

    else:
        newState = "error_state"  

    return newState


def medium_transition(alarm):
    if alarm == 'rise':
        newState = "High"
    
    elif alarm == 'decrease':
        newState = "Low"

    else:
        newState = "error_state"

    return newState


def high_transition(alarm):
    if alarm == 'rise':
        newState = "Critical"
    
    elif alarm == 'decrease':
        newState = "Medium"

    else:
        newState = "error_state"

    return newState


def critical_transition(alarm):
    if alarm == 'rise':
        newState = "Critical"
    
    elif alarm == 'decrease':
        newState = "High"

    else:
        newState = "error_state"
    return newState
