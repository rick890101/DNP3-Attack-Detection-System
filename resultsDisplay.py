__author__  = "David Olano"

import DNP3_Lib   

''' Final results display function set '''

def appFunctionCode(appFunctionCodeList):
    '''Function that shows the name and number of Application Layer
       function codes sniffed'''
    
    print '\nDNP3 Application Layer Function Codes:'
    for i in range (131):
        if appFunctionCodeList[i] != 0:
            print DNP3_Lib.applicationFunctionCode[i], \
                   ':', appFunctionCodeList[i]


def divide_float(op1,op2):
    '''Function used to get a float result while dividing integers'''
    op1=float(op1)   
    result=op1/op2
    return result
