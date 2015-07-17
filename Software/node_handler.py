'''
Created on Jul 15, 2015

@author: Matt
'''

import threading

class nodeHandler (threading.Thread):
    
    def __init__(self, node_conn):
        threading.Thread.__init__(self, group, target, name, args, kwargs, verbose)
        
    def run(self):
        print 'Node handler'