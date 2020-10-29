#**********************************************************************************************
# Traffic Emulator for Network Services
# Copyright 2020 VMware, Inc
# The BSD-2 license (the "License") set forth below applies to all parts of
# the Traffic Emulator for Network Services project. You may not use this file
# except in compliance with the License.
#
# BSD-2 License
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE
#**********************************************************************************************

from threading import Timer
from time import sleep
import sys, time
IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    from Queue import Queue
else:
    from queue import Queue

from threading import Thread
import logging, logging.handlers
from collections import Mapping
from sysv_ipc import MessageQueue, ftok, BusyError, IPC_CREAT


class Logger:
    def __init__(self, name, logFilePath, level=None, bufferSize=1024*1000*5):
        try:
            if level == None:
                level = 10 #DEBUG
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

            self.lgr = logging.getLogger(name)
            self.lgr.setLevel(level)

            fileHandler = logging.FileHandler(logFilePath)
            fileHandler.setLevel(level)
            fileHandler.setFormatter(formatter)

            memoryHandler = logging.handlers.MemoryHandler(bufferSize,level,fileHandler) #Flushes out on htting buffer size to the fileHandler
            memoryHandler.setFormatter(formatter)
            memoryHandler.setLevel(level)

            self.lgr.addHandler(memoryHandler)

        except Exception as e:
            print("ERROR IN logging_init %s" %str(e) )

    def getLogger(self):
        return self.lgr

class SysVQ:
    # Returns an handle to an existing Queue
    # Throws Error if the Queue doesn't exist
    def __init__(self, id):
        try:
            self.genKey = ftok("/tmp", id, True)
            self.q = MessageQueue(self.genKey, IPC_CREAT)
            self.queue_exists = True
        except Exception as e:
            self.queue_exists = False

    # Non-blocking send
    # Default type of the message is 1
    # '\0' is added to every message to send as the receiver call is in C
    def send(self, message):
        try:
            if self.queue_exists:
                self.q.send(message+"\0", block=False, type=1)
                return 1
            else:
                return 0
        except Exception as e:
            return 0

    # The call is made blocking on purpose
    # Reads the 1st message on the queue, irrespective of the type
    def recv(self, max_retries=60, time_between_retries=1):
        try:
            if self.queue_exists:
                for i in range(max_retries):
                    try:
                        msg = self.q.receive(block = False, type = 2)
                        return True, msg
                    except BusyError:
                        pass
                    time.sleep(time_between_retries)
                return True, None
            else:
                return False, None
        except Exception as e:
            print("ERROR: %s" %str(e))
            return False, None

class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


def convert(input):
    '''
    This utility will convert input data from 'str' to 'utf-8'
    map doesnt work directly for nested datastructures so we have
    this utility to the rescue
    '''
    if isinstance(input, dict):
        return {convert(key): convert(value) for key, value in input.items()}
    elif isinstance(input, list):
        return [convert(element) for element in input]
    elif isinstance(input, bytes):
        return input.decode('utf-8')
    else:
        return input

def dict_merge(dct, merge_dct):
    """
        https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
        :param dct: dict onto which the merge is executed
        :param merge_dct: dct merged into dct
        :return: None
    """
    for k, v in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict) and isinstance(merge_dct[k], Mapping)):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]

# From : https://www.metachris.com/2016/04/python-threadpool/
class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                # An exception happened in this thread
                print(e)
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        self.tasks.put((func, args, kargs))

    def map(self, func, args_list):
        """ Add a list of tasks to the queue """
        for args in args_list:
            self.add_task(func, args)

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        self.tasks.join()

def clear_rabbit_queue(host, username, password, queuename):
    host = host
    creds = pika.PlainCredentials(username, password)
    params = pika.ConnectionParameters(host, credentials=creds)#, heartbeat=300)
    #conn = pika.AsyncoreConnection(params)
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    ch.queue_delete(queue=queuename)
    ch.close()
    conn.close()

# WRITE TO CSV
def write_csv(filename=None, json_variable=None, rewrite_file=False, json_dumps=False):
    import csv, json, os.path, StringIO
    import pandas as pd
    if filename == None:
        print("Filename cannot be None")
        return False
    if not json_variable:
        print("Json Variable cannot be None")
        return False

    count = 1
    if rewrite_file or not os.path.isfile(filename) :
        fd = open(filename, 'w')
        count = 0
    elif os.path.isfile(filename):
        fd = open(filename, 'a')
    else:
        print("File cannot be written")
        return False
    if json_dumps:
        json_var = json.dumps(json_variable)
    else:
        json_var = json_variable
    try:
#        data = pd.DataFrame(json_var)
        csvbuffer = StringIO.StringIO()
        csv_data = pd.io.json.json_normalize(json_var)
        csv_data.to_csv(csvbuffer)
        csvbuffer.seek(0)
        csv_data = csvbuffer.getvalue()
        csvbuffer.close()
    except:
        print("Json Variable is not in the required format")
        return False
    if count == 0:
        fd.write(csv_data)
    else:
        csv_lines = csv_data.split('\n')
        csv_no_header = csv_lines[1:]
        for csv_lin in csv_no_header:
            if csv_lin == '':
                continue
            fd.writelines(csv_lin+'\n')
    fd.close()
    return True

# END OF TE UTILS
# END OF CSV WRITING
