'''
evedec.py
Reads and decrypts Eve Online python files and passes them to uncompyle2 to decompile.
  -Doesn't manipulate Eve process. Can be run with or without Eve running.
  -Searches for decryption key in the blue.dll file.
  -Requires uncompyle2 for actual decompilation.
  -Uses multiple processes to speed up decompilation.

Expects a evedec.ini file to specify Eve install location and output directory, e.g.:
[main]
eve_path = C:\Program Files (x86)\CCP\EVE\
store_path = ..\

'''

def test(s, s2, s3, s4, s5, s6, s7):
    print "test"
    print s3

def unjumble(pool, keys, filename, code, result_q, store_path, lock):
#    with lock:
#    print '# unjumble %s' % filename
    sys.stdout.flush()
    code = UnjumbleString(keys, code)[8:]
    pool.apply_async(process_func, args=(filename, code, result_q, store_path, lock))

#function executed by each decompile process
def process_func(filename, marshalled_code, result_q, store_path, lock):
    with lock:
        print '# process_func %s' % filename
        sys.stdout.flush()

    okay_files = failed_files = 0
    try:
        import sys, os, marshal, errno, Queue
        import uncompyle2

        try:
            code = marshal.loads(marshalled_code)
            
            #prepend our store_path
            filename = os.path.join(store_path, filename)
            filename = os.path.abspath(filename)
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as e:
                #the dir may already exist, in which case ignore error
                if e.errno != errno.EEXIST:
                    raise
            try:
                os.remove(filename+'_failed')
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
            with open(filename, 'w') as out_file:
                uncompyle2.uncompyle('2.7', code, out_file)
        except KeyboardInterrupt:
            raise
        except:
            with lock:
                print '### Can\'t decompile %s' % filename
                sys.stdout.flush()
            os.rename(filename, filename+'_failed')
            failed_files += 1
        else:
            with lock:
                print '+++ Okay decompiling %s' % filename
                sys.stdout.flush()
            okay_files += 1
                
    finally:
        result_q.put((okay_files, failed_files))

def UnjumbleString(keys, s):
    try:
        key = keys[0][0]
        dec_s = key.decrypt(s)

        return zlib.decompress(dec_s)
    except zlib.error:
        print 'Key failed. Attempting key switch.'
        del keys[0]
        if not keys:
            print >> sys.stderr, '!!! All keys failed. Exiting.'
            sys.exit(-1)
        return UnjumbleString(s)

#executed once by the starting process
if __name__ == '__main__':
    #moved imports here so that the other processes don't import them unnecessarily
    import sys
    if sys.version[:3] != '2.7':
        print >>sys.stderr, '!!! Wrong Python version : %s.  Python 2.7 required.'
        sys.exit(-1)
    import os, cPickle, imp, zipfile, zlib, traceback, pyDes
    from Queue import Empty
    from multiprocessing import Process, Pool, Queue, cpu_count, freeze_support, Lock
    from datetime import datetime
    from ConfigParser import ConfigParser

    freeze_support()

    startTime = datetime.now() #time this cpu hog

    #Get path to Eve installation from evedec.ini file
    config = ConfigParser()
    config.read('evedec.ini')
    eve_path = config.get('main', 'eve_path')

    #use version info from eve's common.ini to create directory name
    eveconfig = ConfigParser()
    eveconfig.read(os.path.join(eve_path, 'start.ini'))

    store_path = os.path.join(config.get('main', 'store_path'), 'eve-%s.%s' % (eveconfig.get('main', 'version'), eveconfig.get('main', 'build')))
    store_path = os.path.abspath(store_path)

    #search blue.dll for keyblob header
    #yeah, it's really that easy

    blue_path = os.path.join(eve_path, 'bin/blue.dll')
    blue = open(blue_path, 'rb').read()
    blob_header = '010200000366000000A40000'.decode('hex') #simpleblob 3des
    #look for multiple keys, just in case
    #currently there is only one matching byte sequence, so this is overkill
    keylocs = []
    i=0
    while 1:
        i = blue.find(blob_header, i)
        if i == -1 or i+36 >= len(blue):
            break
        i += len(blob_header)
        #parity check, again not really necessary but what the hell
        p = 1 #3des key bytes should have odd parity just like des
        for byte in [ord(c) for c in blue[i:i+24]]:
            byte ^= byte >> 4
            byte ^= byte >> 2
            p &= byte ^ (byte >> 1)

        if p:
            keylocs.append(i)

    if keylocs:
        print 'Number of possible keys found: %s' % len(keylocs)
    else:
        print >> sys.stderr, '!!! No keys found in blue.dll.'
        sys.exit(-1)

    keys = []
    for keyloc in keylocs:
        #build key blob
        #just convert to plaintextkeyblob as it's a little simpler to import
        keyblob = blue[keyloc:keyloc+24][::-1] #reverse key byte order when converting from simpleblob to plaintextkeyblob

        hKey = pyDes.triple_des(keyblob, pyDes.CBC, "\0\0\0\0\0\0\0\0", padmode=pyDes.PAD_PKCS5)
        keys.append((hKey, blue[keyloc-len(blob_header):keyloc+24], '080200000366000018000000'.decode('hex') + keyblob))

    for key in keys:
        simple, plain = key[1], key[2]
        print
        print '[                     SIMPLEBLOB (as found in blue.dll)                         ]'
        print '[    publickeystruc   ]'
        print '[type ver  res  alg_id] [alg_id] [                encryptedkey                  ]'
        print '   %s  %s %s %s %s %s' % \
              (simple[0].encode('hex'),
              simple[1].encode('hex'),
              simple[2:4][::-1].encode('hex'),
              simple[4:8][::-1].encode('hex'),
              simple[8:12][::-1].encode('hex'),
              simple[12:].encode('hex'))
        print
        print '[         PLAINTEXTKEYBLOB (converted from above simpleblob for import)            ]'
        print '[          hdr        ]'
        print '[type ver  res  alg_id] [dwKeySize] [                  rgbKeyData                  ]'
        print '   %s  %s %s %s    %s %s' % \
              (plain[0].encode('hex'),
              plain[1].encode('hex'),
              plain[2:4][::-1].encode('hex'),
              plain[4:8][::-1].encode('hex'),
              plain[8:12][::-1].encode('hex'),
              plain[12:].encode('hex'))
        print


    #queue of process results
    result_queue = Queue()
    
    sys.stdout.flush()
        
    try:
        #create decompile processes
        pool = Pool(processes=cpu_count())
        print_lock = Lock()

        args=("-", "", "-", "", "", "", "")
        pool.apply_async(test, args=args)

        with zipfile.ZipFile(os.path.join(eve_path, 'code.ccp'), 'r') as zf:
            for filename in zf.namelist():
                if filename[-4:] == '.pyj':
                    sys.stdout.write("@")
                    args = (keys, filename[:-1], zf.read(filename), result_queue, store_path, print_lock, pool)
                    pool.apply_async(test, args=args)
                    #pool.apply_async(unjumble, args=(pool, keys, filename[:-1], zf.read(filename), result_queue, store_path, print_lock))
                elif filename[-4:] == '.pyc':
                    sys.stdout.write("!")
                    pool.apply_async(process_func, args=(filename[:-1], zf.read(filename)[8:], result_queue, store_path, print_lock))
                break;

        pool.apply_async(test, args=("+", "", "+", "", "", "", ""))

        #wait for decompile processes to finish
        pool.close()
        pool.join()

        #pull results from the result queue
        okay_files = failed_files = 0
        try:
            while 1: #will terminate when queue.get() generates Empty exception
                (o, f) = result_queue.get(False)
                okay_files += o
                failed_files += f
        except Empty:
            pass
        print '# decompiled %i files: %i okay, %i failed' % \
              (okay_files + failed_files, okay_files, failed_files)
        print '# elapsed time:', datetime.now() - startTime
    except:
        traceback.print_exc()
        os._exit(0) #make Ctrl-C actually end process
