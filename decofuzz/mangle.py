#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
import logging
import random
import os
import subprocess

logger = logging.getLogger("decofuzz.mangle")

class General(object):
    @staticmethod
    def none(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] none")
        return data
    
class Token(object):
    @staticmethod
    def token_inject_pipes(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] token piper ||| yes ;)")
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,"|")
        return data
    @staticmethod
    def token_inject_gibberish(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] token gibberish")
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,os.urandom(len(rand_token)))
        return data
    @staticmethod
    def token_duplicate(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] token duplicate")
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,rand_token*2)
        return data
    @staticmethod
    def token_inject_html_marquee(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] token html marquee")
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,"<marquee>xss</marquee>")
        return data
    @staticmethod
    def token_inject_fmt(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] token fmt inject")
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,"This is a nasty fmt! whoop whoop %s%n%p%p%n%p %x%nwhoop")
        return data
    @staticmethod
    def token_inject_shell(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] token shell inject")
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,"$(whoami)`whoami`;whoami||whoami&&whoami\"'#")
        return data
    @staticmethod
    def token_multiply(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        factor = random.randint(1,1024)
        logger.info("  [mangle] token multiply by %d"%factor)
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,rand_token*factor)
        return data
    @staticmethod
    def token_drop(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] token vanish")
        rand_token = random.choice(data.split())
        data = data.replace(rand_token,"")
        return data
    
class Message(object):
    @staticmethod
    def msg_multiply(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        factor = random.randint(1,10)
        logger.info("  [mangle] msg multiply by %d"%factor)
        data = data*factor
        return data
    @staticmethod
    def msg_drop(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] msg vanish")
        return ""
    @staticmethod
    def msg_all_upper(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] all upper")
        data = data.upper()
        return data
    @staticmethod
    def msg_all_lower(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])     # func, vs object func
        logger.info("  [mangle] all lower")
        data = data.lower()
        return data
    @staticmethod
    def msg_random_incr(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] msg random incr")
        incr = random.randint(1, 255)
        index = random.randint(0,len(data))
        if random.randint(0, 1) == 1:
            incr = -incr
        offset = self.offset()
        data[offset] = max(min(0, data[index] + incr), 255)
        return data
    @staticmethod
    def msg_random_insert(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] msg random insert")
        index = random.randint(0,len(data))
        count = random.randint(1, 255)
        for index in xrange(count):
            data.insert(index, random.randint(0, 255))
        return data
    @staticmethod
    def msg_random_delete(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] msg random delete")
        index = random.randint(0,len(data))
        count = random.randint(1, 255)
        count = min(count, len(data)-index)
        del data[index:index+count]
        return data
    @staticmethod
    def msg_random_replace(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] msg random replace")
        index = random.randint(0,len(data))
        data[index] = random.randint(0,255)
        return data
    @staticmethod
    def msg_inverse_bit(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] inverse")
        index = random.randint(0,len(data))
        bitoffset = random.randint(0, 7)
        mask = 1 << (bitoffset & 7)
        #index = bitoffset >> 3
        if data[index] & mask:
            data[index] &= (~mask & 0xFF)
        else:
            data[index] |= mask
        return data
    @staticmethod
    def msg_bitflip_new(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] bitflip new")
        bit = random.randint(0, 7)
        index = random.randint(0,len(data))
        if random.randint(0, 1) == 1:
            value = data[index] | (1 << bit)
        else:
            value = data[index] & (~(1 << bit) & 0xFF)
        data[index] = value
        return data
    @staticmethod
    def msg_bitflip(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] bitflip")
        index = random.randint(0,len(data))
        try:
            data = list(data)
            data[index] = chr(ord(data[index])^1)
        except Exception, e:
            logger.warning("mangle %s"%repr(e))
        return "".join(data)

class ThirdParty(object):
    @staticmethod
    def radamsa(*args, **kwargs):
        self, data = (args[0], args[1]) if len(args)>1 else (None, args[0])
        logger.info("  [mangle] radamsa")
        cmd="./radamsa-0.4/radamsa-0.4-linux-i386-static"
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        return proc.communicate(input=data)[0].strip()