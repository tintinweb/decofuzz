#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
import inspect
import hashlib
import logging
import bisect
import random
from collections import Counter

logger = logging.getLogger("decofuzz.engine")

class StopFuzzing(Exception):pass

class Queue(object):
    STRATEGY_REPLACE = 1
    STRATEGY_PRE_MANGLE = 2
    STRATEGY_POST_MANGLE = 3
    def __init__(self):
        self.weighted_pick = WeightedChoice()
        self.strategy = self.STRATEGY_REPLACE
        
    def add(self, f, p=1, strategy=None):
        strategy = strategy if strategy else self.STRATEGY_REPLACE
        self.weighted_pick.add(f,p)
        
    def execute(self, *args, **kwargs):
        return self.weighted_pick.next()(*args,**kwargs)
    
    def get_stats(self):
        return self.weighted_pick.stats
    

class FuzzControl(object):
    def __init__(self):
        self.MUTATE_INT = True
        self.MUTATE_STR = True
        self.MUTATE_BYTE = True
        self.MUTATION_PER_RUN = 5
        self.signatures_func = {}
        self.signatures_invocations = {}
        self.fuzz_methods = {} # name: func
        self.reset()
        logger.debug("--init--")
        
    def reset(self):
        self.mutations = 0
        logger.info("--reset--")
        
    def add_fuzzdef(self, fname, f, p=1, strategy=None):
        self.fuzz_methods.setdefault(fname,Queue())
        self.fuzz_methods[fname].add(f=f,p=p,strategy=strategy)
        
    def hash_sig(self, seq):
        return hashlib.sha256(''.join(str(e) for e in seq)).hexdigest()
    
    def print_trace(self):
        for x in inspect.stack():
            logger.debug(x)
        logger.debug("-------")
        
    def candidate(self, f):
        signature = tuple([self.hash_sig(frame) for frame in inspect.stack()])
        self.signatures_func.setdefault(signature,0)
        logger.info("adding static candidate: %s"%f)
        self.print_trace()
        
        def mutate_candidate(*args, **kwargs):
            signature = tuple([self.hash_sig(frame) for frame in inspect.stack()])
            self.signatures_invocations.setdefault(signature,0)
            logger.info("adding dynamic candidate: %s"%f)
            self.print_trace()
            if self.mutations >= self.MUTATION_PER_RUN:
                raise StopFuzzing()
            if self.fuzz_methods.has_key(f.func_name) \
                and self.signatures_invocations[signature]==0 \
                and self.mutations < self.MUTATION_PER_RUN:
                self.mutations += 1
                # mutate
                logger.info("--WHOOP WHOOP MUTATE! %s - %s"%(f.func_name,repr(signature)))
                
                q = self.fuzz_methods[f.func_name]
                if q.strategy == Queue.STRATEGY_REPLACE:
                    return self.fuzz_methods[f.func_name].execute(*args, **kwargs)
                elif q.strategy == Queue.STRATEGY_PRE_MANGLE:
                    ret = self.fuzz_methods[f.func_name].execute(*args, **kwargs)
                    kwargs['wrapped_return'] = ret
                    return f(*args, **kwargs)
                elif q.strategy == Queue.STRATEGY_POST_MANGLE:
                    ret =  f(*args, **kwargs)
                    kwargs['wrapped_return'] = ret
                    return self.fuzz_methods[f.func_name].execute(*args, **kwargs)
            return f(*args, **kwargs)
        return mutate_candidate
    
    def get_stats(self, p=None):
        if p:
            return self.fuzz_methods[p].get_stats()
        stats = Counter()
        for f,o in self.fuzz_methods.iteritems():
            m = Counter(o.get_stats())
            stats += m
        return stats
    
class WeightedChoice(object):
    def __init__(self):
        self.totals = []
        self.weights = []
        self.running_total = 0
        self.stats = {}

    def add(self, f, p=1):
        self.weights.append((f,p))
        self.running_total += p
        self.totals.append(self.running_total)        

    def next(self):
        rnd = random.random() * self.totals[-1]
        i = bisect.bisect_right(self.totals, rnd)
        f = self.weights[i][0]
        self.stats.setdefault(f,0)
        self.stats[f]+=1
        return f

FuzzMaster = FuzzControl()
logger.info("FuzzControl init.")