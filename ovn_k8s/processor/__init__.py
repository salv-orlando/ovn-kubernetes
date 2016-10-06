# Copyright (C) 2016 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc
import six
import sys
import time
from six.moves import queue

import ovs.vlog
import ovn_k8s.modes.overlay
import ovn_k8s.common.variables as variables

vlog = ovs.vlog.Vlog("baseprocessor")


class Event(object):

    def __init__(self, event_type, source, metadata):
        self.event_type = event_type
        self.source = source
        self.metadata = metadata

    def __str__(self):
        return "%s:%s" % (self.event_type, self.source)


class NSEvent(Event):
    pass


class NPEvent(Event):
    pass


class PodEvent(Event):
    pass


@six.add_metaclass(abc.ABCMeta)
class BaseProcessor(object):

    _instance = None

    @classmethod
    def get_instance(cls, *args):
        if cls._instance is None:
            cls._instance = cls(*args)
        return cls._instance

    def __init__(self):
        self.event_queue = queue.PriorityQueue()
        if variables.OVN_MODE == "overlay":
            self.mode = ovn_k8s.modes.overlay.OvnNB()
        else:
            vlog.emer("OVN mode not defined.")
            sys.exit(1)

    @abc.abstractmethod
    def process_events(self, events):
        pass

    def run(self):
        events = []
        while True:
            try:
                # TODO: Not sure how wait with timeout plays with eventlet
                event = self.event_queue.get_nowait()
                events.append(event)
                vlog.dbg("Received event %s from %s"
                         % (event.event_type, event.source))
            except queue.Empty:
                # no element in the queue
                if events:
                    self.process_events(events)
                    events = []
                else:
                    # TODO: Do something better here.
                    time.sleep(0.1)
