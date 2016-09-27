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

from ovs import vlog

from ovn_k8s.common import kubernetes
from ovn_k8s.common import variables
import ovn_k8s.processor as processor
import ovn_k8s.watcher.policy_watcher

log = vlog.Vlog('policy_processor')
pw = ovn_k8s.watcher.policy_watcher


class PolicyProcessor(processor.BaseProcessor):

    def __init__(self, pool):
        super(PolicyProcessor, self).__init__()
        self._pool = pool
        self._np_watcher_threads = {}

    def _pod_matches_from_clause(self, pod_data, ns_data, policy_rule):
        pod_labels = pod_data['metadata'].get('labels', {})
        from_clause = policy_rule.get('from')
        if not from_clause:
            # Empty from clause means policy affects all pods
            return True
        # NOTE: In this case a missing element and an empty element have
        # different semantics
        if 'podsSelector' in from_clause:
            from_pods = from_clause.get('podSelector')
            if not from_pods:
                # Empty pod selector means policy affect all pods in
                # the current namespace
                return True
            # NOTE: the current code assumes only equality-based selectors
            for label in set(pod_labels.keys()) & set(from_pods.keys()):
                if pod_labels[label] == from_pods[label]:
                    return True
        elif 'namespaceSelector' in from_clause:
            from_namespaces = from_clause.get('namespaceSelector')
            if not from_namespaces:
                # Empty namespace selector means all namespaces, and therefore
                # the pod's one as well
                return True
            # NOTE: the current code assumes only equality-based selectors
            ns_labels = ns_data['metadata'].get('labels', {})
            for label in set(ns_labels.keys()) & set(from_namespaces.keys()):
                if pod_labels[label] == from_namespaces[label]:
                    return True
        # We tried very hard, but no match was found
        return False

    def _find_policies_for_pod(self, pod_data):
        # This function return the policies for which there is a rule whose
        # fram clause matches pod labels (or nnemspaces)
        pod_policies = {}
        pod_ns = pod_data['metadata']['namespace']
        ns_data = kubernetes.get_namespace(variables.K8S_API_SERVER, pod_ns)
        for policy in kubernetes.get_network_policies(
                variables.K8S_API_SERVER, pod_ns):
            matching_rules = []
            for rule in policy['spec']['ingress']:
                if self._pod_matches_from_clause(pod_data, ns_data, rule):
                    matching_rules.append(rule)
            if matching_rules:
                policy_id = policy['metadata']['uid']
                pod_policies[policy_id] = {'policy': policy,
                                           'rules': matching_rules}
        return pod_policies

    def _process_ns_event(self, event, affected_pods, pod_events):
        log.dbg("Processing event %s from namespace %s" % (
            event.event_type, event.source))
        namespace = event.source
        # TODO(salv-orlando): handle namespace isolation change events

        def scan_pods():
            ns_pods = kubernetes.get_pods_by_namespace(
                variables.K8S_API_SERVER, event.source)
            for pod in ns_pods:
                pod_id = pod['metadata']['uid']
                affected_pods[pod_id] = pod
                pod_events.setdefault(pod_id, []).append(event)

        if event.event_type == 'ADDED':
            log.dbg("Namespace %s added - spawning policy watcher" % namespace)
            watcher_thread = pw.create_namespace_watcher(
                namespace, self._pool)
            self._np_watcher_threads[namespace] = watcher_thread
            # Upon restart this event will be receive for existing pods.
            # The namespace isolation status might have changed while the
            # watcher was not running. Pods in the namespace need to be
            # checked again
            scan_pods()
        elif event.event_type == 'DELETED':
            watcher_thread = self._np_watcher_threads.pop(namespace)
            pw.remove_namespace_watcher(watcher_thread)
        elif event.event_type == 'MODIFIED':
            # This a transition in the namespace isolation status. All the pods
            # in the namespace are affected
            scan_pods()

    def _process_pod_event(self, event, affected_pods, pod_events):
        log.dbg("Processing event %s from pod %s" % (
            event.event_type, event.source))
        pod_data = event.metadata
        # Pods are always affected if the namespace is isolated
        if not kubernetes.is_namespace_isolated(
                variables.K8S_API_SERVER, pod_data['metadata']['namespace']):
            log.dbg("Namespace %s for pod %s is not isolated, no further "
                    "processing required" % (pod_data['metadata']['namespace'],
                                             event.source))
            return
        pod_id = pod_data['metadata']['uid']
        affected_pods[pod_id] = pod_data
        pod_events.setdefault(pod_id, []).append(event)
        # Find policies whoe PodSelector matches this pod
        affected_policies = self._find_policies_for_pod(pod_data)
        if affected_policies:
            log.dbg("Event for pod %s affects %d network policies."
                    "Generating policy events" % (
                         pod_id, len(affected_policies)))
        else:
            log.dbg("Event for pod %s does not affect any network "
                    "policy. No further processing needed" % pod_id)
        # For each policy generate a policy update event and send it
        # back to the queue
        for policy_id, data in affected_policies:
            policy = data['policy']
            custom_policy_data = policy.setdefault('custom', {})
            custom_policy_data.update({'from_changed': data['rules']})
            get_event_queue().put((processor.NPEvent(
                'UPDATED', policy['metadata']['name'], policy)))

    def _process_np_event(self, event, affected_pods, pod_events,
                          affected_policies):
        log.dbg("Processing event %s from network policy %s" % (
            event.event_type, event.source))
        namespace = event.metadata['metadata']['namespace']
        policy = event.source
        policy_data = event.metadata
        if not kubernetes.is_namespace_isolated(variables.K8S_API_SERVER,
                                                namespace):
            log.warn("Policy %s applied to non-isolated namespace:%s."
                     "Skipping processing" % (policy, namespace))
            return
        # Retrieve pods matching policy selector
        # TODO: use pod cache, even if doing the selector query is so easy
        pod_selector = policy_data.get('podSelector', {})
        pods = kubernetes.get_pods_by_namespace(
            variables.K8S_API_SERVER,
            namespace=namespace,
            pod_selector=pod_selector)
        for pod in pods:
            pod_id = pod['metadata']['uid']
            affected_pods[pod_id] = pod
            pod_events.setdefault(pod_id, []).append(event)
        from_changed = event.metadata.get('from_changed', False)
        if from_changed:
            policy_id = policy_data['metadata']['uid']
            affected_policies[policy_id] = policy_data
        return pods

    def process_events(self, events):
        log.dbg("Processing %d events from queue" % len(events))
        affected_pods = {}
        affected_policies = {}
        pod_events = {}
        for event in events[:]:
            if isinstance(event, processor.NSEvent):
                # namespace add -> create policy watcher
                # namespace delete -> destory policy watcher
                # namespace update -> check isolation property
                self._process_ns_event(event, affected_pods, pod_events)
            elif isinstance(event, processor.NPEvent):
                # policy add -> create ACLs for affected pods
                # policy delete -> remove ACLs for affected pods
                self._process_np_event(event, affected_pods, pod_events,
                                       affected_policies)
            elif isinstance(event, processor.PodEvent):
                # relevant policies must be applied to pod
                # check policies that select pod in from clause
                self._process_pod_event(event, affected_pods, pod_events)

            events.remove(event)
        for pod_id in affected_pods:
            log.dbg("Rebuilding ACL for pod:%s because of:%s" %
                    (pod_id, "; ".join(['%s from %s' % (event.event_type,
                                                        event.source)
                                        for event in pod_events[pod_id]])))

        for policy in affected_policies:
            log.dbg("Affected policy: %s" % policy)

        for event in events:
            log.warn("Event %s from %s was not processed. ACLs might not be "
                     "in sync with network policies" % (event.event_type,
                                                        event.source))
        else:
            log.info("Event processing terminated.")


def get_event_queue():
    """Returns the event queue from the Policy Processor instance."""
    return PolicyProcessor.get_instance().event_queue


def run_processor(pool):
    PolicyProcessor.get_instance(pool).run()
