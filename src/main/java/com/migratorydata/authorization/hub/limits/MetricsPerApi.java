package com.migratorydata.authorization.hub.limits;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MetricsPerApi {

    private final Map<String, Integer> clientsPerSubject = new HashMap<>();
    private long messages = 0;

    private long connections = 0;

    public void inc(List<String> subjects) {
        subjects.forEach((s -> clientsPerSubject.merge(s, 1, Integer::sum)));
    }

    public void dec(Collection<String> subjects) {
        subjects.forEach((s -> {
            Integer clients = clientsPerSubject.get(s);
            if (clients != null && clients > 0) {
                clientsPerSubject.put(s, clients - 1);
            }
        }));
    }

    public void countMessages(String subject) {
        Integer count = clientsPerSubject.get(subject);
        messages++; // +1 for publish message
        //TODO: multiply the number of messages with the number of servers
        if (count != null) {
            messages += count; // +number of sessions, message broadcast
        }
    }

    public long getAndReset() {
        long tmp = messages;
        messages = 0;
        return tmp;
    }

    public void incConnections() {
        connections++;
    }

    public void decConnections() {
        connections--;
    }

    public long getConnections() {
        return connections;
    }
}
