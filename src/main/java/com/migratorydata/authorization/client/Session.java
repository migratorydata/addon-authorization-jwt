package com.migratorydata.authorization.client;

import com.migratorydata.authorization.token.Token;
import com.migratorydata.extensions.authorization.v2.client.Client;
import com.migratorydata.extensions.authorization.v2.client.StatusNotification;

public class Session {
    private Client client;
    private Token token;
    private volatile boolean tokenRenewalStarted = false;
    private long tokenRenewalTimestamp;

    public Session(Client client, Token token) {
        this.client = client;
        this.token = token;
    }

    public void sendStatusNotification(StatusNotification notification) {
        client.sendStatusNotification(notification);
    }

    public void startTokenRenewal() {
        tokenRenewalStarted = true;
        tokenRenewalTimestamp = System.currentTimeMillis();
    }

    public void setTokenRenewalCompleted() {
        tokenRenewalStarted = false;
    }

    public boolean isTokenRenewalCompleted() {
        return (tokenRenewalStarted == false);
    }

    public boolean hasTokenRenewalTimedOut(long currentTimeMillis, long millisBeforeRenewal) {
        if ((currentTimeMillis - tokenRenewalTimestamp) > millisBeforeRenewal) {
            return true;
        }
        return false;
    }

    public long getTokenRenewalTimestamp() {
        return tokenRenewalTimestamp;
    }

    public Token getToken() {
        return token;
    }

    public String getClientAddress() {
        return client.getClientAddress();
    }

    public void disconnect() {
        client.disconnect();
    }
}
