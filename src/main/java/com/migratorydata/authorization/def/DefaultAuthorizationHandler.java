package com.migratorydata.authorization.def;

import com.migratorydata.authorization.common.client.Session;
import com.migratorydata.authorization.common.token.Token;
import com.migratorydata.authorization.common.token.TokenExpirationHandler;
import com.migratorydata.extensions.authorization.v2.*;
import com.migratorydata.extensions.authorization.v2.client.*;
import io.jsonwebtoken.JwtParser;

import java.util.HashMap;
import java.util.Map;

public class DefaultAuthorizationHandler implements MigratoryDataAuthorizationListener {

    public static final StatusNotification TOKEN_EXPIRED = new StatusNotification("NOTIFY_TOKEN_EXPIRED", "NOTIFY_TOKEN_EXPIRED");
    public static final StatusNotification TOKEN_TO_EXPIRE = new StatusNotification("NOTIFY_TOKEN_TO_EXPIRE", "NOTIFY_TOKEN_TO_EXPIRE");
    public static final StatusNotification TOKEN_INVALID = new StatusNotification("NOTIFY_TOKEN_INVALID", "NOTIFY_TOKEN_INVALID");
    public static final StatusNotification TOKEN_UPDATED = new StatusNotification("NOTIFY_TOKEN_UPDATED", "NOTIFY_TOKEN_UPDATED");

    private final Map<String, Session> sessions = new HashMap<>();
    private final TokenExpirationHandler tokenExpirationHandler;
    private final JwtParser jwtVerifyParser;

    public DefaultAuthorizationHandler(long millisBeforeRenewal, JwtParser jwtVerifyParser) {
        this.jwtVerifyParser = jwtVerifyParser;

        tokenExpirationHandler = new TokenExpirationHandler(millisBeforeRenewal);
    }

    @Override
    public void onClientConnect(EventConnect eventConnect) {
        // System.out.println("onClientConnect - " + eventConnect);

        Token token = new Token(eventConnect.getClient().getToken());
        if (token.parseToken(jwtVerifyParser)) {
            Session session = new Session(eventConnect.getClient(), token);
            sessions.put(session.getClientAddress(), session);
            tokenExpirationHandler.add(session);
            eventConnect.authorize(true, "TOKEN_VALID");
        } else {
            eventConnect.authorize(false, token.getErrorNotification().getStatus());
        }
    }

    @Override
    public void onClientUpdateToken(EventUpdateToken eventUpdateToken) {
        // System.out.println("onClientUpdateToken - " + eventUpdateToken);

        Token token = new Token(eventUpdateToken.getClient().getToken());
        if (token.parseToken(jwtVerifyParser)) {
            Session session = new Session(eventUpdateToken.getClient(), token);
            tokenExpirationHandler.add(session);
            Session previousSession = sessions.put(session.getClientAddress(), session);
            if (previousSession != null) {
                previousSession.setTokenRenewalCompleted();
            }
            eventUpdateToken.getClient().sendStatusNotification(TOKEN_UPDATED);
        } else {
            eventUpdateToken.getClient().sendStatusNotification(token.getErrorNotification());
        }
    }

    @Override
    public void onClientSubscribe(EventSubscribe eventSubscribe) {
        // System.out.println("onClientSubscribe - " + eventSubscribe);

        Map<String, Boolean> permissions = new HashMap<String, Boolean>();
        Session session = sessions.get(eventSubscribe.getClient().getClientAddress());
        if (session != null) {
            for (String subject : eventSubscribe.getSubjects()) {
                permissions.put(subject, session.getToken().authorizeSubscribe(subject));
            }
        }
        eventSubscribe.authorize(permissions);
    }

    @Override
    public void onClientPublish(EventPublish eventPublish) {
        // System.out.println("onClientPublish - " + eventPublish);

        boolean permission = false;
        Session session = sessions.get(eventPublish.getClient().getClientAddress());
        if (session != null) {
            String subject = eventPublish.getSubject();
            if (session.getToken().authorizePublish(subject)) {
                permission = true;
            }
        }
        eventPublish.authorize(permission);
    }

    @Override
    public void onClientDisconnect(EventDisconnect eventDisconnect) {
        // System.out.println("onClientDisconnect - " + eventDisconnect);

        Session session = sessions.remove(eventDisconnect.getClient().getClientAddress());
        if (session != null) {
            tokenExpirationHandler.remove(session);
        }
    }

    @Override
    public void onInit() {
        System.out.println("onInit: JWT Authorization Addon");
    }

    @Override
    public void onDispose() {
        System.out.println("onDispose: JWT Authorization Addon");
    }
}
