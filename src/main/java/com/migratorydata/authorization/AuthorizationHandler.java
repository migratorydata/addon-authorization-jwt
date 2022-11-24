package com.migratorydata.authorization;

import com.migratorydata.authorization.client.Session;
import com.migratorydata.authorization.token.Token;
import com.migratorydata.authorization.token.TokenExpirationHandler;
import com.migratorydata.authorization.config.Configuration;
import com.migratorydata.extensions.authorization.v2.*;
import com.migratorydata.extensions.authorization.v2.client.*;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.util.HashMap;
import java.util.Map;

public class AuthorizationHandler implements MigratoryDataAuthorizationListener {
    public static final StatusNotification TOKEN_VALID = new StatusNotification("NOTIFY_TOKEN_VALID", "NOTIFY_TOKEN_VALID");
    public static final StatusNotification TOKEN_EXPIRED = new StatusNotification("NOTIFY_TOKEN_EXPIRED", "NOTIFY_TOKEN_EXPIRED");
    public static final StatusNotification TOKEN_TO_EXPIRE = new StatusNotification("NOTIFY_TOKEN_TO_EXPIRE", "NOTIFY_TOKEN_TO_EXPIRE");
    public static final StatusNotification TOKEN_INVALID = new StatusNotification("NOTIFY_TOKEN_INVALID", "NOTIFY_TOKEN_INVALID");
    public static final StatusNotification TOKEN_UPDATED = new StatusNotification("NOTIFY_TOKEN_UPDATED", "NOTIFY_TOKEN_UPDATED");

    private final Map<String, Session> sessions = new HashMap<>();
    private final TokenExpirationHandler tokenExpirationHandler;
    private JwtParser jwtVerifyParser;

    public AuthorizationHandler() {
        Configuration conf = Configuration.getConfiguration();
        tokenExpirationHandler = new TokenExpirationHandler(conf.getMillisBeforeRenewal());

        if ("hmac".equals(conf.getSignatureType())) {
            jwtVerifyParser = Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(conf.getHMACSecretKey()))).build();
        } else if ("rsa".equals(conf.getSignatureType())){
            try {
                jwtVerifyParser = Jwts.parserBuilder().setSigningKey(conf.getRSAPublicKey()).build();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("Invalid signature type, check the parameter 'signature.type'");
            System.exit(98);
        }
    }

    @Override
    public void onClientConnect(EventConnect eventConnect) {
        System.out.println("onClientConnect - " + eventConnect);

        Token token = new Token(eventConnect.getClient().getToken());
        if (token.parseToken(jwtVerifyParser)) {
            Session session = new Session(eventConnect.getClient(), token);
            sessions.put(session.getClientAddress(), session);
            tokenExpirationHandler.add(session);
            eventConnect.authorize(true, TOKEN_VALID.getStatus());
        } else {
            eventConnect.authorize(false, token.getErrorNotification().getStatus());
        }
    }

    @Override
    public void onClientUpdateToken(EventUpdateToken eventUpdateToken) {
        System.out.println("onClientUpdateToken - " + eventUpdateToken);

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
        System.out.println("onClientSubscribe - " + eventSubscribe);

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
        System.out.println("onClientPublish - " + eventPublish);

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
        System.out.println("onClientDisconnect - " + eventDisconnect);

        Session session = sessions.remove(eventDisconnect.getClient().getClientAddress());
        if (session != null) {
            tokenExpirationHandler.remove(session);
        }
    }

    @Override
    public void onInit() {
        System.out.println("onInit");
    }

    @Override
    public void onDispose() {
        System.out.println("onDispose");
    }
}
