package com.migratorydata.authorization.token;

import com.migratorydata.authorization.config.Util;
import com.migratorydata.extensions.authorization.v2.client.StatusNotification;
import io.jsonwebtoken.*;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;

import java.util.Date;

import static com.migratorydata.authorization.AuthorizationHandler.TOKEN_EXPIRED;
import static com.migratorydata.authorization.AuthorizationHandler.TOKEN_INVALID;

public class Token {
    private final String token;
    private StatusNotification errorNotification = null;
    private Jws<Claims> jwsClaims = null;
    private Permissions permissions = null;

    public Token(String token) {
        this.token = token;
    }

    public boolean parseToken(JwtParser jwtParser) {
        try {
            jwsClaims = jwtParser.parseClaimsJws(token);
            permissions = new Permissions((JSONArray) new JSONParser().parse((String) jwsClaims.getBody().get(Util.PERMISSIONS_FIELD)));
        } catch (MalformedJwtException e1) {
            e1.printStackTrace();
            errorNotification = TOKEN_INVALID;
        } catch (JwtException ex) {
            ex.printStackTrace();
            errorNotification = TOKEN_EXPIRED;
        } catch (Exception e) {
            e.printStackTrace();
            errorNotification = TOKEN_INVALID;
        }
        return (errorNotification == null);
    }

    public StatusNotification getErrorNotification() {
        return errorNotification;
    }

    public boolean authorizeSubscribe(String topic) {
        Permissions.Operation operation = permissions.getOperation(topic);
        if (operation != null && (operation == Permissions.Operation.SUBSCRIBE || operation == Permissions.Operation.PUBLISH_SUBSCRIBE)) {
            return true;
        }
        return false;
    }

    public boolean authorizePublish(String topic) {
        Permissions.Operation operation = permissions.getOperation(topic);
        if (operation != null && (operation == Permissions.Operation.PUBLISH || operation == Permissions.Operation.PUBLISH_SUBSCRIBE)) {
            return true;
        }
        return false;
    }

    public boolean isTimeToRenew(int millisBeforeRenewal) {
        Date currentTime = new Date();
        long currentTimeMillis = currentTime.getTime();
        Date time = new Date(currentTimeMillis + millisBeforeRenewal);
        if (time.after(getExpirationTime())) {
            return true;
        }
        return false;
    }

    public Date getExpirationTime() {
        return jwsClaims.getBody().getExpiration();
    }
}
