package com.migratorydata.authorization;

import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.helper.EventConnect;
import com.migratorydata.authorization.helper.EventUpdate;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import static com.migratorydata.authorization.AuthorizationHandler.*;
import static com.migratorydata.authorization.token.SessionOrderTest.generateToken;

public class EventUpdateTokenTest {

    private AuthorizationHandler tokenAuthorizationHandler = new AuthorizationHandler();
    private String clientAddress = "127.0.0.1:35274";
    private String expiredToken = generateToken(-100);
    private String validToken = generateToken(100);

    @After
    public void shutdown() {
        tokenAuthorizationHandler.onDispose();
    }

    @Test
    public void test_null_token() {
        ClientCredentials clientCredentials = new ClientCredentials(null, clientAddress);

        EventUpdate connectRequest = new EventUpdate(clientCredentials);
        tokenAuthorizationHandler.onClientUpdateToken(connectRequest);
        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_empty_token() {
        ClientCredentials clientCredentials = new ClientCredentials("", clientAddress);

        EventUpdate connectRequest = new EventUpdate(clientCredentials);
        tokenAuthorizationHandler.onClientUpdateToken(connectRequest);
        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_expired_token() {
        ClientCredentials clientCredentials = new ClientCredentials(expiredToken, clientAddress);
        EventUpdate connectRequest = new EventUpdate(clientCredentials);
        tokenAuthorizationHandler.onClientUpdateToken(connectRequest);
        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_EXPIRED.getStatus());
    }

    @Test
    public void test_update_token() {
        EventConnect connectRequest = new EventConnect(new ClientCredentials(validToken, clientAddress));
        tokenAuthorizationHandler.onClientConnect(connectRequest);

        Assert.assertTrue(connectRequest.getReason() == "TOKEN_VALID");

        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);
        EventUpdate updateRequest = new EventUpdate(clientCredentials);
        tokenAuthorizationHandler.onClientUpdateToken(updateRequest);

        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_UPDATED.getStatus());
    }

    @Test
    public void test_valid_token() {
        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);
        EventUpdate updateRequest = new EventUpdate(clientCredentials);
        tokenAuthorizationHandler.onClientUpdateToken(updateRequest);

        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_UPDATED.getStatus());
    }

}
