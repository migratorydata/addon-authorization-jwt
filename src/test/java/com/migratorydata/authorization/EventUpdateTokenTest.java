package com.migratorydata.authorization;

import com.migratorydata.authorization.common.config.Configuration;
import com.migratorydata.authorization.def.DefaultAuthorizationHandler;
import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.helper.EventConnect;
import com.migratorydata.authorization.helper.EventUpdate;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static com.migratorydata.authorization.def.DefaultAuthorizationHandler.*;
import static com.migratorydata.authorization.token.SessionOrderTest.generateToken;

public class EventUpdateTokenTest {

    protected MigratoryDataAuthorizationListener authorizationListener;
    private String clientAddress = "127.0.0.1:35274";
    private String expiredToken = generateToken(-100);
    private String validToken = generateToken(100);

    @Before
    public void onStart() {
        initialize();
    }

    protected void initialize() {
        Configuration conf = Configuration.getConfiguration();
        authorizationListener = new DefaultAuthorizationHandler(conf.getMillisBeforeRenewal(), conf.getJwtVerifyParser());
    }


    @After
    public void shutdown() {
        authorizationListener.onDispose();
    }

    @Test
    public void test_null_token() {
        ClientCredentials clientCredentials = new ClientCredentials(null, clientAddress);

        EventUpdate connectRequest = new EventUpdate(clientCredentials);
        authorizationListener.onClientUpdateToken(connectRequest);
        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_empty_token() {
        ClientCredentials clientCredentials = new ClientCredentials("", clientAddress);

        EventUpdate connectRequest = new EventUpdate(clientCredentials);
        authorizationListener.onClientUpdateToken(connectRequest);
        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_expired_token() {
        ClientCredentials clientCredentials = new ClientCredentials(expiredToken, clientAddress);
        EventUpdate connectRequest = new EventUpdate(clientCredentials);
        authorizationListener.onClientUpdateToken(connectRequest);
        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_EXPIRED.getStatus());
    }

    @Test
    public void test_update_token() {
        EventConnect connectRequest = new EventConnect(new ClientCredentials(validToken, clientAddress));
        authorizationListener.onClientConnect(connectRequest);

        Assert.assertTrue(connectRequest.getReason() == "TOKEN_VALID");

        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);
        EventUpdate updateRequest = new EventUpdate(clientCredentials);
        authorizationListener.onClientUpdateToken(updateRequest);

        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_UPDATED.getStatus());
    }

    @Test
    public void test_valid_token() {
        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);
        EventUpdate updateRequest = new EventUpdate(clientCredentials);
        authorizationListener.onClientUpdateToken(updateRequest);

        Assert.assertTrue(clientCredentials.getNotification().getStatus() == TOKEN_UPDATED.getStatus());
    }

}
