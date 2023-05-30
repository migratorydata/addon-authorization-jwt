package com.migratorydata.authorization;

import com.migratorydata.authorization.common.config.Configuration;
import com.migratorydata.authorization.def.DefaultAuthorizationHandler;
import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.helper.EventConnect;
import com.migratorydata.extensions.authorization.v2.MigratoryDataAuthorizationListener;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static com.migratorydata.authorization.def.DefaultAuthorizationHandler.*;
import static com.migratorydata.authorization.token.SessionOrderTest.generateToken;

public class EventConnectTest {

    private final String clientAddress = "127.0.0.1:35274";
    private final String expiredToken = generateToken(-100);
    private final String validToken = generateToken(100);

    protected MigratoryDataAuthorizationListener authorizationListener;

    @Before
    public void onStart() {
        initialize();
    }

    protected void initialize() {
        Configuration conf = Configuration.getConfiguration();
        authorizationListener = new DefaultAuthorizationHandler(conf.getMillisBeforeRenewal(), conf.getJwtVerifyParser());
    }

    @After
    public void onDispose() {
        authorizationListener.onDispose();
    }

    @Test
    public void test_null_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials(null, clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_empty_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials("", clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == TOKEN_INVALID.getStatus());
    }

    @Test
    public void test_expired_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials(expiredToken, clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == TOKEN_EXPIRED.getStatus());
    }

    @Test
    public void test_valid_token() {
        EventConnect eventConnect = new EventConnect(new ClientCredentials(validToken, clientAddress));
        authorizationListener.onClientConnect(eventConnect);
        Assert.assertTrue(eventConnect.getReason() == "TOKEN_VALID");
    }

}
