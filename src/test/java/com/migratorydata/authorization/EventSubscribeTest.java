package com.migratorydata.authorization;

import com.migratorydata.authorization.config.Util;
import com.migratorydata.authorization.helper.ClientCredentials;
import com.migratorydata.authorization.helper.EventConnect;
import com.migratorydata.authorization.helper.EventSubscribe;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

import static com.migratorydata.authorization.token.SessionOrderTest.generateToken;

public class EventSubscribeTest {

    private AuthorizationHandler tokenAuthorizationHandler = new AuthorizationHandler();
    private String clientAddress = "127.0.0.1:35274";
    private String subject = "/s/s";
    private String expiredToken = generateToken(-100);

    // subject /s/s has permission for publish and subscribe
    private String validToken = generateToken(100);

    // subject /s/s has permission for publish
    private String validTokenWithPublishPermission = generateToken(100, subject, Util.PUB_FIELD);

    // subject /s/s has permission for subscribe
    private String validTokenWithSubscribePermission = generateToken(100, subject, Util.SUB_FIELD);

    @After
    public void onDispose() {
        tokenAuthorizationHandler.onDispose();
    }

    @Test
    public void test_null_token() {
        ClientCredentials clientCredentials = new ClientCredentials(null, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        tokenAuthorizationHandler.onClientConnect(eventConnect);

        EventSubscribe eventSubscribe = new EventSubscribe(clientCredentials, Arrays.asList(subject));
        tokenAuthorizationHandler.onClientSubscribe(eventSubscribe);

        Assert.assertNull(eventSubscribe.getPermissions().get(subject));
    }

    @Test
    public void test_expired_token() {
        ClientCredentials clientCredentials = new ClientCredentials(expiredToken, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        tokenAuthorizationHandler.onClientConnect(eventConnect);

        EventSubscribe eventSubscribe = new EventSubscribe(clientCredentials, Arrays.asList(subject));
        tokenAuthorizationHandler.onClientSubscribe(eventSubscribe);

        Assert.assertNull(eventSubscribe.getPermissions().get(subject));
    }

    @Test
    public void test_valid_token() {
        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        tokenAuthorizationHandler.onClientConnect(eventConnect);

        EventSubscribe eventSubscribe = new EventSubscribe(clientCredentials, Arrays.asList(subject));
        tokenAuthorizationHandler.onClientSubscribe(eventSubscribe);

        Assert.assertTrue(eventSubscribe.getPermissions().get(subject));
    }

    @Test
    public void test_valid_token_without_subject_permission() {
        String subjectWithoutPermission = "/s/s2";

        ClientCredentials clientCredentials = new ClientCredentials(validToken, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        tokenAuthorizationHandler.onClientConnect(eventConnect);

        EventSubscribe eventSubscribe = new EventSubscribe(clientCredentials, Arrays.asList(subjectWithoutPermission));
        tokenAuthorizationHandler.onClientSubscribe(eventSubscribe);

        Assert.assertFalse(eventSubscribe.getPermissions().get(subjectWithoutPermission));
    }

    @Test
    public void test_valid_token_with_publish_permission() {
        ClientCredentials clientCredentials = new ClientCredentials(validTokenWithPublishPermission, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        tokenAuthorizationHandler.onClientConnect(eventConnect);

        EventSubscribe eventSubscribe = new EventSubscribe(clientCredentials, Arrays.asList(subject));
        tokenAuthorizationHandler.onClientSubscribe(eventSubscribe);

        Assert.assertFalse(eventSubscribe.getPermissions().get(subject));
    }

    @Test
    public void test_valid_token_with_subscribe_permission() {
        ClientCredentials clientCredentials = new ClientCredentials(validTokenWithSubscribePermission, clientAddress);

        EventConnect eventConnect = new EventConnect(clientCredentials);
        tokenAuthorizationHandler.onClientConnect(eventConnect);

        EventSubscribe eventSubscribe = new EventSubscribe(clientCredentials, Arrays.asList(subject));
        tokenAuthorizationHandler.onClientSubscribe(eventSubscribe);

        Assert.assertTrue(eventSubscribe.getPermissions().get(subject));
    }
}
