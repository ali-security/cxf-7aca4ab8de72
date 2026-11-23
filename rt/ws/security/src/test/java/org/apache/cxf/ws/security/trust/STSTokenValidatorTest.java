/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.ws.security.trust;

import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.ExchangeImpl;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.service.model.BindingInfo;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.MemoryTokenStore;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.tokenstore.TokenStore;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLCallback;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.bean.AuthenticationStatementBean;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.validate.Credential;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.common.SAMLVersion;

/**
 * The STSTokenValidator caches the token that the STS returns for a validated token. A different
 * (not validated) token must never be mapped to a cached result, e.g. via a hash collision.
 */
public class STSTokenValidatorTest extends Assert {

    @Test
    public void testUsernameTokenHashCollisionIsNotCached() throws Exception {
        UsernameToken victim = createUsernameToken("alice", "Aa");
        // "BB" has the same String hashCode as "Aa", and so the UsernameToken has the same hashCode
        UsernameToken attacker = createUsernameToken("alice", "BB");
        assertEquals(victim.hashCode(), attacker.hashCode());

        TokenStore tokenStore = new MemoryTokenStore();
        StubSTSClient stsClient = new StubSTSClient(victim.getElement());
        STSTokenValidator validator = new STSTokenValidator(true);

        Credential credential = new Credential();
        credential.setUsernametoken(victim);
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getValidationCount());

        // The same UsernameToken (values) is retrieved from the cache
        credential = new Credential();
        credential.setUsernametoken(createUsernameToken("alice", "Aa"));
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getValidationCount());

        credential = new Credential();
        credential.setUsernametoken(attacker);
        assertRejected(validator, credential, createMessage(tokenStore, stsClient));
        assertEquals(2, stsClient.getValidationCount());
    }

    @Test
    public void testBinarySecurityTokenHashCollisionIsNotCached() throws Exception {
        // Arrays.hashCode is the same for {0, 31} and {1, 0}
        BinarySecurity victim = createBinarySecurityToken(new byte[] {0, 31});
        BinarySecurity attacker = createBinarySecurityToken(new byte[] {1, 0});
        assertEquals(victim.hashCode(), attacker.hashCode());

        TokenStore tokenStore = new MemoryTokenStore();
        StubSTSClient stsClient = new StubSTSClient(victim.getElement());
        STSTokenValidator validator = new STSTokenValidator(true);

        Credential credential = new Credential();
        credential.setBinarySecurityToken(victim);
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getValidationCount());

        credential = new Credential();
        credential.setBinarySecurityToken(attacker);
        assertRejected(validator, credential, createMessage(tokenStore, stsClient));
        assertEquals(2, stsClient.getValidationCount());
    }

    @Test
    public void testSecurityContextTokenHashCollisionIsNotCached() throws Exception {
        // "Aa" and "BB" have the same String hashCode
        SecurityContextToken victim = createSecurityContextToken("urn:uuid:Aa");
        SecurityContextToken attacker = createSecurityContextToken("urn:uuid:BB");
        assertEquals(victim.hashCode(), attacker.hashCode());

        TokenStore tokenStore = new MemoryTokenStore();
        StubSTSClient stsClient = new StubSTSClient(victim.getElement());
        STSTokenValidator validator = new STSTokenValidator(true);

        Credential credential = new Credential();
        credential.setSecurityContextToken(victim);
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getValidationCount());

        credential = new Credential();
        credential.setSecurityContextToken(attacker);
        assertRejected(validator, credential, createMessage(tokenStore, stsClient));
        assertEquals(2, stsClient.getValidationCount());
    }

    @Test
    public void testForgedAssertionWithCopiedSignatureValueIsNotCached() throws Exception {
        AssertionWrapper victim = createAssertion("alice", true);

        TokenStore tokenStore = new MemoryTokenStore();
        StubSTSClient stsClient = new StubSTSClient(victim.getElement());
        STSTokenValidator validator = new STSTokenValidator(true);

        Credential credential = new Credential();
        credential.setAssertion(victim);
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getValidationCount());

        // The same (received) Assertion is retrieved from the cache
        String serialized = StaxUtils.toString(victim.getElement());
        Document doc = StaxUtils.read(new StringReader(serialized));
        credential = new Credential();
        credential.setAssertion(new AssertionWrapper(doc.getDocumentElement()));
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getValidationCount());

        // Forge an Assertion for another subject, copying the SignatureValue of the cached Assertion
        AssertionWrapper forged = createAssertion("admin", true);
        Element forgedSignatureValue = (Element)forged.getElement()
            .getElementsByTagNameNS(WSConstants.SIG_NS, "SignatureValue").item(0);
        Element victimSignatureValue = (Element)victim.getElement()
            .getElementsByTagNameNS(WSConstants.SIG_NS, "SignatureValue").item(0);
        forgedSignatureValue.setTextContent(victimSignatureValue.getTextContent());
        AssertionWrapper attacker = new AssertionWrapper(forged.getElement());
        assertTrue(Arrays.equals(victim.getSignatureValue(), attacker.getSignatureValue()));

        credential = new Credential();
        credential.setAssertion(attacker);
        assertRejected(validator, credential, createMessage(tokenStore, stsClient));
        assertEquals(2, stsClient.getValidationCount());
    }

    @Test
    public void testUnsignedAssertionIsNotCached() throws Exception {
        AssertionWrapper victim = createAssertion("alice", false);

        TokenStore tokenStore = new MemoryTokenStore();
        StubSTSClient stsClient = new StubSTSClient(victim.getElement());
        STSTokenValidator validator = new STSTokenValidator(true);

        Credential credential = new Credential();
        credential.setAssertion(victim);
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertTrue(tokenStore.getTokenIdentifiers().isEmpty());

        credential = new Credential();
        credential.setAssertion(createAssertion("admin", false));
        assertRejected(validator, credential, createMessage(tokenStore, stsClient));
        assertEquals(2, stsClient.getValidationCount());
    }

    private static void assertRejected(STSTokenValidator validator, Credential credential, Message message) {
        try {
            validator.validateWithSTS(credential, message);
            fail("The token must be validated by the STS, and not be retrieved from the cache");
        } catch (WSSecurityException ex) {
            // expected
        }
        assertNull(credential.getTransformedToken());
    }

    private static Message createMessage(TokenStore tokenStore, STSClient stsClient) {
        EndpointInfo endpointInfo = new EndpointInfo();
        endpointInfo.setBinding(new BindingInfo(null, "http://schemas.xmlsoap.org/soap/"));
        endpointInfo.setProperty(SecurityConstants.TOKEN_STORE_CACHE_INSTANCE, tokenStore);

        Endpoint endpoint = EasyMock.createNiceMock(Endpoint.class);
        EasyMock.expect(endpoint.getEndpointInfo()).andReturn(endpointInfo).anyTimes();
        EasyMock.replay(endpoint);

        Exchange exchange = new ExchangeImpl();
        exchange.put(Endpoint.class, endpoint);
        Message message = new MessageImpl();
        message.setExchange(exchange);
        message.put(SecurityConstants.STS_CLIENT, stsClient);
        return message;
    }

    private static UsernameToken createUsernameToken(String name, String password) {
        Document doc = DOMUtils.createDocument();
        UsernameToken usernameToken = new UsernameToken(true, doc, WSConstants.PASSWORD_TEXT);
        usernameToken.setName(name);
        usernameToken.setPassword(password);
        return usernameToken;
    }

    private static BinarySecurity createBinarySecurityToken(byte[] token) {
        Document doc = DOMUtils.createDocument();
        BinarySecurity binarySecurity = new BinarySecurity(doc);
        binarySecurity.setValueType("http://custom-value-type");
        binarySecurity.setToken(token);
        return binarySecurity;
    }

    private static SecurityContextToken createSecurityContextToken(String identifier) throws Exception {
        Document doc = DOMUtils.createDocument();
        SecurityContextToken sct = new SecurityContextToken(doc);
        Element identifierElement =
            DOMUtils.getFirstChildWithName(sct.getElement(), sct.getElement().getNamespaceURI(), "Identifier");
        identifierElement.setTextContent(identifier);
        return new SecurityContextToken(sct.getElement());
    }

    private static AssertionWrapper createAssertion(String subjectName, boolean signed) throws Exception {
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(new SAML2CallbackHandler(subjectName));

        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        if (signed) {
            Crypto crypto = CryptoFactory.getInstance("alice.properties");
            assertion.signAssertion("alice", "password", crypto, false);
        }
        Document doc = DOMUtils.createDocument();
        Element element = assertion.toDOM(doc);
        if (element.getParentNode() == null) {
            // As for a received token, the Element is attached to a Document
            doc.appendChild(element);
        }
        return assertion;
    }

    /**
     * A mock STSClient, that only accepts the given token, and returns a SAML Assertion for it.
     */
    private static final class StubSTSClient extends STSClient {

        private final String acceptedToken;
        private int validationCount;

        StubSTSClient(Element acceptedToken) {
            super(null);
            // The SecurityToken that is sent to the STS holds a copy of the token Element
            SecurityToken token = new SecurityToken();
            token.setToken(acceptedToken);
            this.acceptedToken = StaxUtils.toString(token.getToken());
        }

        @Override
        public List<SecurityToken> validateSecurityToken(SecurityToken tok) throws Exception {
            validationCount++;
            if (!acceptedToken.equals(StaxUtils.toString(tok.getToken()))) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            SecurityToken returnedToken = new SecurityToken("transformed-" + validationCount);
            returnedToken.setToken(createAssertion("transformed", false).getElement());
            return Collections.singletonList(returnedToken);
        }

        int getValidationCount() {
            return validationCount;
        }
    }

    private static final class SAML2CallbackHandler implements CallbackHandler {

        private final String subjectName;

        SAML2CallbackHandler(String subjectName) {
            this.subjectName = subjectName;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof SAMLCallback) {
                    SAMLCallback samlCallback = (SAMLCallback)callback;
                    samlCallback.setSamlVersion(SAMLVersion.VERSION_20);
                    samlCallback.setIssuer("sts");
                    samlCallback.setSubject(new SubjectBean(subjectName, null, SAML2Constants.CONF_BEARER));

                    AuthenticationStatementBean authBean = new AuthenticationStatementBean();
                    authBean.setAuthenticationMethod("Password");
                    samlCallback.setAuthenticationStatementData(Collections.singletonList(authBean));
                } else {
                    throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
                }
            }
        }
    }
}
