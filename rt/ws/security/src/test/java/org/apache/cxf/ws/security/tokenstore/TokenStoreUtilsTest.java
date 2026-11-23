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
package org.apache.cxf.ws.security.tokenstore;

import java.io.IOException;
import java.io.StringReader;
import java.util.Collections;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLCallback;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.bean.AuthenticationStatementBean;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.opensaml.common.SAMLVersion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TokenStoreUtilsTest {

    @org.junit.Test
    public void testUnsignedAssertionHasNoCacheKey() throws Exception {
        AssertionWrapper assertion = createAssertion("alice", false);
        assertNull(TokenStoreUtils.getCacheKey(assertion));
    }

    @org.junit.Test
    public void testSignedAssertionCacheKey() throws Exception {
        AssertionWrapper assertion = createAssertion("alice", true);
        String cacheKey = TokenStoreUtils.getCacheKey(assertion);
        assertNotNull(cacheKey);
        // SHA-256 in hex
        assertTrue(cacheKey.matches("[0-9a-f]{64}"));

        // The key must be the same for the Assertion once it has been serialized + re-parsed
        String serialized = StaxUtils.toString(assertion.getElement());
        Document doc = StaxUtils.read(new StringReader(serialized));
        AssertionWrapper parsedAssertion = new AssertionWrapper(doc.getDocumentElement());
        assertEquals(cacheKey, TokenStoreUtils.getCacheKey(parsedAssertion));
    }

    @org.junit.Test
    public void testIssuedAssertionCacheKey() throws Exception {
        // An Assertion that was just signed is not attached to a Document, and so the (non-validating) key
        // is used to store it. It must match the key used to look up the Assertion when it is received.
        AssertionWrapper assertion = createAssertion("alice", true, false);
        String issuedKey = TokenStoreUtils.getCacheKey(assertion, false);
        assertNotNull(issuedKey);

        String serialized = StaxUtils.toString(assertion.getElement());
        Document doc = StaxUtils.read(new StringReader(serialized));
        AssertionWrapper receivedAssertion = new AssertionWrapper(doc.getDocumentElement());
        assertEquals(issuedKey, TokenStoreUtils.getCacheKey(receivedAssertion));
    }

    @org.junit.Test
    public void testDifferentAssertionsHaveDifferentCacheKeys() throws Exception {
        String aliceKey = TokenStoreUtils.getCacheKey(createAssertion("alice", true));
        String bobKey = TokenStoreUtils.getCacheKey(createAssertion("bob", true));
        assertNotEquals(aliceKey, bobKey);
    }

    @org.junit.Test
    public void testModifiedSignedInfoChangesCacheKey() throws Exception {
        AssertionWrapper assertion = createAssertion("alice", true);
        String cacheKey = TokenStoreUtils.getCacheKey(assertion);

        // Change the DigestValue of the SignedInfo, keeping the same SignatureValue
        Element digestValue = (Element)assertion.getElement()
            .getElementsByTagNameNS(WSConstants.SIG_NS, "DigestValue").item(0);
        digestValue.setTextContent("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        AssertionWrapper modifiedAssertion = new AssertionWrapper(assertion.getElement());

        assertNotEquals(cacheKey, TokenStoreUtils.getCacheKey(modifiedAssertion));
    }

    @org.junit.Test
    public void testSignatureNotConformingToProfileHasNoCacheKey() throws Exception {
        AssertionWrapper assertion = createAssertion("alice", true);
        assertNotNull(TokenStoreUtils.getCacheKey(assertion));

        // The signature Reference no longer points to the Assertion itself
        Element reference = (Element)assertion.getElement()
            .getElementsByTagNameNS(WSConstants.SIG_NS, "Reference").item(0);
        reference.setAttributeNS(null, "URI", "#some-other-id");
        AssertionWrapper modifiedAssertion = new AssertionWrapper(assertion.getElement());

        assertNull(TokenStoreUtils.getCacheKey(modifiedAssertion));
    }

    @org.junit.Test
    public void testUsernameTokenCacheKey() throws Exception {
        String key1 = TokenStoreUtils.getCacheKey(createUsernameToken("alice", "password"));
        String key2 = TokenStoreUtils.getCacheKey(createUsernameToken("alice", "password"));
        assertEquals(key1, key2);
        assertTrue(key1.matches("[0-9a-f]{64}"));

        assertNotEquals(key1, TokenStoreUtils.getCacheKey(createUsernameToken("bob", "password")));
        assertNotEquals(key1, TokenStoreUtils.getCacheKey(createUsernameToken("alice", "password2")));
        // Values must not be able to "shift" between fields
        assertNotEquals(TokenStoreUtils.getCacheKey(createUsernameToken("ab", "c")),
                        TokenStoreUtils.getCacheKey(createUsernameToken("a", "bc")));
    }

    private static UsernameToken createUsernameToken(String name, String password) {
        Document doc = DOMUtils.createDocument();
        UsernameToken usernameToken = new UsernameToken(true, doc, WSConstants.PASSWORD_TEXT);
        usernameToken.setName(name);
        usernameToken.setPassword(password);
        return usernameToken;
    }

    private static AssertionWrapper createAssertion(String subjectName, boolean signed) throws Exception {
        return createAssertion(subjectName, signed, true);
    }

    private static AssertionWrapper createAssertion(String subjectName, boolean signed, boolean attach)
        throws Exception {
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(new SAML2CallbackHandler(subjectName));

        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        if (signed) {
            Crypto crypto = CryptoFactory.getInstance("alice.properties");
            assertion.signAssertion("alice", "password", crypto, false);
        }
        Document doc = DOMUtils.createDocument();
        Element element = assertion.toDOM(doc);
        if (attach && element.getParentNode() == null) {
            // As for a received token, the signature profile validation requires the Element to be attached
            doc.appendChild(element);
        }
        return assertion;
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
