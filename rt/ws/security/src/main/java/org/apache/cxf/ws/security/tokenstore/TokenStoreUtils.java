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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.w3c.dom.Element;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;

/**
 * Some common functionality
 */
public final class TokenStoreUtils {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private TokenStoreUtils() {
        // complete
    }

    /**
     * Get a cache key for a signed SAML Assertion, that can be used to store and retrieve the (validated)
     * Assertion in/from a TokenStore. The key is a SHA-256 digest over the canonicalized SignedInfo
     * (which binds the signed content of the Assertion) and the SignatureValue. It returns null if the
     * Assertion is not signed, or if the signature does not conform to the SAML signature profile (in which
     * case the signature might not cover the Assertion itself, and so the Assertion must not be cached).
     *
     * This method must be used to look up a received Assertion in a TokenStore.
     */
    public static String getCacheKey(AssertionWrapper assertion) throws WSSecurityException {
        return getCacheKey(assertion, true);
    }

    /**
     * Get a cache key for a signed SAML Assertion - see getCacheKey(AssertionWrapper).
     * @param validateSignatureProfile whether to check that the signature conforms to the SAML signature
     *        profile first, returning null if it doesn't. This must be true when looking up a received
     *        Assertion. It can be false when storing an Assertion that was just signed by the STS, as
     *        its DOM Element might not be attached to a Document, which the profile validation requires.
     */
    public static String getCacheKey(AssertionWrapper assertion, boolean validateSignatureProfile)
        throws WSSecurityException {
        byte[] signatureValue = assertion.getSignatureValue();
        if (signatureValue == null || signatureValue.length == 0) {
            return null;
        }

        if (validateSignatureProfile) {
            try {
                assertion.validateSignatureAgainstProfile();
            } catch (WSSecurityException ex) {
                return null;
            }
        }

        Element signedInfo = null;
        Element assertionElement = assertion.getElement();
        if (assertionElement == null && assertion.getXmlObject() != null) {
            assertionElement = assertion.getXmlObject().getDOM();
        }
        if (assertionElement != null) {
            Element signature =
                DOMUtils.getFirstChildWithName(assertionElement, WSConstants.SIG_NS, WSConstants.SIG_LN);
            if (signature != null) {
                signedInfo = DOMUtils.getFirstChildWithName(signature, WSConstants.SIG_NS, "SignedInfo");
            }
        }
        if (signedInfo == null) {
            return null;
        }

        try {
            if (!Init.isInitialized()) {
                Init.init();
            }
            byte[] signedInfoBytes =
                Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                    .canonicalizeSubtree(signedInfo);

            return computeCacheKey("SAML", signedInfoBytes, signatureValue);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity", null, ex);
        }
    }

    /**
     * Get a cache key for a UsernameToken, that can be used to store and retrieve the (validated)
     * UsernameToken in/from a TokenStore. The key is a SHA-256 digest over the UsernameToken values.
     */
    public static String getCacheKey(UsernameToken usernameToken) throws WSSecurityException {
        byte[] salt = usernameToken.getSalt();
        return computeCacheKey("UsernameToken",
                               toBytes(usernameToken.getName()),
                               toBytes(usernameToken.getPassword()),
                               toBytes(usernameToken.getPasswordType()),
                               toBytes(usernameToken.getNonce()),
                               toBytes(usernameToken.getCreated()),
                               salt,
                               toBytes(Integer.toString(usernameToken.getIteration())));
    }

    /**
     * Get a cache key for a BinarySecurityToken, that can be used to store and retrieve the (validated)
     * BinarySecurityToken in/from a TokenStore. The key is a SHA-256 digest over the token values.
     */
    public static String getCacheKey(BinarySecurity binarySecurity) {
        return computeCacheKey("BinarySecurityToken",
                               toBytes(binarySecurity.getValueType()),
                               toBytes(binarySecurity.getEncodingType()),
                               binarySecurity.getToken());
    }

    /**
     * Get a cache key for a SecurityContextToken, that can be used to store and retrieve the (validated)
     * SecurityContextToken in/from a TokenStore. The key is a SHA-256 digest over the token identifier.
     */
    public static String getCacheKey(SecurityContextToken securityContextToken) {
        String identifier = securityContextToken.getIdentifier();
        if (identifier == null) {
            return null;
        }
        return computeCacheKey("SecurityContextToken", toBytes(identifier));
    }

    private static byte[] toBytes(String value) {
        if (value == null) {
            return null;
        }
        try {
            return value.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String computeCacheKey(String tokenType, byte[]... values) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeUTF(tokenType);
            for (byte[] value : values) {
                // Length-prefix each value so that different combinations can't produce the same input
                if (value == null) {
                    out.writeInt(-1);
                } else {
                    out.writeInt(value.length);
                    out.write(value);
                }
            }
            out.flush();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHexString(digest.digest(bytes.toByteArray()));
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(HEX_CHARS[(b >> 4) & 0x0F]);
            sb.append(HEX_CHARS[b & 0x0F]);
        }
        return sb.toString();
    }
}
