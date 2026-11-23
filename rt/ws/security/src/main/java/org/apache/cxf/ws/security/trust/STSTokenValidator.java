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

import java.util.List;
import org.w3c.dom.Element;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.message.Message;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.tokenstore.TokenStore;
import org.apache.cxf.ws.security.tokenstore.TokenStoreFactory;
import org.apache.cxf.ws.security.tokenstore.TokenStoreUtils;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;

/**
 * 
 */
public class STSTokenValidator implements Validator {
    private boolean alwaysValidateToSts;
    
    public STSTokenValidator() {
    }
    
    /**
     * Construct a new instance.
     * @param alwaysValidateToSts whether to always validate the token to the STS
     */
    public STSTokenValidator(boolean alwaysValidateToSts) {
        this.alwaysValidateToSts = alwaysValidateToSts;
    }
    
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        
        if (isValidatedLocally(credential, data)) {
            return credential;
        }
        
        return validateWithSTS(credential, (SoapMessage)data.getMsgContext());
    }
    
    public Credential validateWithSTS(Credential credential, Message message) throws WSSecurityException {
        
        try {
            SecurityToken token = new SecurityToken();
            Element tokenElement = null;
            String cacheKey = null;
            if (credential.getAssertion() != null) {
                AssertionWrapper assertion = credential.getAssertion();
                cacheKey = TokenStoreUtils.getCacheKey(assertion);
                tokenElement = assertion.getElement();
            } else if (credential.getUsernametoken() != null) {
                tokenElement = credential.getUsernametoken().getElement();
                cacheKey = TokenStoreUtils.getCacheKey(credential.getUsernametoken());
            } else if (credential.getBinarySecurityToken() != null) {
                tokenElement = credential.getBinarySecurityToken().getElement();
                cacheKey = TokenStoreUtils.getCacheKey(credential.getBinarySecurityToken());
            } else if (credential.getSecurityContextToken() != null) {
                tokenElement = credential.getSecurityContextToken().getElement();
                cacheKey = TokenStoreUtils.getCacheKey(credential.getSecurityContextToken());
            }
            token.setToken(tokenElement);
            
            TokenStore tokenStore = getTokenStore(message);
            if (tokenStore != null && cacheKey != null) {
                SecurityToken transformedToken = getTransformedToken(tokenStore, cacheKey);
                if (transformedToken != null) {
                    AssertionWrapper assertion = new AssertionWrapper(transformedToken.getToken());
                    credential.setTransformedToken(assertion);
                    return credential;
                }
            }
            
            STSClient c = STSUtils.getClient(message, "sts");
            synchronized (c) {
                System.setProperty("noprint", "true");
                List<SecurityToken> tokens = c.validateSecurityToken(token);
                SecurityToken returnedToken = tokens.get(0);
                if (returnedToken != token) {
                    AssertionWrapper assertion = new AssertionWrapper(returnedToken.getToken());
                    credential.setTransformedToken(assertion);
                    if (cacheKey != null) {
                        tokenStore.add(returnedToken);
                        token.setTransformedTokenIdentifier(returnedToken.getId());
                        tokenStore.add(cacheKey, token);
                    }
                }
                return credential;
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity", null, e);
        }
    }
    
    static final TokenStore getTokenStore(Message message) {
        EndpointInfo info = message.getExchange().get(Endpoint.class).getEndpointInfo();
        synchronized (info) {
            TokenStore tokenStore = 
                (TokenStore)message.getContextualProperty(SecurityConstants.TOKEN_STORE_CACHE_INSTANCE);
            if (tokenStore == null) {
                tokenStore = (TokenStore)info.getProperty(SecurityConstants.TOKEN_STORE_CACHE_INSTANCE);
            }
            if (tokenStore == null) {
                TokenStoreFactory tokenStoreFactory = TokenStoreFactory.newInstance();
                String cacheKey = SecurityConstants.TOKEN_STORE_CACHE_INSTANCE;
                if (info.getName() != null) {
                    cacheKey += "-" + info.getName().toString().hashCode();
                }
                tokenStore = tokenStoreFactory.newTokenStore(cacheKey, message);
                info.setProperty(SecurityConstants.TOKEN_STORE_CACHE_INSTANCE, tokenStore);
            }
            return tokenStore;
        }
    }
    
    protected boolean isValidatedLocally(Credential credential, RequestData data) 
        throws WSSecurityException {
        
        if (!alwaysValidateToSts && credential.getAssertion() != null) {
            try {
                // STSSamlAssertionValidator records the trust verification result in an instance field, so
                // a new instance must be used for each request to avoid sharing state between requests
                STSSamlAssertionValidator samlValidator = new STSSamlAssertionValidator();
                samlValidator.validate(credential, data);
                return samlValidator.isTrustVerificationSucceeded();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "invalidSAMLsecurity", null, e);
            }
        }
        return false;
    }

    private SecurityToken getTransformedToken(TokenStore tokenStore, String cacheKey) {
        SecurityToken recoveredToken = tokenStore.getToken(cacheKey);
        if (recoveredToken != null) {
            String transformedTokenId = recoveredToken.getTransformedTokenIdentifier();
            if (transformedTokenId != null) {
                return tokenStore.getToken(transformedTokenId);
            }
        }
        return null;
    }
}
