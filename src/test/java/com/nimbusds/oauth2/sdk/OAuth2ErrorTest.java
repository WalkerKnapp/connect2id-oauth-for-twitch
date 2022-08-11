/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.oauth2.sdk;


import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;


/**
 * Tests the OAuth 2.0 error constants.
 */
public class OAuth2ErrorTest extends TestCase {
	
	
	public void testHTTPStatusCodes() {
		
		assertEquals(403, OAuth2Error.ACCESS_DENIED.getHTTPStatusCode());
		assertEquals(401, OAuth2Error.INVALID_CLIENT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_GRANT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_REQUEST.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_SCOPE.getHTTPStatusCode());
		assertEquals(500, OAuth2Error.SERVER_ERROR.getHTTPStatusCode());
		assertEquals(503, OAuth2Error.TEMPORARILY_UNAVAILABLE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNAUTHORIZED_CLIENT.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNSUPPORTED_GRANT_TYPE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_RESOURCE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_TARGET.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.OVERBROAD_SCOPE.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.INVALID_DPOP_PROOF.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.MISSING_TRUST_ANCHOR.getHTTPStatusCode());
		assertEquals(400, OAuth2Error.VALIDATION_FAILED.getHTTPStatusCode());
	}
	
	
	public void testJARErrors() {
		
		assertEquals("invalid_request_uri", OAuth2Error.INVALID_REQUEST_URI.getCode());
		assertEquals("Invalid request URI", OAuth2Error.INVALID_REQUEST_URI.getDescription());
		assertNull(OAuth2Error.INVALID_REQUEST_URI.getURI());
		assertEquals(302, OAuth2Error.INVALID_REQUEST_URI.getHTTPStatusCode());
		
		assertEquals("invalid_request_object", OAuth2Error.INVALID_REQUEST_OBJECT.getCode());
		assertEquals("Invalid request JWT", OAuth2Error.INVALID_REQUEST_OBJECT.getDescription());
		assertNull(OAuth2Error.INVALID_REQUEST_OBJECT.getURI());
		assertEquals(302, OAuth2Error.INVALID_REQUEST_OBJECT.getHTTPStatusCode());
		
		assertEquals("request_uri_not_supported", OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getCode());
		assertEquals("Request URI parameter not supported", OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getDescription());
		assertNull(OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getURI());
		assertEquals(302, OAuth2Error.REQUEST_URI_NOT_SUPPORTED.getHTTPStatusCode());
		
		assertEquals("request_not_supported", OAuth2Error.REQUEST_NOT_SUPPORTED.getCode());
		assertEquals("Request parameter not supported", OAuth2Error.REQUEST_NOT_SUPPORTED.getDescription());
		assertNull(OAuth2Error.REQUEST_NOT_SUPPORTED.getURI());
		assertEquals(302, OAuth2Error.REQUEST_NOT_SUPPORTED.getHTTPStatusCode());
	}
	
	
	public void testInvalidResourceError() {
		
		assertEquals("invalid_resource", OAuth2Error.INVALID_RESOURCE.getCode());
		assertEquals("Invalid or unaccepted resource", OAuth2Error.INVALID_RESOURCE.getDescription());
		assertEquals(400, OAuth2Error.INVALID_RESOURCE.getHTTPStatusCode());
	}
	
	
	public void testInvalidTargetError() {
		
		assertEquals("invalid_target", OAuth2Error.INVALID_TARGET.getCode());
		assertEquals("Invalid or unaccepted resource", OAuth2Error.INVALID_TARGET.getDescription());
		assertEquals(400, OAuth2Error.INVALID_TARGET.getHTTPStatusCode());
	}
	
	
	public void testIncrementalAuthorization_overbroadScopeError() {
		
		assertEquals("overbroad_scope", OAuth2Error.OVERBROAD_SCOPE.getCode());
		assertEquals("Overbroad scope", OAuth2Error.OVERBROAD_SCOPE.getDescription());
		assertEquals(400, OAuth2Error.OVERBROAD_SCOPE.getHTTPStatusCode());
	}
	
	
	public void testDPoPError() {
		
		assertEquals("invalid_dpop_proof", OAuth2Error.INVALID_DPOP_PROOF.getCode());
		assertEquals("Invalid DPoP proof", OAuth2Error.INVALID_DPOP_PROOF.getDescription());
		assertEquals(400, OAuth2Error.INVALID_DPOP_PROOF.getHTTPStatusCode());
	}
	
	
	public void testOpenIDConnectFederationErrors() {
		
		assertEquals("missing_trust_anchor", OAuth2Error.MISSING_TRUST_ANCHOR.getCode());
		assertEquals("No trusted anchor could be found", OAuth2Error.MISSING_TRUST_ANCHOR.getDescription());
		assertEquals(400, OAuth2Error.MISSING_TRUST_ANCHOR.getHTTPStatusCode());
		
		assertEquals("validation_failed", OAuth2Error.VALIDATION_FAILED.getCode());
		assertEquals("Trust chain validation failed", OAuth2Error.VALIDATION_FAILED.getDescription());
		assertEquals(400, OAuth2Error.VALIDATION_FAILED.getHTTPStatusCode());
	}
	
	
	public void testErrorCodeStringConstantsAreProvided() throws IllegalAccessException {
		Set<String> errorCodeStringConstants = getErrorCodeStringConstants();
		Set<ErrorObject> errorObjectConstants = getErrorObjectsConstants();
		for (ErrorObject eo : errorObjectConstants) {
			assertTrue(errorCodeStringConstants.contains(eo.getCode()));
		}
	}
	
	
	private Set<String> getErrorCodeStringConstants() throws IllegalAccessException {
		Field[] oAuth2ErrorFields = OAuth2Error.class.getDeclaredFields();
		Set<String> errorCodeStringConstants = new HashSet<>();
		for (Field field : oAuth2ErrorFields) {
			if (field.getType().equals(String.class)
				&& Modifier.isPublic(field.getModifiers())
				&& Modifier.isFinal(field.getModifiers())
				&& Modifier.isStatic(field.getModifiers())) {
				errorCodeStringConstants.add((String) field.get(this));
			}
		}
		return errorCodeStringConstants;
	}
	
	
	private Set<ErrorObject> getErrorObjectsConstants() throws IllegalAccessException {
		Field[] oAuth2ErrorFields = OAuth2Error.class.getDeclaredFields();
		Set<ErrorObject> errorObjectConstants = new HashSet<>();
		for (Field field : oAuth2ErrorFields) {
			if (field.getType().equals(ErrorObject.class)) {
				errorObjectConstants.add((ErrorObject) field.get(this));
			}
		}
		return errorObjectConstants;
	}
}
