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

package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;


public class AuthenticationErrorResponseTest extends TestCase {
	
	
	public void testStandardErrors() {
		
		Set<ErrorObject> stdErrors = AuthenticationErrorResponse.getStandardErrors();
		
		assertTrue(stdErrors.contains(OIDCError.INTERACTION_REQUIRED));
		assertTrue(stdErrors.contains(OIDCError.LOGIN_REQUIRED));
		assertTrue(stdErrors.contains(OIDCError.ACCOUNT_SELECTION_REQUIRED));
		assertTrue(stdErrors.contains(OIDCError.CONSENT_REQUIRED));
		assertTrue(stdErrors.contains(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS));
		assertTrue(stdErrors.contains(OIDCError.REGISTRATION_NOT_SUPPORTED));
		
		int numAuthzResponseErrors = AuthorizationErrorResponse.getStandardErrors().size();
		
		assertEquals(6, AuthenticationErrorResponse.getStandardErrors().size() - numAuthzResponseErrors);
	}


	public void testCodeErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State();

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			redirectURI, error, state, ResponseMode.QUERY);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(ResponseMode.QUERY, response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
		assertEquals(state, response.getState());
		assertNull(response.getIssuer());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("\\?");
		assertEquals(redirectURI.toString(), parts[0]);

		assertNotNull(responseURI.getQuery());
		assertNull(responseURI.getFragment());

		response = AuthenticationErrorResponse.parse(responseURI);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(state, response.getState());
		assertNull(response.getIssuer());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}


	public void testCodeErrorResponse_withIssuer()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State();
		Issuer issuer = new Issuer("https://login.c2id.com");

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			redirectURI, error, state, issuer, ResponseMode.QUERY);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(ResponseMode.QUERY, response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
		assertEquals(state, response.getState());
		assertEquals(issuer, response.getIssuer());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("\\?");
		assertEquals(redirectURI.toString(), parts[0]);

		assertNotNull(responseURI.getQuery());
		assertNull(responseURI.getFragment());

		response = AuthenticationErrorResponse.parse(responseURI);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(state, response.getState());
		assertEquals(issuer, response.getIssuer());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}


	public void testIDTokenErrorResponse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State();

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			redirectURI, error, state, ResponseMode.FRAGMENT);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(ResponseMode.FRAGMENT, response.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
		assertEquals(state, response.getState());
		assertNull(response.getIssuer());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(redirectURI.toString(), parts[0]);

		assertNull(responseURI.getQuery());
		assertNotNull(responseURI.getFragment());

		response = AuthenticationErrorResponse.parse(responseURI);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(state, response.getState());
		assertNull(response.getIssuer());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}
	
	
	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140
	public void testRedirectionURIWithQueryString() {
		
		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertEquals("action=oidccallback", redirectURI.getQuery());

		State state = new State();

		ErrorObject error = OAuth2Error.ACCESS_DENIED;

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(redirectURI, error, state, ResponseMode.QUERY);

		Map<String,List<String>> params = response.toParameters();
		assertEquals(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getCode()), params.get("error"));
		assertEquals(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getDescription()), params.get("error_description"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(3, params.size());

		URI uri = response.toURI();

		params = URLUtils.parseParameters(uri.getQuery());
		assertEquals(Collections.singletonList("oidccallback"), params.get("action"));
		assertEquals(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getCode()), params.get("error"));
		assertEquals(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getDescription()), params.get("error_description"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(4, params.size());
	}


	public void testParse_httpRequest() throws Exception {

		AuthenticationErrorResponse response = new AuthenticationErrorResponse(
			URI.create("https://example.com/cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			ResponseMode.FORM_POST
		);

		HTTPRequest httpRequest = response.toHTTPRequest();

		AuthenticationErrorResponse parsedResponse = AuthenticationErrorResponse.parse(httpRequest);

		assertEquals(response.getRedirectionURI(), parsedResponse.getRedirectionURI());
		assertEquals(OAuth2Error.ACCESS_DENIED, parsedResponse.getErrorObject());
		assertEquals(response.getState(), parsedResponse.getState());
		assertNull(parsedResponse.getIssuer());
		assertNull(parsedResponse.getResponseMode());
	}
}
