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


import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;


public class AuthorizationErrorResponseTest extends TestCase {
	
	
	private static URI REDIRECT_URI = null;
	
	
	private static URI ERROR_PAGE_URL = null;
	
	
	public void setUp()
		throws URISyntaxException {
		
		REDIRECT_URI = new URI("https://client.example.com/cb");
		
		ERROR_PAGE_URL = new URI("http://server.example.com/error/123");
	}


	public void testStandardErrors() {
	
		Set<ErrorObject> errors = AuthorizationErrorResponse.getStandardErrors();
	
		assertTrue(errors.contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(errors.contains(OAuth2Error.UNAUTHORIZED_CLIENT));
		assertTrue(errors.contains(OAuth2Error.ACCESS_DENIED));
		assertTrue(errors.contains(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
		assertTrue(errors.contains(OAuth2Error.INVALID_SCOPE));
		assertTrue(errors.contains(OAuth2Error.SERVER_ERROR));
		assertTrue(errors.contains(OAuth2Error.TEMPORARILY_UNAVAILABLE));
		
		assertEquals(7, errors.size());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
	
		State state = new State();
	
		AuthorizationErrorResponse r = new AuthorizationErrorResponse(
			REDIRECT_URI,
			OAuth2Error.INVALID_REQUEST,
			state,
			ResponseMode.QUERY);

		assertFalse(r.indicatesSuccess());
		assertEquals(REDIRECT_URI, r.getRedirectionURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertEquals(ResponseMode.QUERY, r.getResponseMode());
		assertEquals(ResponseMode.QUERY, r.impliedResponseMode());

		assertEquals(state, r.getState());
		
		assertNull(r.getIssuer());

		Map<String,List<String>> params = r.toParameters();
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getCode()), params.get("error"));
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getDescription()), params.get("error_description"));
		assertNull(params.get("error_uri"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(3, params.size());

		URI location = r.toURI();
			
//		System.out.println(location.toString());
		assertNull(location.getFragment());
		assertNotNull(location.getQuery());
			
		assertEquals(REDIRECT_URI.getScheme(), location.getScheme());
		assertEquals(REDIRECT_URI.getPort(), location.getPort());
		assertEquals(REDIRECT_URI.getHost(), location.getHost());
		assertEquals(REDIRECT_URI.getPath(), location.getPath());
			
		params = URLUtils.parseParameters(location.getQuery());
			
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getCode()), params.get("error"));
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getDescription()), params.get("error_description"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(3, params.size());
			
		HTTPResponse httpResponse = r.toHTTPResponse();
			
		assertEquals(HTTPResponse.SC_FOUND, httpResponse.getStatusCode());
		assertEquals(location, httpResponse.getLocation());

		r = AuthorizationErrorResponse.parse(httpResponse);

		assertFalse(r.indicatesSuccess());
		assertEquals(REDIRECT_URI, r.getRedirectionURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertNull(r.getResponseMode());
		assertEquals(ResponseMode.QUERY, r.impliedResponseMode()); // default
		assertEquals(state, r.getState());
		assertNull(r.getIssuer());
	}
	
	
	public void testSerializeAndParse_withIssuer()
		throws ParseException {
		
		Issuer issuer = new Issuer("https://openid.c2id.com");
		
		State state = new State();
		
		AuthorizationErrorResponse r = new AuthorizationErrorResponse(
			REDIRECT_URI,
			OAuth2Error.INVALID_REQUEST,
			state,
			issuer,
			ResponseMode.QUERY);
		
		assertFalse(r.indicatesSuccess());
		assertEquals(REDIRECT_URI, r.getRedirectionURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertEquals(ResponseMode.QUERY, r.getResponseMode());
		assertEquals(ResponseMode.QUERY, r.impliedResponseMode());
		
		assertEquals(state, r.getState());
		
		assertEquals(issuer, r.getIssuer());
		
		Map<String,List<String>> params = r.toParameters();
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getCode()), params.get("error"));
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getDescription()), params.get("error_description"));
		assertNull(params.get("error_uri"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(Collections.singletonList(issuer.getValue()), params.get("iss"));
		assertEquals(4, params.size());
		
		URI location = r.toURI();
		
		assertNull(location.getFragment());
		assertNotNull(location.getQuery());
		
		assertEquals(REDIRECT_URI.getScheme(), location.getScheme());
		assertEquals(REDIRECT_URI.getPort(), location.getPort());
		assertEquals(REDIRECT_URI.getHost(), location.getHost());
		assertEquals(REDIRECT_URI.getPath(), location.getPath());
		
		params = URLUtils.parseParameters(location.getQuery());
		
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getCode()), params.get("error"));
		assertEquals(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getDescription()), params.get("error_description"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(Collections.singletonList(issuer.getValue()), params.get("iss"));
		assertEquals(4, params.size());
		
		HTTPResponse httpResponse = r.toHTTPResponse();
		
		assertEquals(HTTPResponse.SC_FOUND, httpResponse.getStatusCode());
		assertEquals(location, httpResponse.getLocation());
		
		r = AuthorizationErrorResponse.parse(httpResponse);
		
		assertFalse(r.indicatesSuccess());
		assertEquals(REDIRECT_URI, r.getRedirectionURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertNull(r.getResponseMode());
		assertEquals(ResponseMode.QUERY, r.impliedResponseMode()); // default
		assertEquals(state, r.getState());
		assertEquals(issuer, r.getIssuer());
	}
	
	
	public void testParse_emptyIssuer()
		throws URISyntaxException, ParseException {
		
		State state = new State();
		
		URI uri = new AuthorizationErrorResponse(
			REDIRECT_URI,
			OAuth2Error.INVALID_REQUEST,
			state,
			ResponseMode.QUERY)
			.toURI();
		
		uri = new URI(uri.toString() + "&iss=");
		
		AuthorizationErrorResponse errorResponse = AuthorizationErrorResponse.parse(uri);
		assertEquals(REDIRECT_URI, errorResponse.getRedirectionURI());
		assertEquals(OAuth2Error.INVALID_REQUEST, errorResponse.getErrorObject());
		assertEquals(state, errorResponse.getState());
		assertNull(errorResponse.getIssuer());
	}


	public void testCodeErrorInQueryString()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State();

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			redirectURI, error, state, ResponseMode.QUERY);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(ResponseMode.QUERY, response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
		assertEquals(state, response.getState());

		URI responseURI = response.toURI();

		assertNotNull(responseURI.getQuery());
		assertNull(responseURI.getFragment());

		response = AuthorizationErrorResponse.parse(responseURI);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode()); // default
		assertEquals(state, response.getState());
	}


	public void testErrorInFragment()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State();

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			redirectURI, error, state, ResponseMode.FRAGMENT);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertEquals(ResponseMode.FRAGMENT, response.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
		assertEquals(state, response.getState());

		URI responseURI = response.toURI();

		assertNull(responseURI.getQuery());
		assertNotNull(responseURI.getFragment());

		response = AuthorizationErrorResponse.parse(responseURI);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(error, response.getErrorObject());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode()); // default
		assertEquals(state, response.getState());
	}
	
	
	public void testParse()
		throws URISyntaxException {
	
		String s = "https://client.example.com/cb?error=invalid_request&error_description=Invalid+request&error_uri=http%3A%2F%2Fserver.example.com%2Ferror%2F123&state=123";

		AuthorizationErrorResponse r = null;
		
		try {
			r = AuthorizationErrorResponse.parse(new URI(s));
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}

		assertFalse(r.indicatesSuccess());
		assertEquals("https://client.example.com/cb", r.getRedirectionURI().toString());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		assertEquals(ERROR_PAGE_URL, r.getErrorObject().getURI());
		assertEquals(new State("123"), r.getState());
		
		assertNull(r.getResponseMode());
		assertEquals(ResponseMode.QUERY, r.impliedResponseMode());
	}
	
	
	public void testParse_errorDescriptionWithIllegalChars()
		throws ParseException {
		
		String errorDescription = "\"Invalid request\"";
		
		String s = "https://client.example.com/cb?error=invalid_request&error_description=" + URLEncoder.encode(errorDescription) + "&state=123";

		AuthorizationErrorResponse r = AuthorizationErrorResponse.parse(URI.create(s));

		assertFalse(r.indicatesSuccess());
		assertEquals("https://client.example.com/cb", r.getRedirectionURI().toString());
		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), r.getErrorObject().getCode());
		assertEquals(ErrorObject.removeIllegalChars(errorDescription), r.getErrorObject().getDescription());
		assertNull(r.getErrorObject().getURI());
		assertEquals(new State("123"), r.getState());
		
		assertNull(r.getResponseMode());
		assertEquals(ResponseMode.QUERY, r.impliedResponseMode());
	}
	
	
	public void testParseExceptions()
		throws URISyntaxException {
		
		String s1 = "https://client.example.com/cb";
		
		try {
			AuthorizationErrorResponse.parse(new URI(s1));
			fail();
			
		} catch (ParseException e) {
			// ok
		}
	}


	public void testRedirectionURIWithQueryString() {
		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140

		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertEquals("action=oidccallback", redirectURI.getQuery());

		State state = new State();

		ErrorObject error = OAuth2Error.ACCESS_DENIED;

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(redirectURI, error, state, ResponseMode.QUERY);

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
}
