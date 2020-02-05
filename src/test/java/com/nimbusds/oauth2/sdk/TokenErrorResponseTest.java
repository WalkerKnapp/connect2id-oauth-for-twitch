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
import java.util.Set;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests token error response serialisation and parsing.
 */
public class TokenErrorResponseTest extends TestCase {
	
	
	private static URI ERROR_PAGE_URI = null;
	
	
	@Override
	public void setUp()
		throws Exception {
		
		super.setUp();
		
		ERROR_PAGE_URI = new URI("http://server.example.com/error/123");
	}


	public void testStandardErrors() {
	
		Set<ErrorObject> errors = TokenErrorResponse.getStandardErrors();
	
		assertTrue(errors.contains(OAuth2Error.INVALID_REQUEST));
		assertTrue(errors.contains(OAuth2Error.INVALID_CLIENT));
		assertTrue(errors.contains(OAuth2Error.INVALID_GRANT));
		assertTrue(errors.contains(OAuth2Error.UNAUTHORIZED_CLIENT));
		assertTrue(errors.contains(OAuth2Error.UNSUPPORTED_GRANT_TYPE));
		assertTrue(errors.contains(OAuth2Error.INVALID_SCOPE));
		
		assertEquals(6, errors.size());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
	
		ErrorObject err = OAuth2Error.INVALID_REQUEST.setURI(ERROR_PAGE_URI);

		TokenErrorResponse r = new TokenErrorResponse(err);

		assertFalse(r.indicatesSuccess());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
		

		HTTPResponse httpResponse = r.toHTTPResponse();
		
		assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		
		
		JSONObject jsonObject = JSONObjectUtils.parse(httpResponse.getContent());

		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), (String)jsonObject.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), (String)jsonObject.get("error_description"));
		assertEquals(ERROR_PAGE_URI.toString(), (String)jsonObject.get("error_uri"));
		assertEquals(3, jsonObject.size());
		
		
		r = TokenErrorResponse.parse(httpResponse);

		assertFalse(r.indicatesSuccess());
		assertEquals(OAuth2Error.INVALID_REQUEST, r.getErrorObject());
	}


	public void testParseEmpty()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(404);

		TokenErrorResponse errorResponse = TokenErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(404, errorResponse.getErrorObject().getHTTPStatusCode());
		assertNull(errorResponse.getErrorObject().getCode());
		assertNull(errorResponse.getErrorObject().getDescription());
		assertNull(errorResponse.getErrorObject().getURI());
	}


	public void testParseInvalidClient()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(401);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setContent("{\"error\":\"invalid_client\", \"error_description\":\"Client authentication failed\"}");

		TokenErrorResponse errorResponse = TokenErrorResponse.parse(httpResponse);

		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorResponse.getErrorObject().getCode());
		assertEquals("Client authentication failed", errorResponse.getErrorObject().getDescription());
	}


	public void testTokenErrorWithoutObject()
		throws Exception {

		TokenErrorResponse errorResponse = new TokenErrorResponse();
		assertFalse(errorResponse.indicatesSuccess());
		assertNull(errorResponse.getErrorObject());
		assertTrue(errorResponse.toJSONObject().isEmpty());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertNull(httpResponse.getEntityContentType());
		assertNull(httpResponse.getContent());

		errorResponse = TokenErrorResponse.parse(httpResponse);
		assertFalse(errorResponse.indicatesSuccess());
		assertEquals(400, errorResponse.getErrorObject().getHTTPStatusCode());
		assertNull(errorResponse.getErrorObject().getCode());
		assertNull(errorResponse.getErrorObject().getDescription());
		assertNull(errorResponse.getErrorObject().getURI());
		assertEquals("{\"error\":null}", errorResponse.toJSONObject().toJSONString()); // TODO
	}
}
