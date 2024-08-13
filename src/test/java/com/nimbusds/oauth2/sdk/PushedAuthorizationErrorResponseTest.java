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


import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import javax.naming.NoPermissionException;


public class PushedAuthorizationErrorResponseTest extends TestCase {
	
	
	public void testLifeCycle_withParams() throws ParseException {
		
		PushedAuthorizationErrorResponse response = new PushedAuthorizationErrorResponse(OAuth2Error.INVALID_REQUEST);
		assertEquals(OAuth2Error.INVALID_REQUEST, response.getErrorObject());
		assertFalse(response.indicatesSuccess());
		
		Map<String, Object> params = response.getErrorObject().toJSONObject();
		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), params.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), params.get("error_description"));
		assertEquals(2, params.size());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		params = httpResponse.getContentAsJSONObject();
		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), params.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), params.get("error_description"));
		assertEquals(2, params.size());
		
		response = PushedAuthorizationErrorResponse.parse(httpResponse);
		assertEquals(400, response.getErrorObject().getHTTPStatusCode());
		assertEquals(OAuth2Error.INVALID_REQUEST, response.getErrorObject());
		assertFalse(response.indicatesSuccess());
		
		params = response.getErrorObject().toJSONObject();
		assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), params.get("error"));
		assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), params.get("error_description"));
		assertEquals(2, params.size());
	}
	
	
	public void testLifeCycle_withCustomParams() throws ParseException {
		
		Map<String,String> customParams = new HashMap<>();
		customParams.put("client_auth_id", UUID.randomUUID().toString());
		
		ErrorObject errorObject = OAuth2Error.INVALID_CLIENT.setCustomParams(customParams);
		
		PushedAuthorizationErrorResponse response = new PushedAuthorizationErrorResponse(errorObject);
		assertEquals(errorObject, response.getErrorObject());
		assertFalse(response.indicatesSuccess());
		
		Map<String, Object> params = response.getErrorObject().toJSONObject();
		assertEquals(errorObject.getCode(), params.get("error"));
		assertEquals(errorObject.getDescription(), params.get("error_description"));
		assertEquals(customParams.get("client_auth_id"), params.get("client_auth_id"));
		assertEquals(3, params.size());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(401, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		params = httpResponse.getContentAsJSONObject();
		assertEquals(errorObject.getCode(), params.get("error"));
		assertEquals(errorObject.getDescription(), params.get("error_description"));
		assertEquals(customParams.get("client_auth_id"), params.get("client_auth_id"));
		assertEquals(3, params.size());
		
		response = PushedAuthorizationErrorResponse.parse(httpResponse);
		assertEquals(401, response.getErrorObject().getHTTPStatusCode());
		assertEquals(errorObject.getCode(), params.get("error"));
		assertEquals(errorObject.getDescription(), params.get("error_description"));
		assertEquals(customParams.get("client_auth_id"), params.get("client_auth_id"));
		assertEquals(3, params.size());
		assertFalse(response.indicatesSuccess());
		
		params = response.getErrorObject().toJSONObject();
		assertEquals(errorObject.getCode(), params.get("error"));
		assertEquals(errorObject.getDescription(), params.get("error_description"));
		assertEquals(customParams.get("client_auth_id"), params.get("client_auth_id"));
		assertEquals(3, params.size());
	}
	
	
	public void testLifeCycle_noParams() throws ParseException {
		
		PushedAuthorizationErrorResponse response = new PushedAuthorizationErrorResponse(new ErrorObject(null, null, 400));
		assertFalse(response.indicatesSuccess());
		assertTrue(response.getErrorObject().toParameters().isEmpty());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertNull(httpResponse.getEntityContentType());
		assertNull(httpResponse.getContent());
		
		response = PushedAuthorizationErrorResponse.parse(httpResponse);
		assertFalse(response.indicatesSuccess());
		assertEquals(400, response.getErrorObject().getHTTPStatusCode());
		assertTrue(response.getErrorObject().toParameters().isEmpty());
	}
	
	
	public void testRejectNullErrorObject() {
		
		try {
			new PushedAuthorizationErrorResponse(null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testParse_rejectStatusCodes201_200() {
	
		try {
			PushedAuthorizationErrorResponse.parse(new HTTPResponse(201));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP status code must be other than 201 and 200", e.getMessage());
		}
	
		try {
			PushedAuthorizationErrorResponse.parse(new HTTPResponse(200));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP status code must be other than 201 and 200", e.getMessage());
		}
	}
}
