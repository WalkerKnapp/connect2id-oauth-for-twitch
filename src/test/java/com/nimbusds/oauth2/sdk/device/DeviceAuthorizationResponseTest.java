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

package com.nimbusds.oauth2.sdk.device;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

public class DeviceAuthorizationResponseTest extends TestCase {

	public void testRegisteredParameters() {

		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("device_code"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("user_code"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()
		                .contains("verification_uri"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames()
		                .contains("verification_uri_complete"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("expires_in"));
		assertTrue(DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().contains("interval"));
		assertEquals(6, DeviceAuthorizationSuccessResponse.getRegisteredParameterNames().size());
	}


	public void testMinimalSuccess() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		long lifetime = 1800;

		DeviceAuthorizationSuccessResponse resp = new DeviceAuthorizationSuccessResponse(deviceCode, userCode,
		                verificationUri, lifetime);

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(lifetime, resp.getLifetime());

		assertEquals(null, resp.getVerificationUriComplete());
		assertEquals(5, resp.getInterval());

		assertTrue(resp.getCustomParameters().isEmpty());

		HTTPResponse httpResp = resp.toHTTPResponse();
		JSONObject params = httpResp.getContentAsJSONObject();
		assertEquals(deviceCode.getValue(), params.get("device_code"));
		assertEquals(userCode.getValue(), params.get("user_code"));
		assertEquals(verificationUri.toString(), params.get("verification_uri"));
		assertFalse(params.containsKey("verification_uri_complete"));
		assertEquals(lifetime, JSONObjectUtils.getLong(params, "expires_in"));
		assertEquals(5L, JSONObjectUtils.getLong(params,"interval"));
		assertEquals(5, params.size());

		resp = DeviceAuthorizationResponse.parse(httpResp).toSuccessResponse();

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(lifetime, resp.getLifetime());

		assertEquals(null, resp.getVerificationUriComplete());
		assertEquals(5, resp.getInterval());

		assertTrue(resp.getCustomParameters().isEmpty());
	}


	public void testFull() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		URI verificationUriComplete = new URI("https://c2id.com/devauthz/complete");
		long lifetime = 3600;
		long interval = 10;

		Map<String, Object> customParams = new HashMap<>();
		customParams.put("x", "100");
		customParams.put("y", "200");
		customParams.put("z", "300");

		DeviceAuthorizationSuccessResponse resp = new DeviceAuthorizationSuccessResponse(deviceCode, userCode,
		                verificationUri, verificationUriComplete, lifetime, interval, customParams);

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(verificationUriComplete, resp.getVerificationUriComplete());
		assertEquals(lifetime, resp.getLifetime());
		assertEquals(interval, resp.getInterval());
		assertEquals("100", resp.getCustomParameters().get("x"));
		assertEquals("200", resp.getCustomParameters().get("y"));
		assertEquals("300", resp.getCustomParameters().get("z"));
		assertEquals(3, resp.getCustomParameters().size());

		HTTPResponse httpResp = resp.toHTTPResponse();
		JSONObject params = httpResp.getContentAsJSONObject();
		assertEquals(deviceCode.getValue(), params.get("device_code"));
		assertEquals(userCode.getValue(), params.get("user_code"));
		assertEquals(verificationUri.toString(), params.get("verification_uri"));
		assertEquals(verificationUriComplete.toString(), params.get("verification_uri_complete"));
		assertEquals(lifetime, params.get("expires_in"));
		assertEquals(interval, params.get("interval"));
		assertEquals("100", params.get("x"));
		assertEquals("200", params.get("y"));
		assertEquals("300", params.get("z"));
		assertEquals(9, params.size());

		resp = DeviceAuthorizationResponse.parse(httpResp).toSuccessResponse();

		assertEquals(deviceCode, resp.getDeviceCode());
		assertEquals(userCode, resp.getUserCode());
		assertEquals(verificationUri, resp.getVerificationUri());
		assertEquals(verificationUriComplete, resp.getVerificationUriComplete());
		assertEquals(lifetime, resp.getLifetime());
		assertEquals(interval, resp.getInterval());
		assertEquals("100", resp.getCustomParameters().get("x"));
		assertEquals("200", resp.getCustomParameters().get("y"));
		assertEquals("300", resp.getCustomParameters().get("z"));
		assertEquals(3, resp.getCustomParameters().size());
	}


	public void testConstructParseExceptionMissingDeviceCode() throws Exception {

		DeviceCode deviceCode = null;
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		long lifetime = 3600;

		try {
			new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}

		JSONObject o = new JSONObject();
		o.put("user_code", userCode.getValue());
		o.put("verification_uri", verificationUri.toString());
		o.put("expires_in", lifetime);

		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		httpResponse.setBody(o.toString());

		try {
			DeviceAuthorizationSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key device_code", e.getMessage());
		}
	}


	public void testConstructParseExceptionMissingUserCode() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = null;
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		long lifetime = 3600;

		try {
			new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}

		JSONObject o = new JSONObject();
		o.put("device_code", deviceCode.getValue());
		o.put("verification_uri", verificationUri.toString());
		o.put("expires_in", lifetime);

		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		httpResponse.setBody(o.toString());

		try {
			DeviceAuthorizationSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key user_code", e.getMessage());
		}
	}


	public void testConstructParseExceptionMissingVerificationUri() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = null;
		long lifetime = 3600;

		try {
			new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}

		JSONObject o = new JSONObject();
		o.put("device_code", deviceCode.getValue());
		o.put("user_code", userCode.getValue());
		o.put("expires_in", lifetime);

		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		httpResponse.setBody(o.toString());

		try {
			DeviceAuthorizationSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key verification_uri", e.getMessage());
		}
	}


	public void testConstructExceptionLifetime0() throws Exception {

		DeviceCode deviceCode = new DeviceCode();
		UserCode userCode = new UserCode();
		URI verificationUri = new URI("https://c2id.com/devauthz/");
		long lifetime = 0;

		try {
			new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationUri, lifetime);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The lifetime must be greater than 0", e.getMessage());
		}
	}


	public void testToErrorResponse() throws Exception {

		DeviceAuthorizationErrorResponse response = new DeviceAuthorizationErrorResponse(
		                DeviceAuthorizationGrantError.AUTHORIZATION_PENDING);

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = DeviceAuthorizationResponse.parse(httpResponse).toErrorResponse();

		assertEquals(DeviceAuthorizationGrantError.AUTHORIZATION_PENDING, response.getErrorObject());
	}
}
