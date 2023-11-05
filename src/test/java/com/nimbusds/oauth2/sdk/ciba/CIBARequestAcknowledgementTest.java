package com.nimbusds.oauth2.sdk.ciba;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class CIBARequestAcknowledgementTest extends TestCase {
	
	
	private static final AuthRequestID AUTH_REQUEST_ID = new AuthRequestID();
	
	
	public void testDefaultMinWaitIntervalConstant() {
		
		assertEquals(5, CIBARequestAcknowledgement.DEFAULT_MIN_WAIT_INTERVAL);
	}

	
	public void testLifeCycle_noMinWaitInterval() throws ParseException {
		
		int expiresIn = 10;
		
		CIBARequestAcknowledgement response = new CIBARequestAcknowledgement(
			AUTH_REQUEST_ID,
			expiresIn,
			null);

		assertTrue(response.indicatesSuccess());
		assertEquals(AUTH_REQUEST_ID, response.getAuthRequestID());
		assertEquals(expiresIn, response.getExpiresIn());
		assertNull(response.getMinWaitInterval());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON, httpResponse.getEntityContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		assertEquals(3, httpResponse.getHeaderMap().size());
		assertEquals(response.toJSONObject().toJSONString(), httpResponse.getContentAsJSONObject().toJSONString());
		
		response = CIBARequestAcknowledgement.parse(httpResponse);
		
		assertTrue(response.indicatesSuccess());
		assertEquals(AUTH_REQUEST_ID, response.getAuthRequestID());
		assertEquals(expiresIn, response.getExpiresIn());
		assertNull(response.getMinWaitInterval());
	}

	
	public void testLifeCycle_withMinWaitInterval() throws ParseException {
		
		int expiresIn = 10;
		
		CIBARequestAcknowledgement response = new CIBARequestAcknowledgement(
			AUTH_REQUEST_ID,
			expiresIn,
			5);

		assertTrue(response.indicatesSuccess());
		assertEquals(AUTH_REQUEST_ID, response.getAuthRequestID());
		assertEquals(expiresIn, response.getExpiresIn());
		assertEquals(5, response.getMinWaitInterval().intValue());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON, httpResponse.getEntityContentType());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());
		assertEquals(3, httpResponse.getHeaderMap().size());
		assertEquals(response.toJSONObject().toJSONString(), httpResponse.getContentAsJSONObject().toJSONString());
		
		response = CIBARequestAcknowledgement.parse(httpResponse);
		
		assertTrue(response.indicatesSuccess());
		assertEquals(AUTH_REQUEST_ID, response.getAuthRequestID());
		assertEquals(expiresIn, response.getExpiresIn());
		assertEquals(5, response.getMinWaitInterval().intValue());
	}
	
	
	public void testConstructor_rejectZeroMinWaitInterval() {
		
		IllegalArgumentException exception = null;
		
		try {
			new CIBARequestAcknowledgement(
				AUTH_REQUEST_ID,
				10,
				0);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		
		assertEquals("The interval must be a positive integer", exception.getMessage());
	}
	
	
	public void testConstructor_rejectNegativeMinWaitInterval() {
		
		IllegalArgumentException exception = null;
		
		try {
			new CIBARequestAcknowledgement(
				AUTH_REQUEST_ID,
				10,
				-1);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		
		assertEquals("The interval must be a positive integer", exception.getMessage());
	}
	
	
	public void testParse_not200() {
		
		try {
			CIBARequestAcknowledgement.parse(new HTTPResponse(400));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code 400, must be [200]", e.getMessage());
		}
	}
	
	
	public void testParse_missingContentType() {
		
		try {
			CIBARequestAcknowledgement.parse(new HTTPResponse(200));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testParse_unexpectedContentType() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		try {
			CIBARequestAcknowledgement.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json or have the +json suffix, received application/x-www-form-urlencoded", e.getMessage());
		}
	}
	
	
	public void testParse_entityNotJSONObject() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setContent("[]");
		
		try {
			CIBARequestAcknowledgement.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("The JSON entity is not an object", e.getMessage());
		}
	}
	
	
	public void testParse_missingAuthReqID() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("expires_in", 10);
		
		httpResponse.setContent(jsonObject.toJSONString());
		
		try {
			CIBARequestAcknowledgement.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key auth_req_id", e.getMessage());
		}
	}
	
	
	public void testParse_missingExpiresIn() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("auth_req_id", "eu9uuk3Ahjohden0ooPeifahghietai0");
		
		httpResponse.setContent(jsonObject.toJSONString());
		
		try {
			CIBARequestAcknowledgement.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key expires_in", e.getMessage());
		}
	}
	
	
	public void testParse_negativeInterval() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("auth_req_id", "eu9uuk3Ahjohden0ooPeifahghietai0");
		jsonObject.put("expires_in", 30);
		jsonObject.put("interval", -1);
		
		httpResponse.setContent(jsonObject.toJSONString());
		
		try {
			CIBARequestAcknowledgement.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("The interval parameter must be a positive integer", e.getMessage());
		}
	}
}