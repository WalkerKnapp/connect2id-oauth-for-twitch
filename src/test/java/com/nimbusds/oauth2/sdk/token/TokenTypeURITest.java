package com.nimbusds.oauth2.sdk.token;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;


public class TokenTypeURITest extends TestCase {
	
	
	public void testConstants() {
		
		assertEquals(URI.create("urn:ietf:params:oauth:token-type:access_token"), TokenTypeURI.ACCESS_TOKEN.getURI());
		assertEquals(URI.create("urn:ietf:params:oauth:token-type:refresh_token"), TokenTypeURI.REFRESH_TOKEN.getURI());
		assertEquals(URI.create("urn:ietf:params:oauth:token-type:id_token"), TokenTypeURI.ID_TOKEN.getURI());
		assertEquals(URI.create("urn:ietf:params:oauth:token-type:saml1"), TokenTypeURI.SAML1.getURI());
		assertEquals(URI.create("urn:ietf:params:oauth:token-type:saml2"), TokenTypeURI.SAML2.getURI());
		assertEquals(URI.create("urn:ietf:params:oauth:token-type:jwt"), TokenTypeURI.JWT.getURI());
		assertEquals(URI.create("urn:openid:params:token-type:device-secret"), TokenTypeURI.DEVICE_SECRET.getURI());
	}
	
	
	public void testToString() {
		
		assertEquals("urn:ietf:params:oauth:token-type:access_token", TokenTypeURI.ACCESS_TOKEN.toString());
	}
	
	
	public void testParseKnownUri() throws ParseException {
		
		TokenTypeURI tokenTypeURI1 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:access_token");
		TokenTypeURI tokenTypeURI2 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:access_token");
		
		assertEquals(tokenTypeURI1, tokenTypeURI2);
		assertEquals(tokenTypeURI1.hashCode(), tokenTypeURI2.hashCode());
	}
	
	
	public void testParseUnknownUri() throws ParseException {
		
		TokenTypeURI tokenTypeURI1 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:unknown_token");
		TokenTypeURI tokenTypeURI2 = TokenTypeURI.parse("urn:ietf:params:oauth:token-type:unknown_token");
		
		assertEquals(tokenTypeURI1, tokenTypeURI2);
		assertEquals(tokenTypeURI1.hashCode(), tokenTypeURI2.hashCode());
	}
	
	
	public void testParseNullUri() {
		try {
			TokenTypeURI.parse(null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			assertEquals("The URI value must not be null", e.getMessage());
		}
	}
	
	
	public void testParseIllegalUri() {
		try {
			TokenTypeURI.parse("a b");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal token type URI: a b", e.getMessage());
		}
	}
}