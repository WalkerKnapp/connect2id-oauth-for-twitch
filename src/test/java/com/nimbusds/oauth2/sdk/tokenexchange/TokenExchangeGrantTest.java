package com.nimbusds.oauth2.sdk.tokenexchange;


import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessToken;


public class TokenExchangeGrantTest extends TestCase {
	
	
	public void testConstructor_minimal()
		throws ParseException {
		
		TypelessToken subjectToken = new TypelessToken("subjectToken");
		TokenTypeURI subjectTokenType = TokenTypeURI.ACCESS_TOKEN;
		
		TokenExchangeGrant grant = new TokenExchangeGrant(subjectToken, subjectTokenType);
		
		assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
		assertEquals(subjectToken, grant.getSubjectToken());
		assertEquals(subjectTokenType, grant.getSubjectTokenType());
		assertNull(grant.getActorToken());
		assertNull(grant.getActorTokenType());
		assertNull(grant.getRequestedTokenType());
		assertNull(grant.getAudience());
		
		Map<String, List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList(TokenExchangeGrant.GRANT_TYPE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("subjectToken"), params.get("subject_token"));
		assertEquals(Collections.singletonList(subjectTokenType.getURI().toString()), params.get("subject_token_type"));
		assertEquals(3, params.size());
		
		grant = TokenExchangeGrant.parse(params);
		assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
		assertEquals(subjectToken, grant.getSubjectToken());
		assertEquals(subjectTokenType, grant.getSubjectTokenType());
		assertNull(grant.getActorToken());
		assertNull(grant.getActorTokenType());
		assertNull(grant.getRequestedTokenType());
		assertNull(grant.getAudience());
		
		assertEquals(grant, TokenExchangeGrant.parse(params));
	}
	
	
	public void testConstructor_allSet()
		throws ParseException {
		
		TypelessToken subjectToken = new TypelessToken("subjectToken");
		TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
		TypelessToken actorToken = new TypelessToken("actorToken");
		TokenTypeURI actorTokenType = TokenTypeURI.parse("actorTokenType");
		TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
		List<Audience> audience = new Audience("audience").toSingleAudienceList();
		
		TokenExchangeGrant grant = new TokenExchangeGrant(subjectToken, subjectTokenType, actorToken, actorTokenType, requestedTokenType, audience);
		
		assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
		assertEquals(subjectToken, grant.getSubjectToken());
		assertEquals(subjectTokenType, grant.getSubjectTokenType());
		assertEquals(actorToken, grant.getActorToken());
		assertEquals(actorTokenType, grant.getActorTokenType());
		assertEquals(requestedTokenType, grant.getRequestedTokenType());
		assertEquals(audience, grant.getAudience());
		
		Map<String, List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList("urn:ietf:params:oauth:grant-type:token-exchange"), params.get("grant_type"));
		assertEquals(Collections.singletonList("subjectToken"), params.get("subject_token"));
		assertEquals(Collections.singletonList("subjectTokenType"), params.get("subject_token_type"));
		assertEquals(Collections.singletonList("actorToken"), params.get("actor_token"));
		assertEquals(Collections.singletonList("actorTokenType"), params.get("actor_token_type"));
		assertEquals(Collections.singletonList("requestedTokenType"), params.get("requested_token_type"));
		assertEquals(Collections.singletonList("audience"), params.get("audience"));
		assertEquals(7, params.size());
		
		grant = TokenExchangeGrant.parse(params);
		assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
		assertEquals(subjectToken, grant.getSubjectToken());
		assertEquals(subjectTokenType, grant.getSubjectTokenType());
		assertEquals(actorToken, grant.getActorToken());
		assertEquals(actorTokenType, grant.getActorTokenType());
		assertEquals(requestedTokenType, grant.getRequestedTokenType());
		assertEquals(audience, grant.getAudience());
		
		assertEquals(grant, TokenExchangeGrant.parse(params));
	}
	
	
	public void testConstructor_requireSubjectToken() {
		
		try {
			new TokenExchangeGrant(null, null, null, null, null, null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			assertEquals("The subject token must not be null", e.getMessage());
		}
	}
	
	
	public void testConstructor_requireActorTokenTypeWithActorToken()
		throws ParseException {
		
		TypelessToken subjectToken = new TypelessToken("subjectToken");
		TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
		TypelessToken actorToken = new TypelessToken("actorToken");
		
		try {
			new TokenExchangeGrant(subjectToken, subjectTokenType, actorToken, null, null, null);
			fail();
		} catch (Exception e) {
			assertTrue(e instanceof IllegalArgumentException);
			assertEquals("If an actor token is specified the actor token type must not be null", e.getMessage());
		}
	}
	
	
	public void testToParametersWithOptionalActorTokenAndActorTokenType()
		throws ParseException {
		
		TypelessToken subjectToken = new TypelessToken("subjectToken");
		TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
		TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
		List<Audience> audience = new Audience("audience").toSingleAudienceList();
		
		TokenExchangeGrant grant = new TokenExchangeGrant(subjectToken, subjectTokenType, null, null, requestedTokenType, audience);
		
		Map<String, List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList("urn:ietf:params:oauth:grant-type:token-exchange"), params.get("grant_type"));
		assertEquals(Collections.singletonList("subjectToken"), params.get("subject_token"));
		assertEquals(Collections.singletonList("subjectTokenType"), params.get("subject_token_type"));
		assertEquals(Collections.singletonList("requestedTokenType"), params.get("requested_token_type"));
		assertEquals(Audience.toStringList(audience), params.get("audience"));
		assertEquals(5, params.size());
	}
	
	
	public void testParse()
		throws ParseException {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
		params.put("subject_token", Collections.singletonList("subjectToken"));
		params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
		params.put("actor_token", Collections.singletonList("actorToken"));
		params.put("actor_token_type", Collections.singletonList("actorTokenType"));
		params.put("requested_token_type", Collections.singletonList("requestedTokenType"));
		params.put("audience", Collections.singletonList("audience"));
		
		TokenExchangeGrant grant = TokenExchangeGrant.parse(params);
		
		assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
		assertEquals("subjectToken", grant.getSubjectToken().getValue());
		assertEquals("subjectTokenType", grant.getSubjectTokenType().getURI().toString());
		assertEquals("actorToken", grant.getActorToken().getValue());
		assertEquals("actorTokenType", grant.getActorTokenType().getURI().toString());
		assertEquals("requestedTokenType", grant.getRequestedTokenType().getURI().toString());
		assertEquals(Collections.singletonList("audience"), Audience.toStringList(grant.getAudience()));
	}
	
	
	public void testParse_missingGrantType() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", null);
		params.put("subject_token", Collections.singletonList("subjectToken"));
		params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
		
		try {
			TokenExchangeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing grant_type parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}
	
	
	public void testParse_unsupportedGrant() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("no-such-grant"));
		params.put("subject_token", Collections.singletonList("subjectToken"));
		params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
		
		try {
			TokenExchangeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), e.getErrorObject().getCode());
			assertEquals("Unsupported grant type: The grant_type must be urn:ietf:params:oauth:grant-type:token-exchange", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}
	
	
	public void testParse_missingSubjectToken() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
		params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
		
		try {
			TokenExchangeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty subject_token parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}
	
	
	public void testParse_missingSubjectTokenType() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
		params.put("subject_token", Collections.singletonList("subjectToken"));
		
		try {
			TokenExchangeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty subject_token_type parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}
	
	
	public void testParse_withoutActorTokenAndActorTokenType()
		throws Exception {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()));
		params.put("subject_token", Collections.singletonList("subjectToken"));
		params.put("subject_token_type", Collections.singletonList("subjectTokenType"));
		
		TokenExchangeGrant grant = TokenExchangeGrant.parse(params);
		assertEquals(GrantType.TOKEN_EXCHANGE, grant.getType());
		assertEquals("subjectToken", grant.getSubjectToken().getValue());
		assertEquals("subjectTokenType", grant.getSubjectTokenType().getURI().toString());
		assertNull("actorToken", grant.getActorToken());
		assertNull("actorTokenType", grant.getActorTokenType());
	}
	
	
	public void testEquality()
		throws ParseException, URISyntaxException {
		
		TypelessToken subjectToken = new TypelessToken("subjectToken");
		TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
		TypelessToken actorToken = new TypelessToken("actorToken");
		TokenTypeURI actorTokenType = TokenTypeURI.parse("actorTokenType");
		TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
		List<Audience> audience = new Audience("audience").toSingleAudienceList();
		
		TokenExchangeGrant grant1 = new TokenExchangeGrant(subjectToken, subjectTokenType, actorToken, actorTokenType, requestedTokenType, audience);
		
		TokenExchangeGrant grant2 = new TokenExchangeGrant(subjectToken, subjectTokenType, actorToken, actorTokenType, requestedTokenType, audience);
		
		assertEquals(grant1, grant2);
	}
	
	
	public void testInequality() throws ParseException, URISyntaxException {
		
		TypelessToken subjectToken = new TypelessToken("subjectToken");
		TokenTypeURI subjectTokenType = TokenTypeURI.parse("subjectTokenType");
		TypelessToken actorToken = new TypelessToken("actorToken");
		TokenTypeURI actorTokenType = TokenTypeURI.parse("actorTokenType");
		TokenTypeURI anotherActorTokenType = TokenTypeURI.parse("anotherActorTokenType");
		TokenTypeURI requestedTokenType = TokenTypeURI.parse("requestedTokenType");
		List<Audience> audience = new Audience("audience").toSingleAudienceList();
		
		TokenExchangeGrant grant1 = new TokenExchangeGrant(subjectToken, subjectTokenType, actorToken, actorTokenType, requestedTokenType, audience);
		
		TokenExchangeGrant grant2 = new TokenExchangeGrant(subjectToken, subjectTokenType, actorToken, anotherActorTokenType, requestedTokenType, audience);
		
		assertFalse(grant1.equals(grant2));
	}
}