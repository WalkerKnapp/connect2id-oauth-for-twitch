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

package com.nimbusds.oauth2.sdk.token;


import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;


public class DPoPTokenErrorTest extends TestCase {


	public void testConstants() {

		assertNull(DPoPTokenError.MISSING_TOKEN.getCode());
		assertNull(DPoPTokenError.MISSING_TOKEN.getDescription());
		assertEquals(401, DPoPTokenError.MISSING_TOKEN.getHTTPStatusCode());
		assertNull(DPoPTokenError.MISSING_TOKEN.getJWSAlgorithms());
		
		assertEquals("invalid_request", DPoPTokenError.INVALID_REQUEST.getCode());
		assertEquals("Invalid request", DPoPTokenError.INVALID_REQUEST.getDescription());
		assertEquals(400, DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
		
		assertEquals("invalid_token", DPoPTokenError.INVALID_TOKEN.getCode());
		assertEquals("Invalid access token", DPoPTokenError.INVALID_TOKEN.getDescription());
		assertEquals(401, DPoPTokenError.INVALID_TOKEN.getHTTPStatusCode());
		
		assertEquals("insufficient_scope", DPoPTokenError.INSUFFICIENT_SCOPE.getCode());
		assertEquals("Insufficient scope", DPoPTokenError.INSUFFICIENT_SCOPE.getDescription());
		assertEquals(403, DPoPTokenError.INSUFFICIENT_SCOPE.getHTTPStatusCode());
		
		assertEquals("invalid_dpop_proof", DPoPTokenError.INVALID_DPOP_PROOF.getCode());
		assertEquals("Invalid DPoP proof", DPoPTokenError.INVALID_DPOP_PROOF.getDescription());
		assertEquals(401, DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
		
		assertEquals("use_dpop_nonce", DPoPTokenError.USE_DPOP_NONCE.getCode());
		assertEquals("Use of DPoP nonce required", DPoPTokenError.USE_DPOP_NONCE.getDescription());
		assertEquals(401, DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
	}
	
	
	public void testMinimalConstructor()
		throws ParseException {
		
		String code = "invalid_request";
		String description = "Invalid request";
		DPoPTokenError error = new DPoPTokenError(code, description);
		assertEquals(AccessTokenType.DPOP, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		assertNull(error.getJWSAlgorithms());
		
		String wwwHeader = error.toWWWAuthenticateHeader();
		assertEquals("DPoP error=\"invalid_request\", error_description=\"Invalid request\"", wwwHeader);
		
		error = DPoPTokenError.parse(wwwHeader);
		
		assertEquals(AccessTokenType.DPOP, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		assertNull(error.getJWSAlgorithms());
	}
	
	
	public void testPartConstructor()
		throws ParseException {
		
		String code = "invalid_request";
		String description = "Invalid request";
		int statusCode = 400;
		DPoPTokenError error = new DPoPTokenError(code, description, statusCode);
		assertEquals(AccessTokenType.DPOP, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		assertNull(error.getJWSAlgorithms());
		
		String wwwHeader = error.toWWWAuthenticateHeader();
		assertEquals("DPoP error=\"invalid_request\", error_description=\"Invalid request\"", wwwHeader);
		
		error = DPoPTokenError.parse(wwwHeader);
		assertEquals(AccessTokenType.DPOP, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		assertNull(error.getJWSAlgorithms());
	}
	
	
	public void testFullConstructor()
		throws ParseException {
		
		String code = "invalid_request";
		String description = "Invalid request";
		int statusCode = 400;
		URI uri = URI.create("https://c2id.com/errors/invalid_request");
		String realm = "c2id.com";
		Scope scope = new Scope("read", "write");
		Set<JWSAlgorithm> jwsAlgs = new HashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.ES256));
		DPoPTokenError error = new DPoPTokenError(code, description, statusCode, uri, realm, scope, jwsAlgs);
		assertEquals(AccessTokenType.DPOP, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertEquals(uri, error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
		assertEquals(realm, error.getRealm());
		assertEquals(scope, error.getScope());
		assertEquals(jwsAlgs, error.getJWSAlgorithms());
		
		String wwwHeader = error.toWWWAuthenticateHeader();
		assertEquals("DPoP realm=\"c2id.com\", error=\"invalid_request\", error_description=\"Invalid request\", error_uri=\"https://c2id.com/errors/invalid_request\", scope=\"read write\", algs=\"ES256 RS256\"", wwwHeader);
		
		error = DPoPTokenError.parse(wwwHeader);
		
		assertEquals(AccessTokenType.DPOP, error.getScheme());
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertEquals(uri, error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		assertEquals(realm, error.getRealm());
		assertEquals(scope, error.getScope());
		assertEquals(jwsAlgs, error.getJWSAlgorithms());
	}


	public void testSerializeAndParseWWWAuthHeader()
		throws Exception {

		DPoPTokenError error = DPoPTokenError.INVALID_TOKEN.setRealm("example.com");

		assertEquals("example.com", error.getRealm());
		assertEquals("invalid_token", error.getCode());

		String wwwAuth = error.toWWWAuthenticateHeader();

		error = DPoPTokenError.parse(wwwAuth);

		assertEquals("example.com", error.getRealm());
		assertEquals("invalid_token", error.getCode());
	}


	public void testNullRealm() {

		DPoPTokenError error = DPoPTokenError.INVALID_REQUEST.setRealm(null);

		assertNull(error.getRealm());
	}


	public void testNoErrorCode()
		throws Exception {

		String wwwAuth = "DPoP realm=\"example.com\"";

		DPoPTokenError error = DPoPTokenError.parse(wwwAuth);

		assertEquals(error, DPoPTokenError.MISSING_TOKEN);

		assertEquals("example.com", error.getRealm());
		assertNull(error.getCode());
	}


	public void testEmptyRealm()
		throws Exception {

		String wwwAuth = "DPoP realm=\"\"";

		DPoPTokenError error = DPoPTokenError.parse(wwwAuth);

		assertEquals(error, DPoPTokenError.MISSING_TOKEN);

		assertEquals("", error.getRealm());
		assertNull(error.getCode());
	}


	public void testBlankRealm()
		throws Exception {

		String wwwAuth = "DPoP realm=\" \"";

		DPoPTokenError error = DPoPTokenError.parse(wwwAuth);

		assertEquals(error, DPoPTokenError.MISSING_TOKEN);

		assertEquals(" ", error.getRealm());
		assertNull(error.getCode());
	}


	public void testRealmAtCharLimit256()
		throws Exception {

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 256; i++) {
			sb.append('x');
		}
		
		String wwwAuth = "DPoP realm=\"" + sb + "\"";

		DPoPTokenError error = DPoPTokenError.parse(wwwAuth);

		assertEquals(error, DPoPTokenError.MISSING_TOKEN);

		assertEquals(sb.toString(), error.getRealm());
		assertNull(error.getCode());
	}


	public void testRealmBeyondCharLimit256()
		throws Exception {

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 256 + 1; i++) {
			sb.append('x');
		}
		
		String wwwAuth = "DPoP realm=\"" + sb + "\"";

		DPoPTokenError error = DPoPTokenError.parse(wwwAuth);

		assertEquals(error, DPoPTokenError.MISSING_TOKEN);
		assertNull("Too long, not parsed", error.getRealm());
		assertNull(error.getCode());
	}


	public void testInsufficientScope()
		throws Exception {

		DPoPTokenError error = DPoPTokenError.INSUFFICIENT_SCOPE;
		error = error.setScope(Scope.parse("offline_access"));

		String wwwAuth = error.toWWWAuthenticateHeader();

		error = DPoPTokenError.parse(wwwAuth);

		assertEquals(Scope.parse("offline_access"), error.getScope());
	}


	public void testSetDescription() {

		assertEquals("description", DPoPTokenError.INSUFFICIENT_SCOPE.setDescription("description").getDescription());
	}


	public void testAppendDescription() {

		assertEquals("Insufficient scope: offline_access", DPoPTokenError.INSUFFICIENT_SCOPE.appendDescription(": offline_access").getDescription());
	}


	public void testSetHTTPStatusCode() {

		assertEquals(400, DPoPTokenError.INSUFFICIENT_SCOPE.setHTTPStatusCode(400).getHTTPStatusCode());
	}


	public void testSetURI()
		throws Exception {

		URI uri = new URI("https://example.com");

		assertEquals(uri, DPoPTokenError.INSUFFICIENT_SCOPE.setURI(uri).getURI());
	}
	
	
	public void testSetJWSAlgorithms() {
		
		Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.ES256));
		
		assertEquals(jwsAlgorithms, DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(jwsAlgorithms).getJWSAlgorithms());
	}
	
	
	public void testSetJWSAlgorithms_null() {
		
		assertNull(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(null).getJWSAlgorithms());
	}


	public void testParseInvalidTokenHeader()
		throws Exception {

		String header = "DPoP error=\"invalid_token\", error_description=\"Invalid access token\"";

		DPoPTokenError error = DPoPTokenError.parse(header);

		assertEquals(DPoPTokenError.INVALID_TOKEN, error);
		assertEquals("Invalid access token", error.getDescription());
		assertNull(error.getURI());
		assertNull(error.getRealm());
	}
	
	
	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/197/userinfo-error-response-by-google-not
	public void testParseGoogleDPoPTokenError()
		throws Exception {
		
		String header = "DPoP realm=\"https://acounts.google.com/\", error=invalid_token";
		
		DPoPTokenError error = DPoPTokenError.parse(header);
		assertEquals(DPoPTokenError.INVALID_TOKEN, error);
		assertEquals("invalid_token", error.getCode());
		assertNull(error.getDescription());
		assertNull(error.getURI());
		assertEquals("https://acounts.google.com/", error.getRealm());
	}
	
	
	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/197/userinfo-error-response-by-google-not
	public void testParseGoogleDPoPTokenError_extended()
		throws Exception {
		
		String header = "DPoP realm=\"https://acounts.google.com/\", error=invalid_token, error_description=\"Invalid access token\"";
		
		DPoPTokenError error = DPoPTokenError.parse(header);
		assertEquals(DPoPTokenError.INVALID_TOKEN, error);
		assertEquals("invalid_token", error.getCode());
		assertEquals("Invalid access token", error.getDescription());
		assertNull(error.getURI());
		assertEquals("https://acounts.google.com/", error.getRealm());
	}
	
	
	public void testRealmWithEscapeDoubleQuotes()
		throws Exception {
		
		DPoPTokenError error = DPoPTokenError.INVALID_TOKEN.setRealm("\"my-realm\"");
		
		assertEquals("\"my-realm\"", error.getRealm());
		
		String wwwAuthHeader = error.toWWWAuthenticateHeader();
		
		assertEquals("DPoP realm=\"\\\"my-realm\\\"\", error=\"invalid_token\", error_description=\"Invalid access token\"", wwwAuthHeader);
		
		DPoPTokenError parsed = DPoPTokenError.parse(wwwAuthHeader);
		
		assertEquals(error.getRealm(), parsed.getRealm());
	}
	
	
	public void testInvalidCharsInErrorCode() {
		
		try {
			new DPoPTokenError("\"invalid_token\"", null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Illegal char(s) in code, see RFC 6749, section 5.2", e.getMessage());
		}
	}
	
	
	public void testInvalidCharsInErrorDescription() {
		
		try {
			new DPoPTokenError("invalid_token", "Invalid token: \"abc\"");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Illegal char(s) in description, see RFC 6749, section 5.2", e.getMessage());
		}
	}
	
	
	public void testInvalidCharsInScope() {
		
		try {
			DPoPTokenError.INSUFFICIENT_SCOPE.setScope(new Scope("read", "\"write\""));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The scope contains illegal characters, see RFC 6750, section 3", e.getMessage());
		}
	}
	
	
	public void testParseWWWAuthenticateHeader_invalidCharsInErrorCode()
		throws ParseException {
		
		// skip invalid error code
		assertNull(DPoPTokenError.parse("DPoP error=\"\"invalid token\"").getCode());
	}
	
	
	public void testIgnoreParseInvalidErrorURI()
		throws ParseException {
		
		DPoPTokenError error = DPoPTokenError.parse("DPoP error=invalid_token, error_uri=\"a b c\"");
		
		assertEquals(DPoPTokenError.INVALID_TOKEN.getCode(), error.getCode());
		assertNull(error.getURI());
	}
	
	
	// Test lenient parsing with comma after DPoP
	//  https://tools.ietf.org/html/rfc6750#section-3.1
	public void testParseWithCommaAfterBearer() throws ParseException {
		
		DPoPTokenError error = DPoPTokenError.parse("DPoP, error=\"invalid_token\", error_description=\"The Token was expired\"");
		assertEquals("invalid_token", error.getCode());
		assertEquals("The Token was expired", error.getDescription());
		assertNull(error.getRealm());
		assertNull(error.getScope());
		assertEquals("HTTP status code not known", 0, error.getHTTPStatusCode()); // Not known
	}
	
	
	public void testParse_emptyAlgs() throws ParseException {
		
		DPoPTokenError error = DPoPTokenError.parse("DPoP algs=\"\"");
		assertNull(error.getJWSAlgorithms());
	}
	
	
	public void testParse_oneAlg() throws ParseException {
		
		DPoPTokenError error = DPoPTokenError.parse("DPoP algs=\"RS256\"");
		assertEquals(Collections.singleton(JWSAlgorithm.RS256), error.getJWSAlgorithms());
	}
	
	
	public void testParse_twoAlgs() throws ParseException {
		
		DPoPTokenError error = DPoPTokenError.parse("DPoP algs=\"RS256 ES256\"");
		assertEquals(new HashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.ES256)), error.getJWSAlgorithms());
	}
	
	
	public void testRFCExample() throws ParseException {
		
		String wwwHeader = "DPoP error=\"invalid_token\", error_description=\"Invalid DPoP key binding\", algs=\"ES256\"";
		
		DPoPTokenError error = DPoPTokenError.parse(wwwHeader);
		assertNull(error.getRealm());
		assertEquals(DPoPTokenError.INVALID_TOKEN.getCode(), error.getCode());
		assertEquals("Invalid DPoP key binding", error.getDescription());
		assertEquals(Collections.singleton(JWSAlgorithm.ES256), error.getJWSAlgorithms());
	}
	
	
	public void testRFCExampleAlgs() throws ParseException {
		
		String wwwHeader = "DPoP algs=\"ES256 PS256\"";
		
		DPoPTokenError error = DPoPTokenError.parse(wwwHeader);
		assertNull(error.getRealm());
		assertNull(error.getCode());
		assertEquals(new HashSet<>(Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.PS256)), error.getJWSAlgorithms());
	}
	
	
	public void testParseRFCExampleAlgsDeprecated() throws ParseException {
		
		String wwwHeader = "DPoP realm=\"WallyWorld\", algs=\"ES256 PS256\"";
		
		DPoPTokenError error = DPoPTokenError.parse(wwwHeader);
		assertEquals("WallyWorld", error.getRealm());
		assertNull(error.getCode());
		assertEquals(new HashSet<>(Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.PS256)), error.getJWSAlgorithms());
	}
	
	
	public void testParseRFCExampleWithNonce() throws ParseException {
		
		String wwwHeader = "DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\"";
		
		DPoPTokenError error = DPoPTokenError.parse(wwwHeader);
		assertNull(error.getRealm());
		assertEquals(DPoPTokenError.USE_DPOP_NONCE, error);
		assertEquals(DPoPTokenError.USE_DPOP_NONCE.getCode(), error.getCode());
		assertEquals("Resource server requires nonce in DPoP proof", error.getDescription());
		assertNull(error.getJWSAlgorithms());
	}
}
