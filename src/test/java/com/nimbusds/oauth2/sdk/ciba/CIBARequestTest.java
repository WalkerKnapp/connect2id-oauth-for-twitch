package com.nimbusds.oauth2.sdk.ciba;


import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;


public class CIBARequestTest extends TestCase {
	
	private static final URI ENDPOINT_URI = URI.create("https://c2id.com/ciba/");
	
	private static final URL ENDPOINT_URL;
	
	private static final ClientAuthentication CLIENT_AUTH = new ClientSecretBasic(new ClientID("123"), new Secret());
	
	private static final Scope SCOPE = new Scope("openid");
	
	private static final BearerAccessToken CLIENT_NOTIFICATION_TOKEN = new BearerAccessToken("iexi7ahziT1eiCei2eengei6lai3meeg");
	
	private static final List<ACR> ACR_VALUES = Collections.singletonList(new ACR("0"));
	
	private static final String LOGIN_HINT_TOKEN_STRING = "jue7zi8Fah6siem2Eengail1ue1chu9k";
	
	private static final SignedJWT ID_TOKEN;
	
	private static final String LOGIN_HINT = "alice@wonderland.net";
	
	private static final String BINDING_MESSAGE = "W4SCT";
	
	private static final Secret USER_CODE = new Secret("8364");
	
	private static final Integer REQUESTED_EXPIRY = 60;
	
	private static final OIDCClaimsRequest CLAIMS = new OIDCClaimsRequest()
		.withIDTokenClaimsRequest(new ClaimsSetRequest().add("email"));
	
	private static final List<LangTag> CLAIMS_LOCALES;
	
	private static final String PURPOSE = "Account holder verification";
	
	private static final List<URI> RESOURCES = Arrays.asList(URI.create("https://rs1.example.com"), URI.create("https://rs2.example.com"));
	
	static {
		try {
			CLAIMS_LOCALES = Arrays.asList(new LangTag("en"), new LangTag("bg"));
		} catch (LangTagException e) {
			throw new RuntimeException(e);
		}
	}
	
	private static final Map<String,List<String>> CUSTOM_PARAMS;
	
	static {
		try {
			ENDPOINT_URL = ENDPOINT_URI.toURL();
			
			RSAKey rsaJWK = new RSAKeyGenerator(2048)
				.keyID("1")
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			
			Issuer iss = new Issuer("https://c2id.com");
			ClientID clientID = new ClientID("123");
			Date now = new Date();
			
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10 * 60 * 1000L))
				.issueTime(now)
				.build();
			
			ID_TOKEN = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
			ID_TOKEN.sign(new RSASSASigner(rsaJWK));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("custom-xyz", Collections.singletonList("abc"));
		CUSTOM_PARAMS = Collections.unmodifiableMap(params);
	}
	
	
	private static BearerAccessToken generateExcessiveClientNotificationToken() {
		
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < CIBARequest.CLIENT_NOTIFICATION_TOKEN_MAX_LENGTH + 1; i++) {
			sb.append("A");
		}
		BearerAccessToken clientNotificationToken = new BearerAccessToken(sb.toString());
		
		assertEquals(1025, clientNotificationToken.getValue().length());
		
		return clientNotificationToken;
	}
	
	
	public void testConstants() {
		
		assertEquals(1024, CIBARequest.CLIENT_NOTIFICATION_TOKEN_MAX_LENGTH);
	}
	

	public void testConstructor_requiredOnly() throws java.text.ParseException {
		
		CIBARequest request = new CIBARequest(
			null,
			CLIENT_AUTH,
			null,
			null,
			null,
			null,
			null,
			LOGIN_HINT,
			null,
			null,
			null,
			null
		);
		
		assertNull(request.getEndpointURI());
		assertEquals(CLIENT_AUTH, request.getClientAuthentication());
		assertNull(request.getScope());
		assertNull(request.getClientNotificationToken());
		assertNull(request.getACRValues());
		assertEquals(CIBAHintType.LOGIN_HINT, request.getHintType());
		assertNull(request.getLoginHintTokenString());
		assertNull(request.getIDTokenHint());
		assertEquals(LOGIN_HINT, request.getLoginHint());
		assertNull(request.getUserCode());
		assertNull(request.getRequestedExpiry());
		assertNull(request.getOIDCClaims());
		assertTrue(request.getCustomParameters().isEmpty());
		assertNull(request.getCustomParameter("no-such-param"));
		assertFalse(request.isSigned());
		assertNull(request.getRequestJWT());
		
		try {
			request.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			assertEquals("The endpoint URI is not specified", e.getMessage());
		}
		
		JWTClaimsSet jwtClaimsSet = request.toJWTClaimsSet();
		assertEquals(LOGIN_HINT, jwtClaimsSet.getStringClaim("login_hint"));
		assertEquals(1, jwtClaimsSet.getClaims().size());
	}
	

	public void testConstructor_allSet() throws MalformedURLException, ParseException {
		
		for (CIBAHintType hintBy: CIBAHintType.values()) {
			CIBARequest request = new CIBARequest(
				ENDPOINT_URI,
				CLIENT_AUTH,
				SCOPE,
				CLIENT_NOTIFICATION_TOKEN,
				ACR_VALUES,
				CIBAHintType.LOGIN_HINT_TOKEN.equals(hintBy) ? LOGIN_HINT_TOKEN_STRING : null,
				CIBAHintType.ID_TOKEN_HINT.equals(hintBy) ? ID_TOKEN : null,
				CIBAHintType.LOGIN_HINT.equals(hintBy) ? LOGIN_HINT : null,
				BINDING_MESSAGE,
				USER_CODE,
				REQUESTED_EXPIRY,
				CLAIMS,
				CLAIMS_LOCALES,
				PURPOSE,
				RESOURCES,
				CUSTOM_PARAMS
			);
			
			assertEquals(ENDPOINT_URI, request.getEndpointURI());
			assertEquals(CLIENT_AUTH, request.getClientAuthentication());
			assertEquals(SCOPE, request.getScope());
			assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
			assertEquals(ACR_VALUES, request.getACRValues());
			assertEquals(hintBy, request.getHintType());
			if (CIBAHintType.LOGIN_HINT_TOKEN.equals(hintBy)) {
				assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
			} else {
				assertNull(request.getLoginHintTokenString());
			}
			if (CIBAHintType.ID_TOKEN_HINT.equals(hintBy)) {
				assertEquals(ID_TOKEN, request.getIDTokenHint());
			} else {
				assertNull(request.getIDTokenHint());
			}
			if (CIBAHintType.LOGIN_HINT.equals(hintBy)) {
				assertEquals(LOGIN_HINT, request.getLoginHint());
			} else {
				assertNull(request.getLoginHint());
			}
			assertEquals(BINDING_MESSAGE, request.getBindingMessage());
			assertEquals(USER_CODE, request.getUserCode());
			assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
			assertEquals(CLAIMS, request.getOIDCClaims());
			assertEquals(CLAIMS_LOCALES, request.getClaimsLocales());
			assertEquals(PURPOSE, request.getPurpose());
			assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
			assertFalse(request.isSigned());
			assertNull(request.getRequestJWT());
			
			HTTPRequest httpRequest = request.toHTTPRequest();
			assertEquals(ENDPOINT_URI.toURL(), httpRequest.getURL());
			assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
			assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
			
			assertEquals(((ClientSecretBasic) CLIENT_AUTH).toHTTPAuthorizationHeader(), ClientSecretBasic.parse(httpRequest).toHTTPAuthorizationHeader());
			
			assertEquals(2, httpRequest.getHeaderMap().size());
			
			assertEquals(request.toParameters(), httpRequest.getQueryParameters());
			
			request = CIBARequest.parse(httpRequest);
			
			assertEquals(ENDPOINT_URI, request.getEndpointURI());
			assertEquals(((ClientSecretBasic) CLIENT_AUTH).toHTTPAuthorizationHeader(), ((ClientSecretBasic) request.getClientAuthentication()).toHTTPAuthorizationHeader());
			assertEquals(SCOPE, request.getScope());
			assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
			assertEquals(ACR_VALUES, request.getACRValues());
			if (CIBAHintType.LOGIN_HINT_TOKEN.equals(hintBy)) {
				assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
			} else {
				assertNull(request.getLoginHintTokenString());
			}
			if (CIBAHintType.ID_TOKEN_HINT.equals(hintBy)) {
				assertEquals(ID_TOKEN.serialize(), request.getIDTokenHint().getParsedString());
			}
			if (CIBAHintType.LOGIN_HINT.equals(hintBy)) {
				assertEquals(LOGIN_HINT, request.getLoginHint());
			} else {
				assertNull(request.getLoginHint());
			}
			assertEquals(BINDING_MESSAGE, request.getBindingMessage());
			assertEquals(USER_CODE, request.getUserCode());
			assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
			assertEquals(CLAIMS.toJSONObject(), request.getOIDCClaims().toJSONObject());
			assertEquals(CLAIMS_LOCALES, request.getClaimsLocales());
			assertEquals(PURPOSE, request.getPurpose());
			assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
			assertFalse(request.isSigned());
			assertNull(request.getRequestJWT());
			
			JWTClaimsSet jwtClaimsSet = request.toJWTClaimsSet();
			Map<String, List<String>> params = request.toParameters();
			for (Map.Entry<String, Object> en : jwtClaimsSet.getClaims().entrySet()) {
				if (en.getKey().equals("resource")) {
					assertEquals(en.getValue(), params.get(en.getKey()));
				} else {
					assertEquals(Collections.singletonList((String) en.getValue()), params.get(en.getKey()));
				}
			}
			assertEquals(params.size(), jwtClaimsSet.getClaims().size());
		}
	}
	
	
	public void testBuilders() {
		
		// Regular
		for (CIBAHintType hintBy: CIBAHintType.values()) {
			CIBARequest request = new CIBARequest.Builder(CLIENT_AUTH, SCOPE)
				.endpointURI(ENDPOINT_URI)
				.clientNotificationToken(CLIENT_NOTIFICATION_TOKEN)
				.acrValues(ACR_VALUES)
				.loginHintTokenString(CIBAHintType.LOGIN_HINT_TOKEN.equals(hintBy) ? LOGIN_HINT_TOKEN_STRING : null)
				.idTokenHint(CIBAHintType.ID_TOKEN_HINT.equals(hintBy) ? ID_TOKEN : null)
				.loginHint(CIBAHintType.LOGIN_HINT.equals(hintBy) ? LOGIN_HINT : null)
				.bindingMessage(BINDING_MESSAGE)
				.userCode(USER_CODE)
				.requestedExpiry(REQUESTED_EXPIRY)
				.claims(CLAIMS)
				.claimsLocales(CLAIMS_LOCALES)
				.purpose(PURPOSE)
				.resource(RESOURCES.get(0))
				.customParameter("custom-xyz", "abc")
				.build();
			
			assertEquals(ENDPOINT_URI, request.getEndpointURI());
			assertEquals(CLIENT_AUTH, request.getClientAuthentication());
			assertEquals(SCOPE, request.getScope());
			assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
			assertEquals(ACR_VALUES, request.getACRValues());
			assertEquals(hintBy, request.getHintType());
			if (CIBAHintType.LOGIN_HINT_TOKEN.equals(hintBy)) {
				assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
			} else {
				assertNull(request.getLoginHintTokenString());
			}
			if (CIBAHintType.ID_TOKEN_HINT.equals(hintBy)) {
				assertEquals(ID_TOKEN, request.getIDTokenHint());
			} else {
				assertNull(request.getIDTokenHint());
			}
			if (CIBAHintType.LOGIN_HINT.equals(hintBy)) {
				assertEquals(LOGIN_HINT, request.getLoginHint());
			} else {
				assertNull(request.getLoginHint());
			}
			assertEquals(BINDING_MESSAGE, request.getBindingMessage());
			assertEquals(USER_CODE, request.getUserCode());
			assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
			assertEquals(CLAIMS, request.getOIDCClaims());
			assertEquals(CLAIMS_LOCALES, request.getClaimsLocales());
			assertEquals(PURPOSE, request.getPurpose());
			assertEquals(Collections.singletonList(RESOURCES.get(0)), request.getResources());
			assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
			
			// Copy
			request = new CIBARequest.Builder(request)
				.build();
			
			assertEquals(ENDPOINT_URI, request.getEndpointURI());
			assertEquals(CLIENT_AUTH, request.getClientAuthentication());
			assertEquals(SCOPE, request.getScope());
			assertEquals(CLIENT_NOTIFICATION_TOKEN, request.getClientNotificationToken());
			assertEquals(ACR_VALUES, request.getACRValues());
			if (CIBAHintType.LOGIN_HINT_TOKEN.equals(hintBy)) {
				assertEquals(LOGIN_HINT_TOKEN_STRING, request.getLoginHintTokenString());
			} else {
				assertNull(request.getLoginHintTokenString());
			}
			if (CIBAHintType.ID_TOKEN_HINT.equals(hintBy)) {
				assertEquals(ID_TOKEN, request.getIDTokenHint());
			} else {
				assertNull(request.getIDTokenHint());
			}
			if (CIBAHintType.LOGIN_HINT.equals(hintBy)) {
				assertEquals(LOGIN_HINT, request.getLoginHint());
			} else {
				assertNull(request.getLoginHint());
			}
			assertEquals(BINDING_MESSAGE, request.getBindingMessage());
			assertEquals(USER_CODE, request.getUserCode());
			assertEquals(REQUESTED_EXPIRY, request.getRequestedExpiry());
			assertEquals(CLAIMS, request.getOIDCClaims());
			assertEquals(CLAIMS_LOCALES, request.getClaimsLocales());
			assertEquals(PURPOSE, request.getPurpose());
			assertEquals(CUSTOM_PARAMS, request.getCustomParameters());
		}
	}
	
	
	public void testSignedRequest()
		throws JOSEException, ParseException {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.algorithm(JWSAlgorithm.RS256)
			.generate();
		
		CIBARequest plainRequest = new CIBARequest.Builder(CLIENT_AUTH, SCOPE)
			.clientNotificationToken(CLIENT_NOTIFICATION_TOKEN)
			.loginHint(LOGIN_HINT)
			.bindingMessage(BINDING_MESSAGE)
			.build();
		
		Issuer iss = new Issuer(new ClientID());
		Audience aud = new Audience("https://c2id.com");
		Date now = new Date();
		long nowTs = now.getTime() / 1000;
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTs);
		Date nbf = DateUtils.fromSecondsSinceEpoch(nowTs);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTs + 600);
		JWTID jti = new JWTID();
		
		CIBASignedRequestClaimsSet claimsSet = new CIBASignedRequestClaimsSet(
			plainRequest,
			iss,
			aud,
			iat,
			nbf,
			exp,
			jti);
		
		SignedJWT requestJWT = new SignedJWT(
			new JWSHeader((JWSAlgorithm) rsaJWK.getAlgorithm()),
			claimsSet.toJWTClaimsSet());
		requestJWT.sign(new RSASSASigner(rsaJWK));
		
		CIBARequest signedRequest = new CIBARequest.Builder(CLIENT_AUTH, requestJWT)
			.endpointURI(ENDPOINT_URI)
			.build();
		
		assertTrue(signedRequest.isSigned());
		assertEquals(requestJWT, signedRequest.getRequestJWT());
		
		HTTPRequest httpRequest = signedRequest.toHTTPRequest();
		assertEquals(ENDPOINT_URI, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(((ClientSecretBasic)CLIENT_AUTH).toHTTPAuthorizationHeader(), httpRequest.getAuthorization());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(requestJWT.serialize()), params.get("request"));
		assertEquals(1, params.size());
		
		signedRequest = CIBARequest.parse(httpRequest);
		
		assertTrue(signedRequest.isSigned());
		assertEquals(requestJWT.serialize(), signedRequest.getRequestJWT().getParsedString());
	}
	
	
	public void testConstructor_rejectExcessiveClientNotificationToken() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				generateExcessiveClientNotificationToken(),
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The client notification token must not exceed 1024 chars", exception.getMessage());
	}
	
	
	public void testConstructor_rejectMissingIdentityHint() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				0,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("One user identity hist must be provided (login_hint_token, id_token_hint or login_hint)", exception.getMessage());
	}
	
	
	public void testConstructor_rejectMoreThanOneIdentityHint() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				LOGIN_HINT_TOKEN_STRING,
				ID_TOKEN,
				null,
				null,
				null,
				0,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("One user identity hist must be provided (login_hint_token, id_token_hint or login_hint)", exception.getMessage());
		
		exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				null,
				ID_TOKEN,
				LOGIN_HINT,
				null,
				null,
				0,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("One user identity hist must be provided (login_hint_token, id_token_hint or login_hint)", exception.getMessage());
		
		exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				LOGIN_HINT_TOKEN_STRING,
				null,
				LOGIN_HINT,
				null,
				null,
				0,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("One user identity hist must be provided (login_hint_token, id_token_hint or login_hint)", exception.getMessage());
		
		exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				LOGIN_HINT_TOKEN_STRING,
				ID_TOKEN,
				LOGIN_HINT,
				null,
				null,
				0,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("One user identity hist must be provided (login_hint_token, id_token_hint or login_hint)", exception.getMessage());
	}
	
	
	public void testConstructor_rejectZeroExpiry() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				null,
				null,
				LOGIN_HINT,
				null,
				null,
				0,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The requested expiry must be a positive integer", exception.getMessage());
	}
	
	
	public void testConstructor_rejectNegativeExpiry() {
		
		IllegalArgumentException exception = null;
		try {
			new CIBARequest(
				null,
				CLIENT_AUTH,
				SCOPE,
				null,
				null,
				null,
				null,
				LOGIN_HINT,
				null,
				null,
				0,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The requested expiry must be a positive integer", exception.getMessage());
	}
	
	
	public void testParse_expectPOST() {
		
		try {
			CIBARequest.parse(new HTTPRequest(HTTPRequest.Method.PUT, ENDPOINT_URL));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParse_expectContentTypeURLEncoded() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
		
		httpRequest.setEntityContentType(ContentType.TEXT_PLAIN);
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/x-www-form-urlencoded, received text/plain", e.getMessage());
		}
	}
	
	
	public void testParse_idTokenHintNotJWT() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("scope=openid&id_token_hint=cheTh0ae");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid id_token_hint parameter: Invalid JWT serialization: Missing dot delimiter(s)", e.getMessage());
		}
	}
	
	
	public void testParse_rejectExpiryString() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("scope=openid&requested_expiry=abc");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The requested_expiry parameter must be an integer", e.getMessage());
		}
	}
	
	
	public void testParse_rejectNegativeExpiry()
		throws UnsupportedEncodingException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("scope=openid&login_hint=" + URLEncoder.encode(LOGIN_HINT, StandardCharsets.UTF_8.name()) + "&requested_expiry=-1");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The requested expiry must be a positive integer", e.getMessage());
		}
	}
	
	
	public void testParse_rejectZeroExpiry()
		throws UnsupportedEncodingException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("scope=openid&login_hint=" + URLEncoder.encode(LOGIN_HINT, StandardCharsets.UTF_8.name()) + "&requested_expiry=-1");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The requested expiry must be a positive integer", e.getMessage());
		}
	}
	
	
	public void testParse_rejectExcessiveClientNotificationToken() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		CLIENT_AUTH.applyTo(httpRequest);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("scope=openid&client_notification_token=" + generateExcessiveClientNotificationToken().getValue());
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The client notification token must not exceed 1024 chars", e.getMessage());
		}
	}
	
	
	public void testParse_rejectIfAuthMissing() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT_URL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("scope=openid");
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required client authentication", e.getMessage());
		}
	}
	
	
	public void testRoundTrip_privateKeyJWTClientAuthentication() throws JOSEException, ParseException {
		
		RSAKey clientKey = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.generate();
		
		ClientAuthentication clientAuth = new PrivateKeyJWT(
			new ClientID("123"),
			ENDPOINT_URI,
			(JWSAlgorithm) clientKey.getAlgorithm(),
			clientKey.toRSAPrivateKey(),
			clientKey.getKeyID(),
			null);
			
		
		CIBARequest request = new CIBARequest.Builder(clientAuth, new Scope("openid"))
			.endpointURI(ENDPOINT_URI)
			.loginHint("alice")
			.build();
		assertTrue(request.getCustomParameters().isEmpty());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		Map<String,List<String>> formParams = httpRequest.getQueryParameters();
		assertNotNull(formParams.get("client_assertion_type"));
		assertNotNull(formParams.get("client_assertion"));
		assertNotNull(formParams.get("scope"));
		assertNotNull(formParams.get("login_hint"));
		assertEquals(4, formParams.size());
		
		request = CIBARequest.parse(httpRequest);
		
		assertEquals(new Scope("openid"), request.getScope());
		assertEquals("alice", request.getLoginHint());
		assertTrue(request.getCustomParameters().isEmpty());
	}
	
	
	public void testWithNullScopeParameter() throws ParseException {
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			(Scope) null)
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.claims(CLAIMS)
			.build();
		
		assertNull(request.getScope());
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(2, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		request = CIBARequest.parse(httpRequest);
		
		assertNull(request.getScope());
		
		params = request.toParameters();
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(2, params.size());
	}
	
	
	public void testWithEmptyScopeParameter() throws ParseException {
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			new Scope())
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.claims(CLAIMS)
			.build();
		
		assertEquals(new Scope(), request.getScope());
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(2, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		request = CIBARequest.parse(httpRequest);
		
		assertNull(request.getScope());
		
		params = request.toParameters();
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(2, params.size());
	}
	
	
	public void testWithClaimsParameter() throws ParseException {
		
		assertEquals("{\"id_token\":{\"email\":null}}", CLAIMS.toJSONString());
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			SCOPE)
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.claims(CLAIMS)
			.build();
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(3, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		request = CIBARequest.parse(httpRequest);
		
		assertEquals(CLAIMS.toJSONObject(), request.getOIDCClaims().toJSONObject());
		
		params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(3, params.size());
	}
	
	
	public void testWithClaimsAndLocalesParameters() throws ParseException {
		
		assertEquals("{\"id_token\":{\"email\":null}}", CLAIMS.toJSONString());
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			SCOPE)
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.claims(CLAIMS)
			.claimsLocales(CLAIMS_LOCALES)
			.build();
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(Collections.singletonList(LangTagUtils.concat(CLAIMS_LOCALES)), params.get("claims_locales"));
		assertEquals(4, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		request = CIBARequest.parse(httpRequest);
		
		assertEquals(CLAIMS.toJSONObject(), request.getOIDCClaims().toJSONObject());
		
		params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(CLAIMS.toJSONString()), params.get("claims"));
		assertEquals(Collections.singletonList(LangTagUtils.concat(CLAIMS_LOCALES)), params.get("claims_locales"));
		assertEquals(4, params.size());
	}
	
	
	public void testWithPurposeParameter() throws ParseException {
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			SCOPE)
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.purpose(PURPOSE)
			.build();
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(PURPOSE), params.get("purpose"));
		assertEquals(3, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		request = CIBARequest.parse(httpRequest);
		
		params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(PURPOSE), params.get("purpose"));
		assertEquals(3, params.size());
	}
	
	
	public void testWithResourceParameter() throws ParseException {
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			SCOPE)
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.resource(RESOURCES.get(0))
			.build();
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(RESOURCES.get(0).toString()), params.get("resource"));
		assertEquals(3, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		request = CIBARequest.parse(httpRequest);
		
		params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Collections.singletonList(RESOURCES.get(0).toString()), params.get("resource"));
		assertEquals(3, params.size());
	}
	
	
	public void testWithTwoResourceParameters() throws ParseException {
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			SCOPE)
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.resources(RESOURCES.get(0), RESOURCES.get(1))
			.build();
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Arrays.asList(RESOURCES.get(0).toString(), RESOURCES.get(1).toString()), params.get("resource"));
		assertEquals(3, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		request = CIBARequest.parse(httpRequest);
		
		params = request.toParameters();
		assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(LOGIN_HINT), params.get("login_hint"));
		assertEquals(Arrays.asList(RESOURCES.get(0).toString(), RESOURCES.get(1).toString()), params.get("resource"));
		assertEquals(3, params.size());
	}
	
	
	public void testParseWithIllegalResourceParameter() {
		
		CIBARequest request = new CIBARequest.Builder(
			CLIENT_AUTH,
			SCOPE)
			.endpointURI(ENDPOINT_URI)
			.loginHint(LOGIN_HINT)
			.build();
		
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		// Illegal resource
		Map<String,List<String>> params = request.toParameters();
		params.put("resource", Collections.singletonList("/api/v1"));
		httpRequest.setBody(URLUtils.serializeParameters(params));
		
		try {
			CIBARequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment", e.getMessage());
		}
	}
}
