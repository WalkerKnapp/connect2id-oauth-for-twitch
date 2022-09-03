package com.nimbusds.oauth2.sdk.dpop;


import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;


public class DPoPUtilsTest extends TestCase {
	
	
	static final JWTID JTI = new JWTID(96 / 8);
	
	
	static final String HTM = "POST";
	
	
	static final URI HTU = URI.create("https://c2id.com/token");
	
	
	static final Date IAT = DateUtils.fromSecondsSinceEpoch(3600);
	
	
	static final AccessToken ACCESS_TOKEN = new DPoPAccessToken("yie8voch8sae7Uroo4iejah8pohju8sh");
	
	
	static final Nonce NONCE = new Nonce();
	
	
	public void testComputeAccessTokenHash() throws JOSEException, NoSuchAlgorithmException {
		
		Base64URL hash = DPoPUtils.computeSHA256(ACCESS_TOKEN);
		
		assertEquals(256 / 8, hash.decode().length);
		
		byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(ACCESS_TOKEN.getValue().getBytes(StandardCharsets.UTF_8));
		assertEquals(hash, Base64URL.encode(hashBytes));
	}


	public void testCreateClaimsSet() throws ParseException, JOSEException {
		
		JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
			JTI,
			HTM,
			HTU,
			IAT,
			null,
			null
		);
		
		assertEquals(JTI.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(HTM, jwtClaimsSet.getStringClaim("htm"));
		assertEquals(HTU, jwtClaimsSet.getURIClaim("htu"));
		assertEquals(IAT, jwtClaimsSet.getIssueTime());
		
		assertEquals(4, jwtClaimsSet.getClaims().size());
	}


	public void testCreateClaimsSet_deprecated() throws ParseException, JOSEException {
		
		JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
			JTI,
			HTM,
			HTU,
			IAT,
			null
		);
		
		assertEquals(JTI.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(HTM, jwtClaimsSet.getStringClaim("htm"));
		assertEquals(HTU, jwtClaimsSet.getURIClaim("htu"));
		assertEquals(IAT, jwtClaimsSet.getIssueTime());
		
		assertEquals(4, jwtClaimsSet.getClaims().size());
	}


	public void testCreateClaimsSet_withAccessTokenHash() throws ParseException, JOSEException {
		
		JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
			JTI,
			HTM,
			HTU,
			IAT,
			ACCESS_TOKEN,
			null
		);
		
		assertEquals(JTI.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(HTM, jwtClaimsSet.getStringClaim("htm"));
		assertEquals(HTU, jwtClaimsSet.getURIClaim("htu"));
		assertEquals(IAT, jwtClaimsSet.getIssueTime());
		assertEquals(DPoPUtils.computeSHA256(ACCESS_TOKEN).toString(), jwtClaimsSet.getStringClaim("ath"));
		
		assertEquals(5, jwtClaimsSet.getClaims().size());
	}


	public void testCreateClaimsSet_withAccessTokenHash_withNonce() throws ParseException, JOSEException {
		
		JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
			JTI,
			HTM,
			HTU,
			IAT,
			ACCESS_TOKEN,
			NONCE
		);
		
		assertEquals(JTI.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(HTM, jwtClaimsSet.getStringClaim("htm"));
		assertEquals(HTU, jwtClaimsSet.getURIClaim("htu"));
		assertEquals(IAT, jwtClaimsSet.getIssueTime());
		assertEquals(DPoPUtils.computeSHA256(ACCESS_TOKEN).toString(), jwtClaimsSet.getStringClaim("ath"));
		assertEquals(NONCE.getValue(), jwtClaimsSet.getStringClaim("nonce"));
		
		assertEquals(6, jwtClaimsSet.getClaims().size());
	}


	public void testCreateClaimsSet_withNonce() throws ParseException, JOSEException {
		
		JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
			JTI,
			HTM,
			HTU,
			IAT,
			null,
			NONCE
		);
		assertEquals(JTI.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(HTM, jwtClaimsSet.getStringClaim("htm"));
		assertEquals(HTU, jwtClaimsSet.getURIClaim("htu"));
		assertEquals(IAT, jwtClaimsSet.getIssueTime());
		assertEquals(NONCE.getValue(), jwtClaimsSet.getStringClaim("nonce"));
		
		assertEquals(5, jwtClaimsSet.getClaims().size());
	}


	public void testCreateClaimsSet_jtiNull() throws JOSEException {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				null,
				HTM,
				HTU,
				IAT,
				null
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}


	public void testCreateClaimsSet_htmNull() throws JOSEException {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				null,
				HTU,
				IAT,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The HTTP method (htu) is required", e.getMessage());
		}
	}


	public void testCreateClaimsSet_htuNull() throws JOSEException {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				null,
				IAT,
				null
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testCreateClaimsSet_htuQueryString() throws JOSEException {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				URI.create(HTU + "?query"),
				IAT,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The HTTP URI (htu) must not have a query", e.getMessage());
		}
	}
	
	
	public void testCreateClaimsSet_htuFragmentString() throws JOSEException {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				URI.create(HTU + "#fragment"),
				IAT,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The HTTP URI (htu) must not have a fragment", e.getMessage());
		}
	}
	
	
	public void testCreateClaimsSet_iatNull() throws JOSEException {
		
		try {
			DPoPUtils.createJWTClaimsSet(
				JTI,
				HTM,
				HTU,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The issue time (iat) is required", e.getMessage());
		}
	}
}
