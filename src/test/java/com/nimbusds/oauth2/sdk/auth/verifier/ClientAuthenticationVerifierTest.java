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

package com.nimbusds.oauth2.sdk.auth.verifier;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.utils.ConstantTimeUtils;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;
import junit.framework.TestCase;
import org.mockito.ArgumentCaptor;

import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


/**
 * Tests the client authentication verifier.
 */
public class ClientAuthenticationVerifierTest extends TestCase {


	private static final ClientID VALID_CLIENT_ID = new ClientID("123");


	private static final Secret VALID_CLIENT_SECRET = new Secret();


	private static final Set<Audience> EXPECTED_JWT_AUDIENCE = new LinkedHashSet<>(Arrays.asList(
		new Audience("https://c2id.com/token"),
		new Audience("https://c2id.com")));
	
	
	private static final String VALID_SUBJECT_DN = "cn=client-123";

	
	private static final RSAKey VALID_RSA_KEY_PAIR_1;


	private static final RSAKey VALID_RSA_KEY_PAIR_2;


	private static final RSAKey INVALID_RSA_KEY_PAIR;


	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");

			KeyPair keyPair = gen.generateKeyPair();
			VALID_RSA_KEY_PAIR_1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("1")
				.build();

			keyPair = gen.generateKeyPair();
			VALID_RSA_KEY_PAIR_2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("2")
				.build();

			keyPair = gen.generateKeyPair();
			INVALID_RSA_KEY_PAIR = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.build();

		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}


	private static final ClientCredentialsSelector<ClientMetadata> CLIENT_CREDENTIALS_SELECTOR = new ClientCredentialsSelector<ClientMetadata>() {


		@Override
		public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context<ClientMetadata> context)
			throws InvalidClientException {

			assert authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT);

			if (! claimedClientID.equals(VALID_CLIENT_ID)) {
				throw InvalidClientException.BAD_ID;
			}

			return Collections.singletonList(VALID_CLIENT_SECRET);
		}


		@Override
		public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID,
								  ClientAuthenticationMethod authMethod,
								  JWSHeader jwsHeader,
								  boolean forceRefresh,
								  Context<ClientMetadata> context)
			throws InvalidClientException {

			final Set<ClientAuthenticationMethod> permittedClientAuthMethods =
				new HashSet<>(Arrays.asList(
					ClientAuthenticationMethod.PRIVATE_KEY_JWT,
					ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
			
			assert permittedClientAuthMethods.contains(authMethod);

			if (! claimedClientID.equals(VALID_CLIENT_ID)) {
				throw InvalidClientException.BAD_ID;
			}

			try {
				if (!forceRefresh) {
					return Collections.singletonList(VALID_RSA_KEY_PAIR_1.toRSAPublicKey());
				} else {
					// Simulate reload
					return Arrays.asList(VALID_RSA_KEY_PAIR_1.toRSAPublicKey(), VALID_RSA_KEY_PAIR_2.toRSAPublicKey());
				}

			} catch (JOSEException e) {
				fail(e.getMessage());
				throw InvalidClientException.NO_MATCHING_JWK;
			}
		}
	};
	
	
	private static final PKIClientX509CertificateBindingVerifier<ClientMetadata> CERT_BINDING_VERIFIER = new PKIClientX509CertificateBindingVerifier<ClientMetadata>() {
		
		@Override
		public void verifyCertificateBinding(ClientID clientID,
						     X509Certificate certificate,
						     Context<ClientMetadata> ctx)
			throws InvalidClientException {
			
			if (! VALID_CLIENT_ID.equals(clientID)) {
				throw InvalidClientException.BAD_ID;
			}
			
			if (! VALID_SUBJECT_DN.equalsIgnoreCase(certificate.getSubjectDN().getName())) {
				throw new InvalidClientException("Bad subject DN");
			}
		}
	};


	public void testGetters() {

		ClientCredentialsSelector<?> selector = new ClientCredentialsSelector() {
			@Override
			public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) throws InvalidClientException {
				return null;
			}


			@Override
			public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh, Context context) throws InvalidClientException {
				return null;
			}
		};

		Set<Audience> audienceSet = new HashSet<>();
		audienceSet.add(new Audience("https://c2id.com/token"));

		ClientAuthenticationVerifier<?> verifier = new ClientAuthenticationVerifier<>(selector, audienceSet);

		assertEquals(selector, verifier.getClientCredentialsSelector());
		assertNull(verifier.getClientX509CertificateBindingVerifier());
		assertEquals(audienceSet, verifier.getExpectedAudience());
	}


	private static ClientAuthenticationVerifier<ClientMetadata> createBasicVerifier() {

		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, EXPECTED_JWT_AUDIENCE);
	}


	private static ClientAuthenticationVerifier<ClientMetadata> createBasicVerifierWithReusePrevention(final ExpendedJTIChecker<ClientMetadata> jtiChecker) {

		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, EXPECTED_JWT_AUDIENCE, jtiChecker);
	}
	
	
	private static ClientAuthenticationVerifier<ClientMetadata> createVerifierWithPKIBoundCertSupport() {
		
		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, CERT_BINDING_VERIFIER, EXPECTED_JWT_AUDIENCE);
	}


	public void testHappyClientSecretBasic()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}
	
	
	public void testHappyClientSecretPost()
		throws Exception{
		
		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);
		
		createBasicVerifier().verify(clientAuthentication, null, null);
	}
	
	
	public void testHappyClientSecretBasic_overriddenSecretEquals()
		throws Exception {
		
		final Secret storedHashBasedSecret = new Secret() {
			
			@Override
			public boolean equals(Object o) {
				
				if (! (o instanceof Secret)) {
					return false;
				}
				
				Secret otherSecret = (Secret) o;
				
				return ConstantTimeUtils.areEqual(VALID_CLIENT_SECRET.getSHA256(), otherSecret.getSHA256());
			}
		};
		
		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);
		
		ClientAuthenticationVerifier<?> verifier = new ClientAuthenticationVerifier<>(
			new ClientCredentialsSelector() {
				@Override
				public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) {
					return Collections.singletonList(storedHashBasedSecret);
				}
				
				
				@Override
				public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh, Context context) throws InvalidClientException {
					return null;
				}
			},
			EXPECTED_JWT_AUDIENCE
		);
		
		verifier.verify(clientAuthentication, null, null);
	}
	

	public void testHappyClientSecretJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyClientSecretJWT_withReusePrevention()
		throws Exception {

		ClientSecretJWT clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		ExpendedJTIChecker<ClientMetadata> jtiChecker = mock(ExpendedJTIChecker.class);
		ArgumentCaptor<JWTID> jtiCaptor = ArgumentCaptor.forClass(JWTID.class);
		ArgumentCaptor<ClientID> clientIDCaptor = ArgumentCaptor.forClass(ClientID.class);
		ArgumentCaptor<ClientAuthenticationMethod> methodCaptor = ArgumentCaptor.forClass(ClientAuthenticationMethod.class);
		ArgumentCaptor<Context<ClientMetadata>> contextCaptor = ArgumentCaptor.forClass(Context.class);

		when(jtiChecker.isExpended(jtiCaptor.capture(), clientIDCaptor.capture(), methodCaptor.capture(), contextCaptor.capture())).thenReturn(false);

		createBasicVerifierWithReusePrevention(jtiChecker).verify(clientAuthentication, null, null);

		assertEquals(clientAuthentication.getJWTAuthenticationClaimsSet().getJWTID(), jtiCaptor.getValue());
		assertEquals(VALID_CLIENT_ID, clientIDCaptor.getValue());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, methodCaptor.getValue());
		assertNull(contextCaptor.getValue());
	}
	

	public void testClientSecretJWT_erasedStoredSecretValue()
		throws JOSEException {
		
		final Secret storedHashBasedSecret = new Secret();
		storedHashBasedSecret.erase();
		
		ClientAuthenticationVerifier<?> verifier = new ClientAuthenticationVerifier<>(
			new ClientCredentialsSelector() {
				@Override
				public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) {
					return Collections.singletonList(storedHashBasedSecret);
				}
				
				
				@Override
				public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh, Context context) throws InvalidClientException {
					return null;
				}
			},
			EXPECTED_JWT_AUDIENCE
		);

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		try {
			verifier.verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("The client has no registered secret", e.getMessage());
		}
	}


	public void testHappyPrivateKeyJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}


	public void testHappyPrivateKeyJWT_withReusePrevention()
		throws Exception {

		PrivateKeyJWT clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		ExpendedJTIChecker<ClientMetadata> jtiChecker = mock(ExpendedJTIChecker.class);
		ArgumentCaptor<JWTID> jtiCaptor = ArgumentCaptor.forClass(JWTID.class);
		ArgumentCaptor<ClientID> clientIDCaptor = ArgumentCaptor.forClass(ClientID.class);
		ArgumentCaptor<ClientAuthenticationMethod> methodCaptor = ArgumentCaptor.forClass(ClientAuthenticationMethod.class);
		ArgumentCaptor<Context<ClientMetadata>> contextCaptor = ArgumentCaptor.forClass(Context.class);

		when(jtiChecker.isExpended(jtiCaptor.capture(), clientIDCaptor.capture(), methodCaptor.capture(), contextCaptor.capture())).thenReturn(false);

		createBasicVerifierWithReusePrevention(jtiChecker).verify(clientAuthentication, null, null);

		assertEquals(clientAuthentication.getJWTAuthenticationClaimsSet().getJWTID(), jtiCaptor.getValue());
		assertEquals(VALID_CLIENT_ID, clientIDCaptor.getValue());
		assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, methodCaptor.getValue());
		assertNull(contextCaptor.getValue());
	}


	public void testHappyPrivateKeyJWT_withReusePrevention_realImpl()
		throws Exception {

		PrivateKeyJWT clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		createBasicVerifierWithReusePrevention(new SampleExpendedJTIChecker()).verify(clientAuthentication, null, null);
	}


	public void testClientSecretJWT_preventReuse()
		throws Exception {

		ClientSecretJWT clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		ExpendedJTIChecker<ClientMetadata> jtiChecker = mock(ExpendedJTIChecker.class);
		ArgumentCaptor<JWTID> jtiCaptor = ArgumentCaptor.forClass(JWTID.class);
		ArgumentCaptor<ClientID> clientIDCaptor = ArgumentCaptor.forClass(ClientID.class);
		ArgumentCaptor<ClientAuthenticationMethod> methodCaptor = ArgumentCaptor.forClass(ClientAuthenticationMethod.class);
		ArgumentCaptor<Context<ClientMetadata>> contextCaptor = ArgumentCaptor.forClass(Context.class);

		when(jtiChecker.isExpended(jtiCaptor.capture(), clientIDCaptor.capture(), methodCaptor.capture(), contextCaptor.capture())).thenReturn(true);

		try {
			createBasicVerifierWithReusePrevention(jtiChecker).verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Detected JWT ID replay", e.getMessage());
		}

		assertEquals(clientAuthentication.getJWTAuthenticationClaimsSet().getJWTID(), jtiCaptor.getValue());
		assertEquals(VALID_CLIENT_ID, clientIDCaptor.getValue());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, methodCaptor.getValue());
		assertNull(contextCaptor.getValue());
	}


	public void testPrivateKeyJWT_preventReuse()
		throws Exception {

		PrivateKeyJWT clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		ExpendedJTIChecker<ClientMetadata> jtiChecker = mock(ExpendedJTIChecker.class);
		ArgumentCaptor<JWTID> jtiCaptor = ArgumentCaptor.forClass(JWTID.class);
		ArgumentCaptor<ClientID> clientIDCaptor = ArgumentCaptor.forClass(ClientID.class);
		ArgumentCaptor<ClientAuthenticationMethod> methodCaptor = ArgumentCaptor.forClass(ClientAuthenticationMethod.class);
		ArgumentCaptor<Context<ClientMetadata>> contextCaptor = ArgumentCaptor.forClass(Context.class);

		when(jtiChecker.isExpended(jtiCaptor.capture(), clientIDCaptor.capture(), methodCaptor.capture(), contextCaptor.capture())).thenReturn(true);

		try {
			createBasicVerifierWithReusePrevention(jtiChecker).verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Detected JWT ID replay", e.getMessage());
		}

		assertEquals(clientAuthentication.getJWTAuthenticationClaimsSet().getJWTID(), jtiCaptor.getValue());
		assertEquals(VALID_CLIENT_ID, clientIDCaptor.getValue());
		assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, methodCaptor.getValue());
		assertNull(contextCaptor.getValue());
	}


	public void testClientSecretJWT_preventReuse_realImpl()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		ClientAuthenticationVerifier<ClientMetadata> verifier = createBasicVerifierWithReusePrevention(new SampleExpendedJTIChecker());

		verifier.verify(clientAuthentication, null, null);

		try {
			verifier.verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Detected JWT ID replay", e.getMessage());
		}
	}


	public void testPrivateKeyJWT_preventReuse_realImpl()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		ClientAuthenticationVerifier<ClientMetadata> verifier = createBasicVerifierWithReusePrevention(new SampleExpendedJTIChecker());

		verifier.verify(clientAuthentication, null, null);

		try {
			verifier.verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Detected JWT ID replay", e.getMessage());
		}
	}


	public void testInvalidClientSecretPost_badID()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(new ClientID("invalid-id"), VALID_CLIENT_SECRET);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_ID, e);
		}
	}


	public void testInvalidClientSecretPost_badSecret()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, new Secret("invalid-secret"));

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_SECRET, e);
		}
	}


	public void testInvalidClientSecretJWT_badHMAC()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_HMAC, e);
		}
	}


	public void testInvalidPrivateKeyJWT_badSignature()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_SIGNATURE, e);
		}
	}


	public void testClientSecretJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://other.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: JWT audience rejected: [https://other.com/token]", e.getMessage());
		}
	}


	public void testPrivateKeyJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID,
			URI.create("https://other.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: JWT audience rejected: [https://other.com/token]", e.getMessage());
		}
	}


	public void testExpiredClientSecretJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000L);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new MACSigner(VALID_CLIENT_SECRET.getValueBytes()));

		ClientAuthentication clientAuthentication = new ClientSecretJWT(jwt);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: Expired JWT", e.getMessage());
		}
	}


	public void testExpiredPrivateKeyJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000L);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new RSASSASigner(VALID_RSA_KEY_PAIR_1));

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(jwt);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertEquals("Bad / expired JWT claims: Expired JWT", e.getMessage());
		}
	}


	public void testReloadRemoteJWKSet()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_2.toRSAPrivateKey(),
			null,
			null);

		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}


	public void testReloadRemoteJWKSet_preventReuse()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_2.toRSAPrivateKey(),
			null,
			null);

		ClientAuthenticationVerifier<?> verifier = createBasicVerifierWithReusePrevention(new SampleExpendedJTIChecker());

		verifier.verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);

		try {
			verifier.verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Detected JWT ID replay", e.getMessage());
		}
	}


	public void testReloadRemoteJWKSet_badSignature()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
		} catch (InvalidClientException e) {
			assertEquals(InvalidClientException.BAD_JWT_SIGNATURE, e);
		}
	}
	
	
	public void testPubKeyTLSClientAuth_ok()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			VALID_RSA_KEY_PAIR_1.toRSAPublicKey(),
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, null, null);
	}
	
	
	public void testPubKeyTLSClientAuth_signedByCA_ok()
		throws Exception {
		
		// Generate CA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey caRSAPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey caRSAPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		X509Certificate clientCert = X509CertificateGenerator.generateCertificate(
			new Issuer("o=c2id"),
			new Subject(VALID_CLIENT_ID.getValue()),
			VALID_RSA_KEY_PAIR_1.toRSAPublicKey(), // client public key
			caRSAPrivateKey // CA private key
		);
		
		assertTrue(X509CertificateUtils.hasValidSignature(clientCert, caRSAPublicKey));
		assertTrue(X509CertificateUtils.publicKeyMatches(clientCert, VALID_RSA_KEY_PAIR_1.toRSAPublicKey()));
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, null, null);
	}
	
	
	public void testPubKeyTLSClientAuth_okWithReload()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			VALID_RSA_KEY_PAIR_2.toRSAPublicKey(),
			VALID_RSA_KEY_PAIR_2.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}
	
	
	public void testPubKeyTLSClientAuth_signedByCA_okWithReload()
		throws Exception {
		
		// Generate CA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey caRSAPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey caRSAPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		X509Certificate clientCert = X509CertificateGenerator.generateCertificate(
			new Issuer("o=c2id"),
			new Subject(VALID_CLIENT_ID.getValue()),
			VALID_RSA_KEY_PAIR_1.toRSAPublicKey(), // client public key
			caRSAPrivateKey // CA private key
		);
		
		assertTrue(X509CertificateUtils.hasValidSignature(clientCert, caRSAPublicKey));
		assertTrue(X509CertificateUtils.publicKeyMatches(clientCert, VALID_RSA_KEY_PAIR_1.toRSAPublicKey()));
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}
	
	public void testPubKeyTLSClientAuth_badSignature()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			INVALID_RSA_KEY_PAIR.toRSAPublicKey(),
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Couldn't validate client X.509 certificate signature: No matching registered client JWK found", e.getMessage());
		}
	}
	
	public void testPubKeyTLSClientAuth_signedByCA_badSignature()
		throws Exception {
		
		// Generate CA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey caRSAPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey caRSAPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		X509Certificate clientCert = X509CertificateGenerator.generateCertificate(
			new Issuer("o=c2id"),
			new Subject(VALID_CLIENT_ID.getValue()),
			INVALID_RSA_KEY_PAIR.toRSAPublicKey(), // client public key that isn't registered
			caRSAPrivateKey // CA private key
		);
		
		assertTrue(X509CertificateUtils.hasValidSignature(clientCert, caRSAPublicKey));
		assertTrue(X509CertificateUtils.publicKeyMatches(clientCert, INVALID_RSA_KEY_PAIR.toRSAPublicKey()));
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Couldn't validate client X.509 certificate signature: No matching registered client JWK found", e.getMessage());
		}
	}
	
	
	public void testPubKeyTLSClientAuth_missingCertificate()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			(SSLSocketFactory) null);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Missing client X.509 certificate", e.getMessage());
		}
	}
	
	
	public void testTLSClientAuth_ok()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new PKITLSClientAuthentication(
			VALID_CLIENT_ID,
			X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate("issuer", "client-123")
		);
		
		createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
	}
	
	
	public void testTLSClientAuth_badSubjectDN()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new PKITLSClientAuthentication(
			VALID_CLIENT_ID,
			X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate("issuer", "invalid-subject")
		);
		
		try {
			createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertEquals("Bad subject DN", e.getMessage());
		}
	}
}
