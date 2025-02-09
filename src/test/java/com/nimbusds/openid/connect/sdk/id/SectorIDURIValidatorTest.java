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

package com.nimbusds.openid.connect.sdk.id;


import java.io.IOException;
import java.net.SocketException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.ciba.BackChannelTokenDeliveryMode;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class SectorIDURIValidatorTest extends TestCase {
	

	public void testSuccess()
		throws Exception {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				jsonArray.add("https://yourapp.com/callback");
				return new Resource(jsonArray.toJSONString(), "application/json");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
	}


	public void testRetrievalFailed() {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				throw new SocketException("Timeout");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Couldn't retrieve the sector ID JSON document: Timeout", e.getMessage());
		}
	}


	public void testMissingContentType() {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				jsonArray.add("https://yourapp.com/callback");
				return new Resource(jsonArray.toJSONString(), null);
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Couldn't validate sector ID: Missing HTTP Content-Type", e.getMessage());
		}
	}


	public void testBadContentType() {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				jsonArray.add("https://yourapp.com/callback");
				return new Resource(jsonArray.toJSONString(), "text/plain");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Couldn't validate sector ID: HTTP Content-Type must be application/json, found text/plain", e.getMessage());
		}
	}


	public void testBadJSON() {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				return new Resource("a b c", "application/json");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Invalid JSON", e.getMessage());
		}
	}


	public void testRedirectURINotFoundInSectorIDURI() {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {

				JSONArray jsonArray = new JSONArray();
				jsonArray.add("https://myapp.com/callback");
				return new Resource(jsonArray.toJSONString(), "application/json");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://myapp.com/callback"), URI.create("https://yourapp.com/callback")));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Sector ID validation failed: URI https://yourapp.com/callback not present at sector ID URI https://example.com/apps.json", e.getMessage());
		}
	}


	public void testNoneRedirectURIsInInSectorIDURI() {

		ResourceRetriever resourceRetriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) throws IOException {
				return new Resource("[]", "application/json");
			}
		};

		SectorIDURIValidator v = new SectorIDURIValidator(resourceRetriever);

		assertEquals(resourceRetriever, v.getResourceRetriever());

		Set<URI> redirectURIs = Collections.singleton(URI.create("https://myapp.com/callback"));

		try {
			v.validate(URI.create("https://example.com/apps.json"), redirectURIs);
			fail();
		} catch (GeneralException e) {
			assertEquals("Sector ID validation failed: URI https://myapp.com/callback not present at sector ID URI https://example.com/apps.json", e.getMessage());
		}
	}
	
	
	
	public void testCollectURIs_none() {
	
		assertTrue(SectorIDURIValidator.collectURIsForValidation(new OIDCClientMetadata()).isEmpty());
	}
	
	
	public void testCollectURIs_redirectURI() {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setRedirectionURI(URI.create("https://rp.example.com"));
		clientMetadata.applyDefaults();
		
		assertEquals(Collections.singleton(URI.create("https://rp.example.com")), SectorIDURIValidator.collectURIsForValidation(clientMetadata));
	}
	
	
	public void testCollectURIs_multipleRedirectURIs() {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		Set<URI> redirectURIs = new HashSet<>(Arrays.asList(URI.create("https://rp.example.com/cb-1"), URI.create("https://rp.example.com/cb-2")));
		clientMetadata.setRedirectionURIs(redirectURIs);
		clientMetadata.applyDefaults();
		
		assertEquals(redirectURIs, SectorIDURIValidator.collectURIsForValidation(clientMetadata));
	}
	
	
	public void testCollectURIs_CIBA_poll() {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.POLL);
		
		assertTrue(SectorIDURIValidator.collectURIsForValidation(clientMetadata).isEmpty());
		
		clientMetadata.setJWKSetURI(URI.create("https://rp.example.com/jwks.json"));
		
		assertEquals(Collections.singleton(URI.create("https://rp.example.com/jwks.json")), SectorIDURIValidator.collectURIsForValidation(clientMetadata));
	}
	
	
	public void testCollectURIs_CIBA_ping() {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.PING);
		
		assertTrue(SectorIDURIValidator.collectURIsForValidation(clientMetadata).isEmpty());
		
		clientMetadata.setJWKSetURI(URI.create("https://rp.example.com/jwks.json"));
		
		assertEquals(Collections.singleton(URI.create("https://rp.example.com/jwks.json")), SectorIDURIValidator.collectURIsForValidation(clientMetadata));
	}
	
	
	public void testCollectURIs_CIBA_push() {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.PUSH);
		
		assertTrue(SectorIDURIValidator.collectURIsForValidation(clientMetadata).isEmpty());
		
		clientMetadata.setBackChannelClientNotificationEndpoint(URI.create("https://rp.example.com/ciba"));
		
		assertEquals(Collections.singleton(URI.create("https://rp.example.com/ciba")), SectorIDURIValidator.collectURIsForValidation(clientMetadata));
	}
	
	
	public void testCollectURIs_codeGrant_and_CIBA() {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(new HashSet<>(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.CIBA)));
		clientMetadata.setRedirectionURI(URI.create("https://rp.example.com/cb"));
		clientMetadata.setJWKSetURI(URI.create("https://rp.example.com/jwks.json"));
		clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
		clientMetadata.setTokenEndpointAuthJWSAlg(JWSAlgorithm.RS256);
		clientMetadata.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.POLL);
		clientMetadata.setBackChannelAuthRequestJWSAlg(JWSAlgorithm.RS256);
		
		Set<URI> urisToValidate = SectorIDURIValidator.collectURIsForValidation(clientMetadata);
		assertTrue(urisToValidate.contains(URI.create("https://rp.example.com/cb")));
		assertTrue(urisToValidate.contains(URI.create("https://rp.example.com/jwks.json")));
		assertEquals(2, urisToValidate.size());
	}
}
