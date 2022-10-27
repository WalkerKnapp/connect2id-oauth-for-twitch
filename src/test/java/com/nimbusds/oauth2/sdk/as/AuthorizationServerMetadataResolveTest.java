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

package com.nimbusds.oauth2.sdk.as;


import java.io.IOException;

import static net.jadler.Jadler.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class AuthorizationServerMetadataResolveTest {
	
	
	@Before
	public void setUp() {
		initJadler();
	}
	
	
	@After
	public void tearDown() {
		closeJadler();
	}
	
	
	@Test
	public void testResolveOK()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port());
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(issuer);
		metadata.applyDefaults();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/.well-known/oauth-authorization-server")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(metadata.toJSONObject().toJSONString());
		
		AuthorizationServerMetadata result = AuthorizationServerMetadata.resolve(issuer);
		
		assertEquals(issuer, result.getIssuer());
	}
	
	
	@Test
	public void testResolveWithPathOK()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port() + "/tenant-1");
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(issuer);
		metadata.applyDefaults();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/tenant-1/.well-known/oauth-authorization-server")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(metadata.toJSONObject().toJSONString());
		
		AuthorizationServerMetadata result = AuthorizationServerMetadata.resolve(issuer);
		
		assertEquals(issuer, result.getIssuer());
	}
	
	
	@Test
	public void testResolveWithPathTrailingSlashOK()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port() + "/tenant-1/");
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(issuer);
		metadata.applyDefaults();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/tenant-1/.well-known/oauth-authorization-server")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(metadata.toJSONObject().toJSONString());
		
		AuthorizationServerMetadata result = AuthorizationServerMetadata.resolve(issuer);
		
		assertEquals(issuer, result.getIssuer());
	}
	
	
	@Test
	public void testResolveWithConfigurator()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port());
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(issuer);
		metadata.applyDefaults();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/.well-known/oauth-authorization-server")
			.havingHeaderEqualTo("Accept", "application/json")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(metadata.toJSONObject().toJSONString());
		
		AuthorizationServerMetadata result = AuthorizationServerMetadata.resolve(
			issuer,
			new HTTPRequestConfigurator() {
				@Override
				public void configure(HTTPRequest httpRequest) {
					httpRequest.setAccept("application/json");
				}
			});
		
		assertEquals(issuer, result.getIssuer());
	}
	
	
	@Test
	public void testResolveInvalidMetadata()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port());
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/.well-known/oauth-authorization-server")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody("{}");
		
		try {
			AuthorizationServerMetadata.resolve(issuer);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key issuer", e.getMessage());
		}
	}
	
	
	@Test
	public void testResolveNotFound404()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port());
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/.well-known/oauth-authorization-server")
			.respond()
			.withStatus(404)
			.withContentType("text/plain")
			.withBody("Not Found");
		
		try {
			AuthorizationServerMetadata.resolve(issuer);
			fail();
		} catch (IOException e) {
			assertEquals("Couldn't download OAuth 2.0 Authorization Server metadata from http://localhost:"+port()+"/.well-known/oauth-authorization-server: Status code 404", e.getMessage());
		}
	}
	
	
	@Test
	public void testIssuerMismatch()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port());
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(new Issuer("http://localhost/abcdef"));
		metadata.applyDefaults();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/.well-known/oauth-authorization-server")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(metadata.toJSONObject().toJSONString());
		
		try {
			AuthorizationServerMetadata.resolve(issuer);
			fail();
		} catch (GeneralException e) {
			assertEquals("The returned issuer doesn't match the expected: http://localhost/abcdef", e.getMessage());
		}
	}
}
