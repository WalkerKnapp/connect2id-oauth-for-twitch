package com.nimbusds.oauth2.sdk.auth;


import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests client secret basic authentication.
 *
 * @author Vladimir Dzhuvinov
 */
public class ClientSecretBasicTest extends TestCase {


	public void testSerializeAndParse()
		throws ParseException {
	
		// Test vectors from OAuth 2.0 RFC
		
		final String id = "s6BhdRkqt3";
		final String pw = "7Fjfp0ZBr1KtDRbnfVdmIw";
		
		ClientID clientID = new ClientID(id);
		Secret secret = new Secret(pw);
		
		ClientSecretBasic csb = new ClientSecretBasic(clientID, secret);
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, csb.getMethod());
		
		assertEquals(id, csb.getClientID().toString());
		assertEquals(pw, csb.getClientSecret().getValue());
		
		String header = csb.toHTTPAuthorizationHeader();
		
		assertEquals("Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3", header);
		
		csb = ClientSecretBasic.parse(header);
		
		assertEquals(id, csb.getClientID().toString());
		assertEquals(pw, csb.getClientSecret().getValue());
	}


	public void testParseAndSerialize()
		throws Exception {

		String header = "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3";

		ClientSecretBasic csb = ClientSecretBasic.parse(header);

		assertEquals("s6BhdRkqt3", csb.getClientID().getValue());
		assertEquals("7Fjfp0ZBr1KtDRbnfVdmIw", csb.getClientSecret().getValue());
	}
}
