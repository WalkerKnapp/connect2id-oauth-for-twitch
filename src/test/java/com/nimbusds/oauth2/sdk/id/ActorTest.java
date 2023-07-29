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

package com.nimbusds.oauth2.sdk.id;


import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class ActorTest extends TestCase {
	

	public void testMinimalConstructor()
		throws ParseException {

		Actor actor = new Actor(new Subject("claire"));
		assertEquals("claire", actor.getSubject().getValue());
		assertNull(actor.getIssuer());
		assertNull(actor.getParent());

		JSONObject jsonObject = actor.toJSONObject();
		assertEquals("claire", jsonObject.get("sub"));
		assertEquals(1, jsonObject.size());

		actor = Actor.parse(jsonObject);
		assertEquals("claire", actor.getSubject().getValue());
		assertNull(actor.getIssuer());
		assertNull(actor.getParent());

		// top-level JSON object
		JSONObject topLevel = new JSONObject();
		topLevel.put("act", actor.toJSONObject());

		actor = Actor.parseTopLevel(topLevel);
		assertEquals("claire", actor.getSubject().getValue());
		assertNull(actor.getIssuer());
		assertNull(actor.getParent());
	}


	public void testFullConstructor()
		throws ParseException {

		Actor parent = new Actor(new Subject("cindy"));

		Actor actor = new Actor(new Subject("claire"), new Issuer("https://openid.c2id.com"), parent);
		assertEquals("claire", actor.getSubject().getValue());
		assertEquals("https://openid.c2id.com", actor.getIssuer().getValue());
		assertEquals(parent, actor.getParent());

		JSONObject jsonObject = actor.toJSONObject();
		assertEquals("claire", jsonObject.get("sub"));
		assertEquals("https://openid.c2id.com", jsonObject.get("iss"));
		assertEquals("cindy", ((JSONObject)jsonObject.get("act")).get("sub"));
		assertEquals(3, jsonObject.size());

		actor = Actor.parse(jsonObject);
		assertEquals("claire", actor.getSubject().getValue());
		assertEquals("https://openid.c2id.com", actor.getIssuer().getValue());
		assertEquals("cindy", actor.getParent().getSubject().getValue());
		assertNull(actor.getParent().getIssuer());
		assertNull(actor.getParent().getParent());

		// top-level JSON object
		JSONObject topLevel = new JSONObject();
		topLevel.put("act", actor.toJSONObject());

		actor = Actor.parseTopLevel(topLevel);
		assertEquals("claire", actor.getSubject().getValue());
		assertEquals("https://openid.c2id.com", actor.getIssuer().getValue());
		assertEquals("cindy", actor.getParent().getSubject().getValue());
		assertNull(actor.getParent().getIssuer());
		assertNull(actor.getParent().getParent());
	}


	public void testParseEmptyTopLevel()
		throws ParseException {

		JSONObject jsonObject = new JSONObject();

		assertNull(Actor.parseTopLevel(jsonObject));
	}
	
	
	public void testToString() {
		
		Actor actor = new Actor(new Subject("claire"));
		
		assertEquals("{\"sub\":\"claire\"}", actor.toString());
	}


	public void testEquality() {

		assertEquals(new Actor(new Subject("claire")), new Actor(new Subject("claire")));

		assertEquals(
			new Actor(new Subject("claire"), new Issuer("https://openid.com"), null),
			new Actor(new Subject("claire"), new Issuer("https://openid.com"), null)
		);

		assertEquals(
			new Actor(new Subject("claire"), new Issuer("https://openid.com"),
			new Actor(new Subject("cindy"))), new Actor(new Subject("claire"), new Issuer("https://openid.com"), new Actor(new Subject("cindy")))
		);
	}
}
