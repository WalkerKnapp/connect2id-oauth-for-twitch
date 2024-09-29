/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;


public class EmbeddedAttachmentTest extends TestCase {
	
	
	public void testLifeCycle()
		throws ParseException {
	
		String description = "John Doe ID card";
		
		EmbeddedAttachment attachment = new EmbeddedAttachment(new Content(ContentTest.IMAGE_JPG, ContentTest.SAMPLE_ID_CARD_JPEG, description));
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(ContentTest.IMAGE_JPG, attachment.getContent().getType());
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG, attachment.getContent().getBase64());
		assertEquals(description, attachment.getDescriptionString());
		
		JSONObject jsonObject = attachment.toJSONObject();
		assertEquals(ContentTest.IMAGE_JPG.toString(), jsonObject.get("content_type"));
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG.toString(), jsonObject.get("content"));
		assertEquals(description, jsonObject.get("desc"));
		assertEquals(3, jsonObject.size());
		
		attachment = EmbeddedAttachment.parse(jsonObject);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(ContentTest.IMAGE_JPG, attachment.getContent().getType());
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG, attachment.getContent().getBase64());
		assertEquals(description, attachment.getDescriptionString());
		
		assertEquals(attachment, EmbeddedAttachment.parse(jsonObject));
		assertEquals(attachment.hashCode(), EmbeddedAttachment.parse(jsonObject).hashCode());
	}


	public void testLifeCycle_noDesc()
		throws ParseException {
	
		EmbeddedAttachment attachment = new EmbeddedAttachment(new Content(ContentTest.IMAGE_JPG, ContentTest.SAMPLE_ID_CARD_JPEG, null));
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(ContentTest.IMAGE_JPG, attachment.getContent().getType());
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG, attachment.getContent().getBase64());
		assertNull(attachment.getDescriptionString());
		
		JSONObject jsonObject = attachment.toJSONObject();
		assertEquals(ContentTest.IMAGE_JPG.toString(), jsonObject.get("content_type"));
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG.toString(), jsonObject.get("content"));
		assertEquals(2, jsonObject.size());
		
		attachment = EmbeddedAttachment.parse(jsonObject);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(ContentTest.IMAGE_JPG, attachment.getContent().getType());
		assertEquals(ContentTest.SAMPLE_ID_CARD_JPEG, attachment.getContent().getBase64());
		assertNull(attachment.getDescriptionString());
		
		assertEquals(attachment, EmbeddedAttachment.parse(jsonObject));
		assertEquals(attachment.hashCode(), EmbeddedAttachment.parse(jsonObject).hashCode());
	}
	
	
	public void testInequality() {
		
		EmbeddedAttachment a = new EmbeddedAttachment(new Content(ContentTest.IMAGE_JPG, ContentTest.SAMPLE_ID_CARD_JPEG, null));
		EmbeddedAttachment b = new EmbeddedAttachment(new Content(ContentTest.IMAGE_JPG, ContentTest.SAMPLE_ID_CARD_JPEG, "Some description"));
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
	
	
	public void testConstructor_contentTypeMustBeDefined() {
		
		try {
			new EmbeddedAttachment(null);
			fail();
		} catch (NullPointerException e) {
			assertEquals("Cannot invoke \"com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Content.getDescription()\" because \"content\" is null", e.getMessage());
		}
	}
	
	
	public void testParse_missingContentType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content", ContentTest.SAMPLE_ID_CARD_JPEG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key content_type", e.getMessage());
		}
	}
	
	
	public void testParse_emptyContentType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", "");
		jsonObject.put("content", ContentTest.SAMPLE_ID_CARD_JPEG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid content_type: Null or empty content type string", e.getMessage());
		}
	}
	
	
	public void testParse_blankContentType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", " ");
		jsonObject.put("content", ContentTest.SAMPLE_ID_CARD_JPEG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid content_type: Null or empty content type string", e.getMessage());
		}
	}
	
	
	public void testParse_missingContent() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", ContentTest.IMAGE_JPG.toString());
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key content", e.getMessage());
		}
	}
	
	
	public void testParse_emptyContent() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", ContentTest.IMAGE_JPG.toString());
		jsonObject.put("content", "");
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Empty or blank JSON object member with key content", e.getMessage());
		}
	}
	
	
	public void testParse_blankContent() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", ContentTest.IMAGE_JPG.toString());
		jsonObject.put("content", "");
		
		try {
			EmbeddedAttachment.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Empty or blank JSON object member with key content", e.getMessage());
		}
	}
	
	
	public void testParse_invalidContentB64()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("content_type", ContentTest.IMAGE_JPG.toString());
		jsonObject.put("content", "{}{}{}");
		
		EmbeddedAttachment attachment = EmbeddedAttachment.parse(jsonObject);
		
		assertEquals(AttachmentType.EMBEDDED, attachment.getType());
		assertEquals(ContentTest.IMAGE_JPG, attachment.getContent().getType());
		assertEquals("{}{}{}", attachment.getContent().getBase64().toString());
		assertNull(attachment.getDescriptionString());
		
		byte[] contentBytes = attachment.getContent().getBase64().decode();
		assertEquals(0, contentBytes.length);
	}
}
