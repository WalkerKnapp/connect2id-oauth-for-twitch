/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.nimbusds.openid.connect.sdk.federation.trust.TrustChainTest.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.EntityIDConstraint;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.ExactMatchEntityIDConstraint;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;


public class TrustChainSetTest extends TestCase {
	
	
	public void testWithTwo() throws JOSEException {
		
		// chain with leaf and anchor
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain minimalChain = new TrustChain(leafStmt, superiorStatements);
		
		// chain with leaf, intermediate and anchor
		leafClaims = createOPSelfStatementClaimsSet(INTERMEDIATE_ENTITY_ID);
		leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		superiorStatements = Arrays.asList(intermediateStmtAboutLeaf, anchorStmtAboutIntermediate);
		TrustChain longerChain = new TrustChain(leafStmt, superiorStatements);
		
		TrustChainSet set = new TrustChainSet();
		set.add(minimalChain);
		set.add(longerChain);
		
		assertEquals(2, set.size());
		
		assertEquals(minimalChain, set.getShortest());
		
		assertEquals(set, set.filter(new TrustChainConstraints()));
		
		assertEquals(set, set.filter(new TrustChainConstraints(1)));
		assertEquals(Collections.singleton(minimalChain), set.filter(new TrustChainConstraints(0)));
		
		assertTrue(set.filter(new TrustChainConstraints(-1, null, Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(ANCHOR_ENTITY_ID)), null)).isEmpty());
	}
}
