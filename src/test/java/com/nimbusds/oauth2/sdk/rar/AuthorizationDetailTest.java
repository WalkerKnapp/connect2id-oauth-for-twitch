/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.rar;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class AuthorizationDetailTest extends TestCase {


        public void testMinimal()
                throws ParseException {

                AuthorizationType type = new AuthorizationType("payment_initiation");

                AuthorizationDetail detail = new AuthorizationDetail.Builder(type).build();

                assertEquals(type, detail.getType());

                JSONObject jsonObject = detail.toJSONObject();
                assertEquals(type.getValue(), jsonObject.get("type"));
                assertEquals(1, jsonObject.size());

                detail = AuthorizationDetail.parse(jsonObject);

                assertEquals(type, detail.getType());

                assertEquals(detail, AuthorizationDetail.parse(jsonObject));
                assertEquals(detail.hashCode(), AuthorizationDetail.parse(jsonObject).hashCode());
        }


        public void testAllStandardFields()
                throws ParseException {

                AuthorizationType type = new AuthorizationType("payment_initiation");
                List<Location> locations = Arrays.asList(new Location("rs1"), new Location("rs2"));
                List<Action> actions = Arrays.asList(new Action("read"), new Action("write"));
                List<DataType> dataTypes = Arrays.asList(new DataType("email"), new DataType("telephone"));
                Identifier identifier = new Identifier("7ca256ff-c112-4a80-b38c-79685417538f");
                List<Privilege> privileges = Arrays.asList(new Privilege("admin"), new Privilege("audit"));

                AuthorizationDetail detail = new AuthorizationDetail.Builder(type)
                        .locations(locations)
                        .actions(actions)
                        .dataTypes(dataTypes)
                        .identifier(identifier)
                        .privileges(privileges)
                        .build();

                assertEquals(type, detail.getType());
                assertEquals(locations, detail.getLocations());
                assertEquals(actions, detail.getActions());
                assertEquals(dataTypes, detail.getDataTypes());
                assertEquals(identifier, detail.getIdentifier());
                assertEquals(privileges, detail.getPrivileges());

                JSONObject jsonObject = detail.toJSONObject();
                assertEquals(type.getValue(), jsonObject.get("type"));
                assertEquals(Identifier.toStringList(locations), jsonObject.get("locations"));
                assertEquals(Identifier.toStringList(actions), jsonObject.get("actions"));
                assertEquals(Identifier.toStringList(dataTypes), jsonObject.get("datatypes"));
                assertEquals(identifier.getValue(), jsonObject.get("identifier"));
                assertEquals(Identifier.toStringList(privileges), jsonObject.get("privileges"));
                assertEquals(6, jsonObject.size());

                detail = AuthorizationDetail.parse(jsonObject);

                assertEquals(type, detail.getType());
                assertEquals(locations, detail.getLocations());
                assertEquals(actions, detail.getActions());
                assertEquals(dataTypes, detail.getDataTypes());
                assertEquals(identifier, detail.getIdentifier());
                assertEquals(privileges, detail.getPrivileges());

                assertEquals(detail, AuthorizationDetail.parse(jsonObject));
                assertEquals(detail.hashCode(), AuthorizationDetail.parse(jsonObject).hashCode());
        }


        public void testBuilderMethods_nulls() {

                AuthorizationType type = new AuthorizationType("payment_initiation");
                List<Location> locations = Arrays.asList(new Location("rs1"), new Location("rs2"));
                List<Action> actions = Arrays.asList(new Action("read"), new Action("write"));
                List<DataType> dataTypes = Arrays.asList(new DataType("email"), new DataType("telephone"));
                Identifier identifier = new Identifier("7ca256ff-c112-4a80-b38c-79685417538f");
                List<Privilege> privileges = Arrays.asList(new Privilege("admin"), new Privilege("audit"));
                String ref = "d0b3b92b-dddd-437d-a23e-faabc55f9647";

                AuthorizationDetail detail = new AuthorizationDetail.Builder(type)
                        .locations(locations)
                        .actions(actions)
                        .dataTypes(dataTypes)
                        .identifier(identifier)
                        .privileges(privileges)
                        .field("ref", ref)
                        .locations(null) // clears field
                        .actions(null) // clears field
                        .dataTypes(null) // clears field
                        .identifier(null) // clears field
                        .privileges(null) // clears field
                        .field("ref", null) // clears field
                        .build();

                assertEquals(type, detail.getType());
                assertNull(detail.getLocations());
                assertNull(detail.getActions());
                assertNull(detail.getDataTypes());
                assertNull(detail.getIdentifier());
                assertNull(detail.getPrivileges());

                JSONObject jsonObject = detail.toJSONObject();
                assertEquals(type.getValue(), jsonObject.get("type"));
                assertEquals(1, jsonObject.size());
        }


        public void testBuilderCustomField() {

                AuthorizationType type = new AuthorizationType("payment_initiation");
                String ref = "d0b3b92b-dddd-437d-a23e-faabc55f9647";

                AuthorizationDetail detail = new AuthorizationDetail.Builder(type)
                        .field("ref", ref)
                        .build();

                assertEquals(type, detail.getType());
                assertEquals(ref, detail.getStringField("ref"));

                JSONObject jsonObject = detail.toJSONObject();
                assertEquals(type.getValue(), jsonObject.get("type"));
                assertEquals(ref, jsonObject.get("ref"));
                assertEquals(2, jsonObject.size());
        }


        public void testEmptyIdentifier() {

                AuthorizationType type = new AuthorizationType("payment_initiation");

                AuthorizationDetail detail = new AuthorizationDetail.Builder(type)
                        .field("identifier", "")
                        .build();

                assertNull(detail.getIdentifier());
        }


        public void testBlankIdentifier() {

                AuthorizationType type = new AuthorizationType("payment_initiation");

                AuthorizationDetail detail = new AuthorizationDetail.Builder(type)
                        .field("identifier", " ")
                        .build();

                assertNull(detail.getIdentifier());
        }


        public void testGetStringField_illegalValue() throws ParseException {

                String json =
                        "{" +
                        "  \"type\": \"payment_initiation\"," +
                        "  \"actions\": [" +
                        "     \"initiate\"," +
                        "     \"status\"," +
                        "     \"cancel\"" +
                        "  ]" +
                        "}";

                AuthorizationDetail detail = AuthorizationDetail.parse(JSONObjectUtils.parse(json));

                assertNull(detail.getStringField("actions"));
        }


        public void testGetJSONObjectField_illegalValue() throws ParseException {

                String json =
                        "{" +
                        "  \"type\": \"payment_initiation\"," +
                        "  \"actions\": [" +
                        "     \"initiate\"," +
                        "     \"status\"," +
                        "     \"cancel\"" +
                        "  ]" +
                        "}";

                AuthorizationDetail detail = AuthorizationDetail.parse(JSONObjectUtils.parse(json));

                assertNull(detail.getJSONObjectField("actions"));
        }


        // https://www.rfc-editor.org/rfc/rfc9396.html#figure-2
        public void testParse_exampleFigure2()
                throws ParseException {

                String json =
                        "{" +
                        "  \"type\": \"payment_initiation\"," +
                        "  \"actions\": [" +
                        "     \"initiate\"," +
                        "     \"status\"," +
                        "     \"cancel\"" +
                        "  ]," +
                        "  \"locations\": [" +
                        "     \"https://example.com/payments\"" +
                        "  ]," +
                        "  \"instructedAmount\": {" +
                        "     \"currency\": \"EUR\"," +
                        "     \"amount\": \"123.50\"" +
                        "  }," +
                        "  \"creditorName\": \"Merchant A\"," +
                        "  \"creditorAccount\": {" +
                        "     \"iban\": \"DE02100100109307118603\"" +
                        "  }," +
                        "  \"remittanceInformationUnstructured\": \"Ref Number Merchant\"" +
                        "}";

                AuthorizationDetail detail = AuthorizationDetail.parse(JSONObjectUtils.parse(json));

                assertEquals(new AuthorizationType("payment_initiation"), detail.getType());

                assertEquals(
                        Arrays.asList(new Action("initiate"), new Action("status"), new Action("cancel")),
                        detail.getActions()
                );

                assertEquals(
                        Collections.singletonList(new Location(URI.create("https://example.com/payments"))),
                        detail.getLocations()
                );

                JSONObject instructedAmount = new JSONObject();
                instructedAmount.put("currency", "EUR");
                instructedAmount.put("amount", "123.50");
                assertEquals(instructedAmount, detail.getJSONObjectField("instructedAmount"));
                assertEquals(instructedAmount, detail.getField("instructedAmount"));

                assertEquals("Merchant A", detail.getStringField("creditorName"));
                assertEquals("Merchant A", detail.getField("creditorName"));

                JSONObject creditorAccount = new JSONObject();
                creditorAccount.put("iban", "DE02100100109307118603");
                assertEquals(creditorAccount, detail.getJSONObjectField("creditorAccount"));
                assertEquals(creditorAccount, detail.getField("creditorAccount"));

                assertEquals("Ref Number Merchant", detail.getStringField("remittanceInformationUnstructured"));
                assertEquals("Ref Number Merchant", detail.getField("remittanceInformationUnstructured"));
        }


        // https://www.rfc-editor.org/rfc/rfc9396.html#figure-2
        public void testBuild_exampleFigure2()
                throws ParseException {

                String json =
                        "{" +
                        "  \"type\": \"payment_initiation\"," +
                        "  \"actions\": [" +
                        "     \"initiate\"," +
                        "     \"status\"," +
                        "     \"cancel\"" +
                        "  ]," +
                        "  \"locations\": [" +
                        "     \"https://example.com/payments\"" +
                        "  ]," +
                        "  \"instructedAmount\": {" +
                        "     \"currency\": \"EUR\"," +
                        "     \"amount\": \"123.50\"" +
                        "  }," +
                        "  \"creditorName\": \"Merchant A\"," +
                        "  \"creditorAccount\": {" +
                        "     \"iban\": \"DE02100100109307118603\"" +
                        "  }," +
                        "  \"remittanceInformationUnstructured\": \"Ref Number Merchant\"" +
                        "}";

                JSONObject instructedAmount = new JSONObject();
                instructedAmount.put("currency", "EUR");
                instructedAmount.put("amount", "123.50");

                JSONObject creditorAccount = new JSONObject();
                creditorAccount.put("iban", "DE02100100109307118603");

                AuthorizationDetail detail = new AuthorizationDetail.Builder(
                        new AuthorizationType("payment_initiation"))
                        .actions(Arrays.asList(
                                new Action("initiate"),
                                new Action("status"),
                                new Action("cancel")))
                        .locations(
                                Collections.singletonList(new Location(URI.create("https://example.com/payments"))))
                        .field("instructedAmount", instructedAmount)
                        .field("creditorName", "Merchant A")
                        .field("creditorAccount", creditorAccount)
                        .field("remittanceInformationUnstructured", "Ref Number Merchant")
                        .build();

                assertEquals(detail, AuthorizationDetail.parse(JSONObjectUtils.parse(json)));
        }


        public void testParse_missingType() {

                try {
                        AuthorizationDetail.parse(new JSONObject());
                        fail();
                } catch (ParseException e) {
                        assertEquals("Illegal or missing type", e.getMessage());
                }
        }


        public void testParse_illegalType() {

                JSONObject jsonObject = new JSONObject();
                jsonObject.put("type", 123); // must be string

                try {
                        AuthorizationDetail.parse(jsonObject);
                        fail();
                } catch (ParseException e) {
                        assertEquals("Illegal or missing type", e.getMessage());
                }
        }


        public void testParse_emptyType() {

                JSONObject jsonObject = new JSONObject();
                jsonObject.put("type", ""); // must be string

                try {
                        AuthorizationDetail.parse(jsonObject);
                        fail();
                } catch (ParseException e) {
                        assertEquals("Illegal or missing type", e.getMessage());
                }
        }


        public void testParse_blankType() {

                JSONObject jsonObject = new JSONObject();
                jsonObject.put("type", " "); // must be string

                try {
                        AuthorizationDetail.parse(jsonObject);
                        fail();
                } catch (ParseException e) {
                        assertEquals("Illegal or missing type", e.getMessage());
                }
        }
        
        
        
        public void testParseArray_exampleFigure9()
                throws ParseException {
                
                String json = "[" +
                        "   {" +
                        "      \"type\": \"account_information\"," +
                        "      \"actions\": [" +
                        "         \"list_accounts\"," +
                        "         \"read_balances\"," +
                        "         \"read_transactions\"" +
                        "      ]," +
                        "      \"locations\": [" +
                        "         \"https://example.com/accounts\"" +
                        "      ]" +
                        "   }," +
                        "   {" +
                        "      \"type\": \"payment_initiation\"," +
                        "      \"actions\": [" +
                        "         \"initiate\"," +
                        "         \"status\"," +
                        "         \"cancel\"" +
                        "      ]," +
                        "      \"locations\": [" +
                        "         \"https://example.com/payments\"" +
                        "      ]," +
                        "      \"instructedAmount\": {" +
                        "         \"currency\": \"EUR\"," +
                        "         \"amount\": \"123.50\"" +
                        "      }," +
                        "      \"creditorName\": \"Merchant A\"," +
                        "      \"creditorAccount\": {" +
                        "         \"iban\": \"DE02100100109307118603\"" +
                        "      }," +
                        "      \"remittanceInformationUnstructured\": \"Ref Number Merchant\"" +
                        "   }" +
                        "]";

                JSONArray jsonArray = JSONArrayUtils.parse(json);
                List<JSONObject> jsonObjectList = JSONArrayUtils.toJSONObjectList(jsonArray);

                List<AuthorizationDetail> details = AuthorizationDetail.parseList(jsonObjectList);

                assertEquals(2, details.size());

                AuthorizationDetail accountInformation = details.get(0);
                assertEquals(new AuthorizationType("account_information"), accountInformation.getType());
                assertEquals(
                        Arrays.asList(
                                new Action("list_accounts"),
                                new Action("read_balances"),
                                new Action("read_transactions")),
                        accountInformation.getActions()
                );
                assertEquals(Collections.singletonList(new Location("https://example.com/accounts")), accountInformation.getLocations());


                AuthorizationDetail paymentInitiation = details.get(1);
                assertEquals(new AuthorizationType("payment_initiation"), paymentInitiation.getType());
                assertEquals(
                        Arrays.asList(
                                new Action("initiate"),
                                new Action("status"),
                                new Action("cancel")),
                        paymentInitiation.getActions()
                );
                assertEquals(Collections.singletonList(new Location("https://example.com/payments")), paymentInitiation.getLocations());
                JSONObject instructedAmount = new JSONObject();
                instructedAmount.put("currency", "EUR");
                instructedAmount.put("amount", "123.50");
                assertEquals(instructedAmount, paymentInitiation.getJSONObjectField("instructedAmount"));
                assertEquals("Merchant A", paymentInitiation.getStringField("creditorName"));
                JSONObject creditorAccount = new JSONObject();
                creditorAccount.put("iban", "DE02100100109307118603");
                assertEquals(creditorAccount, paymentInitiation.getJSONObjectField("creditorAccount"));
                assertEquals("Ref Number Merchant", paymentInitiation.getStringField("remittanceInformationUnstructured"));
        }


        public void testArray_serialize_parse()
                throws ParseException {

                AuthorizationDetail detail_1 = new AuthorizationDetail.Builder(new AuthorizationType("api_1"))
                        .build();

                AuthorizationDetail detail_2 = new AuthorizationDetail.Builder(new AuthorizationType("api_2"))
                        .build();

                String json = AuthorizationDetail.toJSONString(Arrays.asList(detail_1, detail_2));

                assertEquals("[{\"type\":\"api_1\"},{\"type\":\"api_2\"}]", json);

                List<AuthorizationDetail> details = AuthorizationDetail.parseList(json);

                assertEquals(detail_1, details.get(0));
                assertEquals(detail_2, details.get(1));

                assertEquals(2, details.size());
        }


        public void testParseArray_empty()
                throws ParseException {

                assertTrue(AuthorizationDetail.parseList(Collections.<JSONObject>emptyList()).isEmpty());
        }


        public void testParseArray_illegalObjects()
                throws ParseException {

                String json = "[{},{}]";

                try {
                        AuthorizationDetail.parseList(json);
                        fail();
                } catch (ParseException e) {
                        assertEquals("Invalid authorization details: Invalid authorization detail at position 0: Illegal or missing type", e.getMessage());
                }

                JSONArray jsonArray = JSONArrayUtils.parse(json);
                List<JSONObject> jsonObjects = JSONArrayUtils.toJSONObjectList(jsonArray);

                try {
                        AuthorizationDetail.parseList(jsonObjects);
                        fail();
                } catch (ParseException e) {
                        assertEquals("Invalid authorization detail at position 0: Illegal or missing type", e.getMessage());
                }
        }


        public void testParseArray_illegalJSON() {

                try {
                        AuthorizationDetail.parseList("xxx");
                        fail();
                } catch (ParseException e) {
                        assertEquals("Invalid authorization details: Invalid JSON", e.getMessage());
                }
        }


        public void testInequality() {

                AuthorizationDetail detail_1 = new AuthorizationDetail.Builder(new AuthorizationType("account_information")).build();
                AuthorizationDetail detail_2 = new AuthorizationDetail.Builder(new AuthorizationType("payment_initiation")).build();

                assertNotSame(detail_1, detail_2);

                assertNotSame(detail_1, "abc");
        }
}
