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

package com.nimbusds.oauth2.sdk.rar;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.ListUtils;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * Authorisation detail.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396)
 * </ul>
 */
public class AuthorizationDetail {


        /**
         * Builder for constructing authorisation details.
         */
        public static class Builder {


                /**
                 * The authorisation details JSON object.
                 */
                private final JSONObject jsonObject = new JSONObject();


                /**
                 * Creates a new authorisation detail builder.
                 *
                 * @param type The authorisation type. Must not be
                 *             {@code null}.
                 */
                public Builder(final AuthorizationType type) {
                        jsonObject.put("type", type.getValue());
                }


                /**
                 * Sets the locations.
                 *
                 * @param locations The locations, {@code null} if not
                 *                  specified.
                 *
                 * @return This builder.
                 */
                public Builder locations(final List<Location> locations) {
                        if (locations != null) {
                                jsonObject.put("locations", Identifier.toStringList(locations));
                        } else {
                                jsonObject.remove("locations");
                        }
                        return this;
                }


                /**
                 * Sets the actions.
                 *
                 * @param actions The actions, {@code null} if not specified.
                 *
                 * @return This builder.
                 */
                public Builder actions(final List<Action> actions) {
                        if (actions != null) {
                                jsonObject.put("actions", Identifier.toStringList(actions));
                        } else {
                                jsonObject.remove("actions");
                        }
                        return this;
                }


                /**
                 * Sets the data types.
                 *
                 * @param dataTypes The data types, {@code null} if not
                 *                  specified.
                 *
                 * @return This builder.
                 */
                public Builder dataTypes(final List<DataType> dataTypes) {
                        if (dataTypes != null) {
                                jsonObject.put("datatypes", Identifier.toStringList(dataTypes));
                        } else {
                                jsonObject.remove("datatypes");
                        }
                        return this;
                }


                /**
                 * Sets the identifier.
                 *
                 * @param identifier The identifier, {@code null} if not
                 *                   specified.
                 *
                 * @return This builder.
                 */
                public Builder identifier(final Identifier identifier) {
                        if (identifier != null) {
                                jsonObject.put("identifier", identifier.getValue());
                        } else {
                                jsonObject.remove("identifier");
                        }
                        return this;
                }


                /**
                 * Sets the privileges.
                 *
                 * @param privileges The privileges, {@code null} if not
                 *                   specified.
                 *
                 * @return This builder.
                 */
                public Builder privileges(final List<Privilege> privileges) {
                        if (privileges != null) {
                                jsonObject.put("privileges", Identifier.toStringList(privileges));
                        } else {
                                jsonObject.remove("privileges");
                        }
                        return this;
                }


                /**
                 * Sets the specified authorisation detail field.
                 *
                 * @param name  The field name. Must not be {@code null}.
                 * @param value The field value, {@code null} if not specified.
                 *
                 * @return This builder.
                 */
                public Builder field(final String name, final Object value) {
                        if (value != null) {
                                jsonObject.put(name, value);
                        } else {
                                jsonObject.remove(name);
                        }
                        return this;
                }


                /**
                 * Builds a new authorisation detail.
                 *
                 * @return The authorisation detail.
                 */
                public AuthorizationDetail build() {
                        return new AuthorizationDetail(jsonObject);
                }
        }


        /**
         * The authorisation details JSON object.
         */
        private final JSONObject jsonObject;


        /**
         * Creates a new authorisation detail from the specified JSON object.
         *
         * @param jsonObject The JSON object. Must not be {@code null}.
         */
        private AuthorizationDetail(final JSONObject jsonObject) {
                this.jsonObject = Objects.requireNonNull(jsonObject);
        }


        /**
         * Returns the type.
         *
         * @return The type.
         */
        public AuthorizationType getType() {
                try {
                        return new AuthorizationType(JSONObjectUtils.getNonBlankString(jsonObject, "type"));
                } catch (Exception e) {
                        throw new RuntimeException(e);
                }
        }


        /**
         * Returns the locations.
         *
         * @return The locations as an unmodifiable list, {@code null} if not
         *         specified.
         */
        public List<Location> getLocations() {
                List<String> values = getStringListField("locations");
                if (values == null) {
                        return null;
                }
                List<Location> locations = new LinkedList<>();
                for (String v: ListUtils.removeNullItems(values)) {
                        locations.add(new Location(v));
                }
                return Collections.unmodifiableList(locations);
        }


        /**
         * Returns the actions.
         *
         * @return The actions as an unmodifiable list, {@code null} if not
         *         specified.
         */
        public List<Action> getActions() {
                List<String> values = getStringListField("actions");
                if (values == null) {
                        return null;
                }
                List<Action> actions = new LinkedList<>();
                for (String v: ListUtils.removeNullItems(values)) {
                        actions.add(new Action(v));
                }
                return Collections.unmodifiableList(actions);
        }


        /**
         * Returns the data types.
         *
         * @return The data type as an unmodifiable list, {@code null} if not
         *         specified.
         */
        public List<DataType> getDataTypes() {
                List<String> values = getStringListField("datatypes");
                if (values == null) {
                        return null;
                }
                List<DataType> dataTypes = new LinkedList<>();
                for (String v: ListUtils.removeNullItems(values)) {
                        dataTypes.add(new DataType(v));
                }
                return Collections.unmodifiableList(dataTypes);
        }


        /**
         * Returns the identifier.
         *
         * @return The identifier, {@code null} if not specified.
         */
        public Identifier getIdentifier() {
                String value;
                try {
                        value = JSONObjectUtils.getNonBlankString(jsonObject, "identifier");
                } catch (ParseException e) {
                        return null;
                }
                if (value.trim().isEmpty()) {
                        return null;
                }
                return new Identifier(value);
        }


        /**
         * Returns the privileges.
         *
         * @return The privileges as an unmodifiable list, {@code null} if not
         *         specified.
         */
        public List<Privilege> getPrivileges() {
                List<String> values = getStringListField("privileges");
                if (values == null) {
                        return null;
                }
                List<Privilege> privileges = new LinkedList<>();
                for (String v: ListUtils.removeNullItems(values)) {
                        privileges.add(new Privilege(v));
                }
                return Collections.unmodifiableList(privileges);
        }


        /**
         * Returns the field with the specified name.
         *
         * @param name The field name.
         *
         * @return The field value, {@code null} if not specified.
         */
        public Object getField(final String name) {
                return jsonObject.get(name);
        }


        /**
         * Returns the string field with the specified name.
         *
         * @param name The field name.
         *
         * @return The field value, {@code null} if not specified or parsing
         *         failed.
         */
        public String getStringField(final String name) {
                try {
                        return JSONObjectUtils.getNonBlankString(jsonObject, name);
                } catch (ParseException e) {
                        return null;
                }
        }


        /**
         * Returns the string list field with the specified name.
         *
         * @param name The field name.
         *
         * @return The field value, {@code null} if not specified or parsing
         *         failed.
         */
        public List<String> getStringListField(final String name) {
                try {
                        return JSONObjectUtils.getStringList(jsonObject, name);
                } catch (ParseException e) {
                        return null;
                }
        }


        /**
         * Returns the JSON object field with the specified name.
         *
         * @param name The field name.
         *
         * @return The field value, {@code null} if not specified or parsing
         *         failed.
         */
        public JSONObject getJSONObjectField(final String name) {
                try {
                        return JSONObjectUtils.getJSONObject(jsonObject, name);
                } catch (ParseException e) {
                        return null;
                }
        }


        /**
         * Returns a JSON object representation of this authorisation detail.
         *
         * @return The JSON object.
         */
        public JSONObject toJSONObject() {
                JSONObject o = new JSONObject();
                o.putAll(jsonObject);
                return o;
        }


        @Override
        public boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof AuthorizationDetail)) return false;
                AuthorizationDetail detail = (AuthorizationDetail) o;
                return Objects.equals(jsonObject, detail.jsonObject);
        }


        @Override
        public int hashCode() {
                return Objects.hash(jsonObject);
        }


        /**
         * Returns the JSON array representation of the specified authorisation
         * details.
         *
         * @param details The authorisation details. Must not be {@code null}.
         *
         * @return The JSON array.
         */
        public static JSONArray toJSONArray(final List<AuthorizationDetail> details) {
                JSONArray jsonArray = new JSONArray();
                for (AuthorizationDetail detail : details) {
                        jsonArray.add(detail.toJSONObject());
                }
                return jsonArray;
        }


        /**
         * Returns the JSON array string representation of the specified
         * authorisation details.
         *
         * @param details The authorisation details. Must not be {@code null}.
         *
         * @return The JSON string.
         */
        public static String toJSONString(final List<AuthorizationDetail> details) {
                return toJSONArray(details).toJSONString();
        }


        /**
         * Parses an authorisation detail from the specified JSON object.
         *
         * @param jsonObject The JSON object. Must not be {@code null}.
         *
         * @return The authorisation detail.
         *
         * @throws ParseException If parsing failed.
         */
        public static AuthorizationDetail parse(final JSONObject jsonObject)
                throws ParseException {

                AuthorizationDetail detail = new AuthorizationDetail(jsonObject);

                // Verify a type is present
                try {
                        detail.getType();
                } catch (Exception e) {
                        throw new ParseException("Illegal or missing type");
                }

                return detail;
        }


        /**
         * Parses an authorisation details list from the specified JSON objects
         * list.
         *
         * @param jsonObjects The JSON objects list. Must not be {@code null}.
         *
         * @return The authorisation details, as unmodifiable list.
         *
         * @throws ParseException If parsing failed.
         */
        public static List<AuthorizationDetail> parseList(final List<JSONObject> jsonObjects)
                throws ParseException {

                List<AuthorizationDetail> details = new LinkedList<>();

                int i=0;
                for (JSONObject jsonObject: ListUtils.removeNullItems(jsonObjects)) {

                        AuthorizationDetail detail;
                        try {
                                detail = parse(jsonObject);
                        } catch (ParseException e) {
                                throw new ParseException("Invalid authorization detail at position " + i + ": " + e.getMessage());
                        }
                        details.add(detail);
                }

                return Collections.unmodifiableList(details);
        }


        /**
         * Parses an authorisation details list from the specified JSON array
         * string.
         *
         * @param json The JSON string. Must not be {@code null}.
         *
         * @return The authorisation details, as unmodifiable list.
         *
         * @throws ParseException If parsing failed.
         */
        public static List<AuthorizationDetail> parseList(final String json)
                throws ParseException {

                try {
                        JSONArray jsonArray = JSONArrayUtils.parse(json);
                        List<JSONObject> jsonObjects = JSONArrayUtils.toJSONObjectList(jsonArray);
                        return parseList(jsonObjects);
                } catch (ParseException e) {
                        throw new ParseException("Invalid authorization details: " + e.getMessage());
                }
        }
}
