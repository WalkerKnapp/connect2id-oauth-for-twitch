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

package com.nimbusds.oauth2.sdk.util;


import java.util.*;


/**
 * Multi-valued map utilities.
 */
public final class MultivaluedMapUtils {
	
	
	/**
	 * Converts the specified multi-valued map to a single-valued map by
	 * taking the first value in the list.
	 *
	 * @param map The multi-valued map, {@code null} if not specified.
	 *
	 * @return The single-valued map, {@code null} if no map was specified.
	 */
	public static <K,V> Map<K,V> toSingleValuedMap(final Map<K,List<V>> map) {
		
		if (map == null)
			return null;
		
		Map<K,V> out = new HashMap<>();
		
		for (Map.Entry<K,List<V>> en: map.entrySet()) {
			
			if (en.getValue() == null || en.getValue().isEmpty()) {
				out.put(en.getKey(), null);
			} else {
				out.put(en.getKey(), en.getValue().get(0));
			}
		}
		
		return out;
	}
	
	
	/**
	 * Gets the first value for the specified key.
	 *
	 * @param map The multi-valued map. Must not be {@code null}.
	 * @param key The key. Must not be {@code null}.
	 *
	 * @return The first value, {@code null} if not set.
	 */
	public static <K,V> V getFirstValue(final Map<K,List<V>> map, final K key) {
		
		List<V> valueList = map.get(key);
		
		if (valueList == null || valueList.isEmpty()) {
			return null;
		}
		
		return valueList.get(0);
	}
	
	
	/**
	 * Removes the entry for the specified key and returns its first value.
	 *
	 * @param map The multi-valued map. Must not be {@code null}.
	 * @param key The key. Must not be {@code null}.
	 *
	 * @return The first value, {@code null} if not set.
	 */
	public static <K,V> V removeAndReturnFirstValue(final Map<K,List<V>> map, final String key) {
		
		List<V> valueList = map.remove(key);
		
		if (valueList == null || valueList.isEmpty()) {
			return null;
		}
		
		return valueList.get(0);
	}
	
	
	/**
	 * Returns the keys with more than one distinct value. Keys that map to
	 * two or more identical values are treated as single-valued.
	 *
	 * @param map      The multi-valued map, {@code null} if not specified.
	 * @param excepted The excepted keys, {@code null} or empty if none.
	 *
	 * @return The keys with more than one distinct value, empty set if
	 *         none.
	 */
	public static <K,V> Set<K> getKeysWithMoreThanOneValue(final Map<K,List<V>> map, final Set<K> excepted) {
		
		if (MapUtils.isEmpty(map)) {
			return Collections.emptySet();
		}
		
		Set<K> found = new HashSet<>();
		for (Map.Entry<K,List<V>> en: map.entrySet()) {
			
			if (CollectionUtils.contains(excepted, en.getKey())) {
				continue;
			}
			
			Set<V> entryValues = new HashSet<>(en.getValue());
			
			if (CollectionUtils.isNotEmpty(entryValues) && entryValues.size() > 1) {
				found.add(en.getKey());
			}
		}
		return found;
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private MultivaluedMapUtils() {}
}
