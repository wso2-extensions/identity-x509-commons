/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.carbon.identity.x509Certificate.validation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.wso2.carbon.identity.x509Certificate.validation.model.IssuerDNMap;

/**
 * Utility class to serialize and deserialize model objects.
 */
public class ModelSerializer {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static String serializeIssuerDNMap(IssuerDNMap issuerDNMap) throws JsonProcessingException {

        return objectMapper.writeValueAsString(issuerDNMap);
    }

    public static IssuerDNMap deserializeIssuerDNMap(String json) throws JsonProcessingException {

        return objectMapper.readValue(json, IssuerDNMap.class);
    }
}
