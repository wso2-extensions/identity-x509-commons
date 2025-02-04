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
 */

package org.wso2.carbon.identity.x509Certificate.validation.service;

import org.wso2.carbon.identity.x509Certificate.validation.exception.X509ConfigurationException;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;

import java.util.List;

/**
 * This interface supports the x509 authenticator validator manager.
 */
public interface X509AuthenticatorValidatorManager {

    /**
     * Add validator.
     *
     * @param validator Validator.
     * @param tenantId Tenant Id.
     * @return Added validator.
     * @throws X509ConfigurationException If an error occurs while adding the validator.
     */
    Validator addValidator(Validator validator, int tenantId) throws X509ConfigurationException;

    /**
     * Get validators.
     * @param tenantId Tenant Id.
     * @return List of validators.
     * @throws X509ConfigurationException If an error occurs while getting the validators.
     */
    List<Validator> getValidators(int tenantId) throws X509ConfigurationException;

    /**
     * Get the validator by name.
     *
     * @param name Name of the validator.
     * @param tenantId Tenant Id.
     * @return Validator.
     * @throws X509ConfigurationException If an error occurs while getting the validator.
     */
    Validator getValidator(String name, int tenantId) throws X509ConfigurationException;

    /**
     * Update the validator.
     *
     * @param validator Validator.
     * @param tenantId Tenant Id.
     * @return Updated validator.
     * @throws X509ConfigurationException If an error occurs while updating the validator.
     */
    Validator updateValidator(Validator validator, int tenantId) throws X509ConfigurationException;
}
