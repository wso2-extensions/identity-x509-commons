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

import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.exception.X509ConfigurationException;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.util.X509ConfigurationExceptionHandler;

import java.util.List;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCES_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getNormalizedName;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.startTenantFlow;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.buildResourceFromValidator;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.addResource;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getValidatorsFromConfigStore;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getValidatorFromConfigStoreByName;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.updateValidatorInConfigStore;


/**
 * This implementation handles the x509 authenticator validator manager implementation.
 */
public class X509AuthenticatorValidatorManagerImpl implements X509AuthenticatorValidatorManager {

    @Override
    public Validator addValidator(Validator validator, int tenantId) throws X509ConfigurationException {

        try {
            startTenantFlow(tenantId);
            org.wso2.carbon.identity.configuration.mgt.core.model.Resource validatorResource =
                    buildResourceFromValidator(validator, getNormalizedName(validator.getDisplayName()));
            return addResource(validatorResource);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_ALREADY_EXISTS.getCode().equals(e.getErrorCode())) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_VALIDATOR_ALREADY_EXISTS);
            } else {
                throw X509ConfigurationExceptionHandler.handleServerException
                        (ErrorMessage.ERROR_WHILE_ADDING_VALIDATOR, e);
            }
        }
    }

    @Override
    public List<Validator> getValidators(int tenantId) throws X509ConfigurationException {

        try {
            return getValidatorsFromConfigStore(tenantId);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCES_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_NO_VALIDATORS_CONFIGURED_ON_TENANT);
            } else {
                throw X509ConfigurationExceptionHandler.handleServerException
                        (ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATORS, e);
            }
        }
    }

    @Override
    public Validator getValidator(String name, int tenantId) throws X509ConfigurationException {

        try {
            Validator validator = getValidatorFromConfigStoreByName(tenantId, name);
            if (validator == null) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_INVALID_VALIDATOR_TYPE);
            } else {
                return validator;
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATOR_BY_NAME, e);
        }
    }

    @Override
    public Validator updateValidator(Validator validator, int tenantId) throws X509ConfigurationException {

        try {
            startTenantFlow(tenantId);
            Validator updatedValidator = updateValidatorInConfigStore(tenantId, validator);
            if (updatedValidator == null) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_INVALID_VALIDATOR_TYPE);
            } else {
                return updatedValidator;
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_UPDATING_VALIDATOR, e);
        }
    }
}
