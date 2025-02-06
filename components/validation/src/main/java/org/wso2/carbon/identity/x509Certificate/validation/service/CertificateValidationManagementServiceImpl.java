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

import org.wso2.carbon.identity.certificate.management.exception.CertificateMgtException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage;
import org.wso2.carbon.identity.x509Certificate.validation.exception.X509ConfigurationException;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.CertObject;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.util.X509ConfigurationExceptionHandler;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCES_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.addCertificateInConfigurationStore;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.deleteCACertificateFromCertificateManager;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.deleteCertificateInConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCertificateFromConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCertificateListFromConfigurationStore;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getNormalizedName;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getValidatorFromConfigStoreByName;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getValidatorsFromConfigStore;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.updateCACertificateInCertificateManager;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.updateCertificateInConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.updateValidatorInConfigStore;

/**
 * This implementation handles the x509 authenticator validator manager implementation.
 */
public class CertificateValidationManagementServiceImpl implements CertificateValidationManagementService {

    @Override
    public List<Validator> getValidators(String tenantDomain) throws X509ConfigurationException {

        try {
            return getValidatorsFromConfigStore(tenantDomain);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCES_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_NO_VALIDATORS_CONFIGURED_ON_TENANT, tenantDomain);
            } else {
                throw X509ConfigurationExceptionHandler
                        .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATORS, e);
            }
        }
    }

    @Override
    public Validator getValidator(String name, String tenantDomain) throws X509ConfigurationException {

        try {
            Validator validator = getValidatorFromConfigStoreByName(tenantDomain, name);
            if (validator == null) {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, name, tenantDomain);
            } else {
                return validator;
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATOR_BY_NAME, e);
        }
    }

    @Override
    public Validator updateValidator(Validator validator, String tenantDomain) throws X509ConfigurationException {

        try {
            Validator updatedValidator = updateValidatorInConfigStore(tenantDomain, validator);
            if (updatedValidator == null) {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, validator.getName(),
                                tenantDomain);
            } else {
                return updatedValidator;
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_UPDATING_VALIDATOR, e);
        }
    }

    @Override
    public List<CACertificateInfo> getCACertificates(String tenantDomain) throws X509ConfigurationException {

        try {
            List<CACertificateInfo> caCertificateInfoList = getCertificateListFromConfigurationStore(tenantDomain);
            if (caCertificateInfoList == null || caCertificateInfoList.isEmpty()) {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_NO_CA_CERTIFICATES_CONFIGURED_ON_TENANT,
                                tenantDomain);
            }
            return getCertificateListFromConfigurationStore(tenantDomain);
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATES, e);
        }
    }

    @Override
    public CACertificate addCACertificate(X509Certificate caCertificate, String tenantDomain)
            throws X509ConfigurationException {

        try {
            CertObject certObject = addCertificateInConfigurationStore(tenantDomain, caCertificate);
            return new CACertificate(certObject.getCrlUrls(), certObject.getOcspUrls(), caCertificate);
        } catch (CertificateValidationException | CertificateException | CertificateMgtException e) {
            throw X509ConfigurationExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public CACertificateInfo getCaCertificate(String certificateId, String tenantDomain)
            throws X509ConfigurationException {

        try {
            CACertificate caCertificate =
                    getCertificateFromConfigurationStoreByCertificateId(tenantDomain, certificateId);
            if (caCertificate == null) {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            } else {
                CACertificateInfo caCertificateInfo = new CACertificateInfo();
                caCertificateInfo.setCertId(certificateId);
                caCertificateInfo.setIssuerDN(getNormalizedName(caCertificate
                        .getX509Certificate().getIssuerDN().getName()));
                caCertificateInfo.setSerialNumber(getNormalizedName(caCertificate.getX509Certificate()
                        .getSerialNumber().toString()));
                caCertificateInfo.setCrlUrls(caCertificate.getCrlUrl());
                caCertificateInfo.setOcspUrls(caCertificate.getOcspUrl());
                return caCertificateInfo;
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATE_BY_ID, e);
        }
    }

    @Override
    public CACertificateInfo updateCACertificate(String certificateId, X509Certificate certificate, String tenantDomain)
            throws X509ConfigurationException {

        try {
            CertObject certObject =
                    updateCertificateInConfigurationStoreByCertificateId(certificateId, certificate, tenantDomain);
            if (certObject == null) {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
            X509Certificate updatedCertificate = updateCACertificateInCertificateManager(certificateId,
                    certificate, tenantDomain);
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certificateId);
            caCertificateInfo.setIssuerDN(getNormalizedName(updatedCertificate.getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(updatedCertificate.getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(certObject.getCrlUrls());
            caCertificateInfo.setOcspUrls(certObject.getOcspUrls());
            return caCertificateInfo;
        } catch (CertificateValidationException | CertificateException | CertificateMgtException e) {
            throw X509ConfigurationExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_UPDATING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public void deleteCACertificate(String certificateId, String tenantDomain) throws X509ConfigurationException {

        try {
            CertObject certObject = deleteCertificateInConfigurationStoreByCertificateId(certificateId, tenantDomain);
            if (certObject != null) {
                deleteCACertificateFromCertificateManager(certificateId, tenantDomain);
            } else {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_DELETING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public void addDefaultValidationConfigInRegistry(String tenantDomain) {

        addDefaultValidationConfigInRegistry(tenantDomain);
    }

    @Override
    public void loadCRLDownloadTimeoutFromConfig() {

        loadCRLDownloadTimeoutFromConfig();
    }
}
