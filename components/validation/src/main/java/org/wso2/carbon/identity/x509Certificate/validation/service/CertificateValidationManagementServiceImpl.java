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

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCES_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.addCertificateInConfigurationStore;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.decodeCertificate;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.deleteCACertificateFromCertificateManager;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.deleteCertificateInConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCACertificateInfo;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCertificateFromConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCertificateListFromConfigurationStore;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getNormalizedName;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getValidatorFromConfigStoreByName;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getValidatorsFromConfigStore;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.updateCACertificateInCertificateManager;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.updateCertificateInConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.updateValidatorInConfigStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.wso2.carbon.identity.certificate.management.exception.CertificateMgtException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.CertObject;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.util.CertificateValidationManagementExceptionHandler;

/**
 * This implementation handles the x509 authenticator validator manager implementation.
 */
public class CertificateValidationManagementServiceImpl implements CertificateValidationManagementService {

    @Override
    public List<Validator> getValidators(String tenantDomain) throws CertificateValidationManagementException {

        try {
            return getValidatorsFromConfigStore(tenantDomain);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCES_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return new ArrayList<>();
            }
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATORS, e);
        }
    }

    @Override
    public Validator getValidator(String name, String tenantDomain) throws CertificateValidationManagementException {

        try {
            name = name.toLowerCase();
            Optional<Validator> validator = getValidatorFromConfigStoreByName(tenantDomain, name);

            if (!validator.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, name, tenantDomain);
            }
            return validator.get();
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATOR_BY_NAME, e);
        }
    }

    @Override
    public Validator updateValidator(Validator validator, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<Validator> updatedValidator = updateValidatorInConfigStore(tenantDomain, validator);
            if (!updatedValidator.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, validator.getName(),
                                tenantDomain);
            }
            return updatedValidator.get();
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_UPDATING_VALIDATOR, e);
        }
    }

    @Override
    public List<CACertificateInfo> getCACertificates(String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<List<CACertificateInfo>> caCertificateInfoList =
                    getCertificateListFromConfigurationStore(tenantDomain);
            return caCertificateInfoList.orElseGet(ArrayList::new);
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATES, e);
        }
    }

    @Override
    public CACertificateInfo addCACertificate(String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            X509Certificate caCertificate = decodeCertificate(encodedCertificate);
            Optional<CertObject> certObject = addCertificateInConfigurationStore(tenantDomain, caCertificate);
            if (!certObject.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_NO_CA_CERTIFICATES_CONFIGURED_ON_TENANT,
                                tenantDomain);
            }
            return getCACertificateInfo(caCertificate, certObject.get());
        } catch (CertificateValidationException | CertificateException | CertificateMgtException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public CACertificateInfo getCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<CACertificate> caCertificate =
                    getCertificateFromConfigurationStoreByCertificateId(tenantDomain, certificateId);
            if (!caCertificate.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certificateId);
            caCertificateInfo.setIssuerDN(getNormalizedName(caCertificate.get()
                    .getX509Certificate().getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(caCertificate.get().getX509Certificate()
                    .getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(caCertificate.get().getCrlUrl());
            caCertificateInfo.setOcspUrls(caCertificate.get().getOcspUrl());
            return caCertificateInfo;
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATE_BY_ID, e);
        }
    }

    @Override
    public CACertificateInfo updateCACertificate(String certificateId, String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            X509Certificate certificate = decodeCertificate(encodedCertificate);
            Optional<CertObject> certObject =
                    updateCertificateInConfigurationStoreByCertificateId(certificateId, certificate, tenantDomain);
            if (!certObject.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
            X509Certificate updatedCertificate = updateCACertificateInCertificateManager(certificateId,
                    certificate, tenantDomain);
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certificateId);
            caCertificateInfo.setIssuerDN(getNormalizedName(updatedCertificate.getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(updatedCertificate.getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(certObject.get().getCrlUrls());
            caCertificateInfo.setOcspUrls(certObject.get().getOcspUrls());
            return caCertificateInfo;
        } catch (CertificateValidationException | CertificateException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_UPDATING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public void deleteCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<CertObject> certObject =
                    deleteCertificateInConfigurationStoreByCertificateId(certificateId, tenantDomain);
            if (certObject.isPresent()) {
                deleteCACertificateFromCertificateManager(certificateId, tenantDomain);
            } else {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_DELETING_CA_CERTIFICATE, e);
        }
    }
}
