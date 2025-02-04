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

import com.fasterxml.jackson.core.JsonProcessingException;
import org.wso2.carbon.identity.certificate.management.exception.CertificateMgtException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.exception.X509ConfigurationException;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.CertObject;
import org.wso2.carbon.identity.x509Certificate.validation.util.X509ConfigurationExceptionHandler;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getNormalizedName;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.startTenantFlow;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.endTenantFlow;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.addCertificateInConfigurationStore;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.addCertificateListInConfigurationStore;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getCertificateListFromConfigurationStore;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getCertificateFromConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getCACertsFromConfigStore;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.updateCertificateInConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.deleteCertificateInConfigurationStoreByCertificateId;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.deleteCACertificateFromCertificateManager;
import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.updateCACertificateInCertificateManager;


/**
 * This implementation handles the x509 authenticator certificate configurations.
 */
public class X509AuthenticatorCertificateManagerImpl implements X509AuthenticatorCertificateManager {

    @Override
    public List<CACertificateInfo> getCACertificates(int tenantId) throws X509ConfigurationException {

        try {
            List<CACertificateInfo> caCertificateInfoList = getCertificateListFromConfigurationStore(tenantId);
            if (caCertificateInfoList == null || caCertificateInfoList.isEmpty()) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_NO_CA_CERTIFICATES_CONFIGURED_ON_TENANT);
            }
            return getCertificateListFromConfigurationStore(tenantId);
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATES, e);
        }
    }

    @Override
    public CACertificate addCACertificate(X509Certificate caCertificate, int tenantId)
            throws X509ConfigurationException {

        try {
            startTenantFlow(tenantId);
            CertObject certObject = addCertificateInConfigurationStore(tenantId, caCertificate);
            return new CACertificate(certObject.getCrlUrls(), certObject.getOcspUrls(), caCertificate);
        } catch (CertificateValidationException | CertificateException | CertificateMgtException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATE, e);
        } finally {
            endTenantFlow();
        }
    }

    @Override
    public void addCACertificateList(List<X509Certificate> caCertificateList, int tenantId)
            throws X509ConfigurationException {

        try {
            startTenantFlow(tenantId);
            addCertificateListInConfigurationStore(caCertificateList, tenantId);
        } catch (CertificateValidationException | CertificateException | CertificateMgtException |
                 JsonProcessingException | ConfigurationManagementException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATE, e);
        } finally {
            endTenantFlow();
        }
    }

    @Override
    public CACertificateInfo getCaCertificate(String certificateId, int tenantId) throws X509ConfigurationException {

        try {
            CACertificate caCertificate = getCertificateFromConfigurationStoreByCertificateId(tenantId, certificateId);
            if (caCertificate == null) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST);
            } else {
                CACertificateInfo caCertificateInfo = new CACertificateInfo();
                caCertificateInfo.setCertId(certificateId);
                caCertificateInfo.setIssuerDN(getNormalizedName(caCertificate.getX509Certificate()
                        .getIssuerDN().getName()));
                caCertificateInfo.setSerialNumber(getNormalizedName(caCertificate.getX509Certificate()
                        .getSerialNumber().toString()));
                caCertificateInfo.setCrlUrls(caCertificate.getCrlUrl());
                caCertificateInfo.setOcspUrls(caCertificate.getOcspUrl());
                return caCertificateInfo;
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATE_BY_ID, e);
        }
    }

    @Override
    public List<CACertificate> getCaCertificatesByIssuer(String issuer, int tenantId)
            throws X509ConfigurationException {

        try {
            List<CACertificate> caCertificates = getCACertsFromConfigStore(issuer, tenantId);
            if (caCertificates == null || caCertificates.isEmpty()) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_NO_CA_CERTIFICATES_CONFIGURED_ON_ISSUER);
            } else {
                return caCertificates;
            }
        } catch (ConfigurationManagementException | CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATES, e);
        }
    }

    @Override
    public CACertificateInfo updateCACertificate(String certificateId, X509Certificate certificate, int tenantId)
            throws X509ConfigurationException {

        try {
            startTenantFlow(tenantId);
            CertObject certObject = updateCertificateInConfigurationStoreByCertificateId
                    (certificateId, certificate, tenantId);
            if (certObject == null) {
                throw X509ConfigurationExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST);
            }
            X509Certificate updatedCertificate = updateCACertificateInCertificateManager(certificateId, certificate,
                    IdentityTenantUtil.getTenantDomain(tenantId));
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certificateId);
            caCertificateInfo.setIssuerDN(getNormalizedName(updatedCertificate.getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(updatedCertificate.getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(certObject.getCrlUrls());
            caCertificateInfo.setOcspUrls(certObject.getOcspUrls());
            return caCertificateInfo;
        } catch (CertificateValidationException | CertificateException | CertificateMgtException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_UPDATING_CA_CERTIFICATE, e);
        } finally {
            endTenantFlow();
        }
    }

    @Override
    public void deleteCACertificate(String certificateId, int tenantId) throws X509ConfigurationException {

        try {
            startTenantFlow(tenantId);
            CertObject certObject = deleteCertificateInConfigurationStoreByCertificateId(certificateId, tenantId);
            if (certObject != null) {
                deleteCACertificateFromCertificateManager(certificateId, IdentityTenantUtil.getTenantDomain(tenantId));
            } else {
                throw X509ConfigurationExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST);
            }
        } catch (CertificateValidationException e) {
            throw X509ConfigurationExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_DELETING_CA_CERTIFICATE, e);
        } finally {
            endTenantFlow();
        }
    }
}
