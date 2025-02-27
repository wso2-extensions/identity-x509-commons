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

package org.wso2.carbon.identity.x509Certificate.validation.persistence.impl;

import static org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST;
import static org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage.ERROR_INVALID_VALIDATOR_NAME;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.CertificateValidationPersistenceManager;

/**
 * HybridCertificateValidationPersistenceManager is a hybrid implementation of CertificateValidationPersistenceManager
 * which uses both JDBC and Registry based persistence managers.
 */
public class HybridCertificateValidationPersistenceManager implements CertificateValidationPersistenceManager {

    private static final Log LOG = LogFactory.getLog(HybridCertificateValidationPersistenceManager.class);
    private final JDBCCertificateValidationPersistenceManager jdbcCertificateValidationPersistenceManager =
            new JDBCCertificateValidationPersistenceManager();
    private final RegistryCertificateValidationPersistenceManager registryCertificateValidationPersistenceManager =
            new RegistryCertificateValidationPersistenceManager();

    @Override
    public void addValidators(List<Validator> validators, String tenatDomain)
            throws CertificateValidationManagementException {

        List<Validator> existingValidators = registryCertificateValidationPersistenceManager.getValidators(tenatDomain);
        if (existingValidators.isEmpty()) {
            jdbcCertificateValidationPersistenceManager.addValidators(validators, tenatDomain);
        }
    }

    @Override
    public void addCACertificates(List<Validator> validators, List<X509Certificate> trustedCertificates,
                                  String tenantDomain) throws CertificateValidationManagementException {

        jdbcCertificateValidationPersistenceManager.addCACertificates(validators, trustedCertificates,
                tenantDomain);
    }

    @Override
    public List<CACertificate> getCACertsByIssuer(String issuerDN, String tenantDomain)
            throws CertificateValidationManagementException {

        List<CACertificate> caCertificates =
                jdbcCertificateValidationPersistenceManager.getCACertsByIssuer(issuerDN, tenantDomain);
        caCertificates.addAll(
                registryCertificateValidationPersistenceManager.getCACertsByIssuer(issuerDN, tenantDomain));
        return caCertificates;
    }

    @Override
    public List<Validator> getValidators(String tenantDomain) throws CertificateValidationManagementException {

        List<Validator> validators = jdbcCertificateValidationPersistenceManager.getValidators(tenantDomain);
        if (validators.isEmpty()) {
            validators = registryCertificateValidationPersistenceManager.getValidators(tenantDomain);
        }
        return validators;
    }

    @Override
    public Validator getValidator(String name, String tenantDomain) throws CertificateValidationManagementException {

        try {
            return jdbcCertificateValidationPersistenceManager.getValidator(name, tenantDomain);
        } catch (CertificateValidationManagementException e) {
            if (ERROR_INVALID_VALIDATOR_NAME.getCode().equals(e.getErrorCode())) {
                return registryCertificateValidationPersistenceManager.getValidator(name, tenantDomain);
            } else {
                throw e;
            }
        }
    }

    @Override
    public Validator updateValidator(Validator validator, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            return jdbcCertificateValidationPersistenceManager.updateValidator(validator, tenantDomain);
        } catch (CertificateValidationManagementException e) {
            if (ERROR_INVALID_VALIDATOR_NAME.getCode().equals(e.getErrorCode())) {
                return registryCertificateValidationPersistenceManager.updateValidator(validator, tenantDomain);
            } else {
                throw e;
            }
        }
    }

    @Override
    public List<CACertificateInfo> getCACertificates(String tenantDomain)
            throws CertificateValidationManagementException {

        List<CACertificateInfo> caCertificates = new ArrayList<>();
        Set<String> uniqueCertIds = new HashSet<>();

        try {
            caCertificates.addAll(jdbcCertificateValidationPersistenceManager.getCACertificates(tenantDomain));
        } catch (CertificateValidationManagementException e) {
            LOG.debug("Error occurred while getting CA certificates from JDBC persistence manager.", e);
        }

        try {
            caCertificates.addAll(registryCertificateValidationPersistenceManager.getCACertificates(tenantDomain));
        } catch (CertificateValidationManagementException e) {
            LOG.debug("Error occurred while getting CA certificates from Registry persistence manager.", e);
        }

        List<CACertificateInfo> uniqueCACertificates = new ArrayList<>();
        for (CACertificateInfo certInfo : caCertificates) {
            if (uniqueCertIds.add(certInfo.getCertId())) {
                uniqueCACertificates.add(certInfo);
            }
        }

        return uniqueCACertificates;
    }

    @Override
    public CACertificateInfo addCACertificate(String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        return jdbcCertificateValidationPersistenceManager.addCACertificate(encodedCertificate, tenantDomain);
    }

    @Override
    public CACertificateInfo getCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            return jdbcCertificateValidationPersistenceManager.getCACertificate(certificateId, tenantDomain);
        } catch (CertificateValidationManagementException e) {
            if (ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                return registryCertificateValidationPersistenceManager.getCACertificate(certificateId, tenantDomain);
            }
            throw e;
        }
    }

    @Override
    public CACertificateInfo updateCACertificate(String certificateId, String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            return jdbcCertificateValidationPersistenceManager.updateCACertificate(certificateId, encodedCertificate,
                    tenantDomain);
        } catch (CertificateValidationManagementException e) {
            try {
                return registryCertificateValidationPersistenceManager.updateCACertificate(certificateId,
                        encodedCertificate, tenantDomain);
            } catch (CertificateValidationManagementException ex) {
                if (ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                    throw e;
                }
                throw ex;
            }
        }
    }

    @Override
    public void deleteCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            jdbcCertificateValidationPersistenceManager.deleteCACertificate(certificateId, tenantDomain);
        } catch (CertificateValidationManagementException e) {
            if (ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                registryCertificateValidationPersistenceManager.deleteCACertificate(certificateId, tenantDomain);
            } else {
                throw e;
            }
        }
    }
}
