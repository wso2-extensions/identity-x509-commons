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

import java.util.List;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.CertificateValidationPersistenceManager;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.CertificateValidationPersistenceManagerFactory;

/**
 * This implementation handles the certificate validation management operations.
 */
public class CertificateValidationManagementServiceImpl implements CertificateValidationManagementService {


    private static final CertificateValidationPersistenceManager certificateValidationPersistenceManager =
            CertificateValidationPersistenceManagerFactory.getX509CertificatePersistenceManager();

    @Override
    public List<Validator> getValidators(String tenantDomain) throws CertificateValidationManagementException {

        return certificateValidationPersistenceManager.getValidators(tenantDomain);
    }

    @Override
    public Validator getValidator(String name, String tenantDomain) throws CertificateValidationManagementException {

        return certificateValidationPersistenceManager.getValidator(name, tenantDomain);
    }

    @Override
    public Validator updateValidator(Validator validator, String tenantDomain)
            throws CertificateValidationManagementException {

        return certificateValidationPersistenceManager.updateValidator(validator, tenantDomain);
    }

    @Override
    public List<CACertificateInfo> getCACertificates(String tenantDomain)
            throws CertificateValidationManagementException {

        return certificateValidationPersistenceManager.getCACertificates(tenantDomain);
    }

    @Override
    public CACertificateInfo addCACertificate(String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        return certificateValidationPersistenceManager.addCACertificate(encodedCertificate, tenantDomain);
    }

    @Override
    public CACertificateInfo getCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        return certificateValidationPersistenceManager.getCACertificate(certificateId, tenantDomain);
    }

    @Override
    public CACertificateInfo updateCACertificate(String certificateId, String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        return certificateValidationPersistenceManager.updateCACertificate(certificateId, encodedCertificate,
                tenantDomain);
    }

    @Override
    public void deleteCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        certificateValidationPersistenceManager.deleteCACertificate(certificateId, tenantDomain);
    }
}
