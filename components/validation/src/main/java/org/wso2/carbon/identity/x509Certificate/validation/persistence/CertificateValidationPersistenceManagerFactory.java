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

package org.wso2.carbon.identity.x509Certificate.validation.persistence;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.impl.HybridCertificateValidationPersistenceManager;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.impl.JDBCCertificateValidationPersistenceManager;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.impl.RegistryCertificateValidationPersistenceManager;

/**
 * Factory class to get the CertificateValidationPersistenceManager based on the configuration.
 */
public class CertificateValidationPersistenceManagerFactory {

    private static final Log LOG = LogFactory.getLog(CertificateValidationPersistenceManagerFactory.class);
    private static final String X509_CERTIFICATE_STORAGE_TYPE =
            IdentityUtil.getProperty("DataStorageType.CertificateValidation");
    private static final String REGISTRY = "registry";
    private static final String HYBRID = "hybrid";
    private static final String DATABASE = "database";

    private CertificateValidationPersistenceManagerFactory() {

    }

    public static CertificateValidationPersistenceManager getX509CertificatePersistenceManager() {

        if (LOG.isDebugEnabled()) {
            LOG.debug("x509 certificate storage type is set to: " + X509_CERTIFICATE_STORAGE_TYPE);
        }

        CertificateValidationPersistenceManager certificateValidationPersistenceManager;
        if (REGISTRY.equals(X509_CERTIFICATE_STORAGE_TYPE)) {
            LOG.warn("Registry based KeyStore persistence manager was initialized");
            certificateValidationPersistenceManager = new RegistryCertificateValidationPersistenceManager();
        } else if (HYBRID.equals(X509_CERTIFICATE_STORAGE_TYPE)) {
            LOG.info("Hybrid KeyStore persistence manager was initialized");
            certificateValidationPersistenceManager = new HybridCertificateValidationPersistenceManager();
        } else {
            certificateValidationPersistenceManager = new JDBCCertificateValidationPersistenceManager();
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("KeyStore Persistence Manager initialized with the type: " +
                    certificateValidationPersistenceManager.getClass());
        }
        return certificateValidationPersistenceManager;
    }
}
