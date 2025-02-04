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
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This interface handles the CA certificate configurations.
 */
public interface X509AuthenticatorCertificateManager {

    /**
     * Get CA Certificates.
     *
     * @param tenantId Tenant Id.
     * @return List of CA certificates.
     * @throws X509ConfigurationException If an error occurs while getting the CA certificates.
     */
    List<CACertificateInfo> getCACertificates(int tenantId) throws X509ConfigurationException;

    /**
     * Add CA Certificate.
     *
     * @param caCertificate CA Certificate.
     * @param tenantId Tenant Id.
     * @return Added CA Certificate Info.
     * @throws X509ConfigurationException If an error occurs while adding the CA certificate.
     */
    CACertificate addCACertificate(X509Certificate caCertificate, int tenantId) throws X509ConfigurationException;

    /**
     * Add CA Certificate List.
     *
     * @param caCertificateList List of X509 Certificates.
     * @param tenantId Tenant Id.
     * @throws X509ConfigurationException If an error occurs while adding the CA certificate list.
     */
    void addCACertificateList(List<X509Certificate> caCertificateList, int tenantId) throws X509ConfigurationException;

    /**
     * Get CA Certificate.
     *
     * @param certificateId Certificate Id.
     * @param tenantId Tenant Id.
     * @return CA Certificate Info.
     * @throws X509ConfigurationException If an error occurs while getting the CA certificate.
     */
    CACertificateInfo getCaCertificate(String certificateId, int tenantId) throws X509ConfigurationException;

    /**
     * Get CA Certificates by Issuer.
     *
     * @param issuer Issuer.
     * @param tenantId Tenant Id.
     * @return List of CA certificates.
     * @throws X509ConfigurationException If an error occurs while getting the CA certificates.
     */
    List<CACertificate> getCaCertificatesByIssuer(String issuer, int tenantId) throws X509ConfigurationException;

    /**
     * Update CA Certificate.
     *
     * @param certificateId Certificate Id.
     * @param certificate CA Certificate.
     * @param tenantId Tenant Id.
     * @return Updated CA Certificate Info.
     * @throws X509ConfigurationException If an error occurs while updating the CA certificate.
     */
    CACertificateInfo updateCACertificate(String certificateId, X509Certificate certificate, int tenantId)
            throws X509ConfigurationException;

    /**
     * Delete CA Certificate.
     *
     * @param certificateId Certificate Id.
     * @param tenantId Tenant Id.
     * @throws X509ConfigurationException If an error occurs while deleting the CA certificate.
     */
    void deleteCACertificate(String certificateId, int tenantId) throws X509ConfigurationException;
}
