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

/**
 * This interface supports the x509 authenticator validator manager.
 */
public interface CertificateValidationManagementService {

    /**
     * Get validators.
     *
     * @param tenantDomain Tenant Id.
     * @return List of validators.
     * @throws CertificateValidationManagementException If an error occurs while getting the validators.
     */
    List<Validator> getValidators(String tenantDomain) throws CertificateValidationManagementException;

    /**
     * Get the validator by name.
     *
     * @param name         Name of the validator.
     * @param tenantDomain Tenant Id.
     * @return Validator.
     * @throws CertificateValidationManagementException If an error occurs while getting the validator.
     */
    Validator getValidator(String name, String tenantDomain) throws CertificateValidationManagementException;

    /**
     * Update the validator.
     *
     * @param validator    Validator.
     * @param tenantDomain Tenant Id.
     * @return Updated validator.
     * @throws CertificateValidationManagementException If an error occurs while updating the validator.
     */
    Validator updateValidator(Validator validator, String tenantDomain) throws CertificateValidationManagementException;

    /**
     * Get CA Certificates.
     *
     * @param tenantDomain Tenant Id.
     * @return List of CA certificates.
     * @throws CertificateValidationManagementException If an error occurs while getting the CA certificates.
     */
    List<CACertificateInfo> getCACertificates(String tenantDomain) throws CertificateValidationManagementException;

    /**
     * Add CA Certificate.
     *
     * @param encodedCertificate Base64 Encoded CA Certificate.
     * @param tenantDomain       Tenant Id.
     * @return Added CA Certificate Info.
     * @throws CertificateValidationManagementException If an error occurs while adding the CA certificate.
     */
    CACertificateInfo addCACertificate(String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException;

    /**
     * Get CA Certificate.
     *
     * @param certificateId Certificate Id.
     * @param tenantDomain  Tenant Id.
     * @return CA Certificate Info.
     * @throws CertificateValidationManagementException If an error occurs while getting the CA certificate.
     */
    CACertificateInfo getCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException;

    /**
     * Update CA Certificate.
     *
     * @param certificateId      Certificate Id.
     * @param encodedCertificate Base64 Encoded CA Certificate.
     * @param tenantDomain       Tenant Id.
     * @return Updated CA Certificate Info.
     * @throws CertificateValidationManagementException If an error occurs while updating the CA certificate.
     */
    CACertificateInfo updateCACertificate(String certificateId, String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException;

    /**
     * Delete CA Certificate.
     *
     * @param certificateId Certificate Id.
     * @param tenantDomain  Tenant Id.
     * @throws CertificateValidationManagementException If an error occurs while deleting the CA certificate.
     */
    void deleteCACertificate(String certificateId, String tenantDomain) throws CertificateValidationManagementException;
}
