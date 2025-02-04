/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationException;

import java.security.cert.X509Certificate;

/**
 * Validation manager interface to be used for verifying revocation status
 */
public interface RevocationValidationManager {

    /**
     * Verify the revocation status of an X509 certificate.
     *
     * @param peerCertificate x509 certificate
     * @return revocation status of the x509
     * @throws CertificateValidationException certificateValidationException
     */
    boolean verifyRevocationStatus(X509Certificate peerCertificate) throws CertificateValidationException;

}
