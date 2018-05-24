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

package org.wso2.carbon.identity.x509Certificate.validation.validator;

import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.RevocationStatus;

import java.security.cert.X509Certificate;

/**
 * This interface needs to be implemented by any certificate revocation validator
 */
public interface RevocationValidator {

    /**
     * Checks revocation status of the peer certificate.
     *
     * @param peerCert   peer certificate
     * @param issuerCert issuer certificate
     * @param retryCount retry count
     * @return revocation status
     * @throws CertificateValidationException certificateValidationException
     */
    RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert, int retryCount)
            throws CertificateValidationException;

    /**
     * Check whether the revocation validator is enabled.
     *
     * @return true if revocation validator is enabled
     */
    boolean isEnable();

    /**
     * Set whether the revocation validator to be enabled or not.
     *
     * @param enabled true if revocation validator is to be enabled
     */
    void setEnable(boolean enabled);

    /**
     * Get priority of the revocation validator.
     *
     * @return priority of the revocation validator
     */
    int getPriority();

    /**
     * Set priority of the revocation validator.
     *
     * @param priority priority of the revocation validator
     */
    void setPriority(int priority);

    /**
     * Check whether full chain validation enabled.
     *
     * @return true if full chain validation enabled
     */
    boolean isFullChainValidationEnable();

    /**
     * Set whether full chain validation enabled or not.
     *
     * @param fullChainValidationEnabled true if full chain validation to be enabled
     */
    void setFullChainValidation(boolean fullChainValidationEnabled);

    /**
     * Get revocation validator retry count.
     *
     * @return validator retry count
     */
    int getRetryCount();

    /**
     * Set revocation validator retry count.
     *
     * @param retryCount revocation validator retry count
     */
    void setRetryCount(int retryCount);
}
