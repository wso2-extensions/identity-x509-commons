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
import org.wso2.carbon.identity.x509Certificate.validation.util.CertificateValidationUtil;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.wso2.carbon.identity.x509Certificate.validation.util.X509CertificateUtil.getCRLUrls;

/**
 * This is used to verify a certificate is revoked or not by using the Certificate Revocation List published
 * by the CA.
 */
public class CRLValidator implements RevocationValidator {

    private int priority;
    private boolean enabled;
    private int retryCount;
    private boolean fullChainValidationEnabled;

    public CRLValidator() {
    }

    /**
     * Checks revocation status (Good, Revoked) of the peer certificate
     *
     * @param peerCert   peer certificate
     * @param issuerCert issuer certificate of the peer
     * @param retryCount retry count to connect to CRL Url and get CRL
     * @return revocation status of the peer certificate
     * @throws CertificateValidationException certificateValidationException
     */
    @Override
    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert, int retryCount)
            throws CertificateValidationException {

        List<String> crlUrls = getCRLUrls(peerCert);
        return CertificateValidationUtil.getRevocationStatus(peerCert, retryCount, crlUrls);
    }

    @Override
    public boolean isEnable() {

        return enabled;
    }

    @Override
    public void setEnable(boolean enabled) {

        this.enabled = enabled;
    }

    @Override
    public int getPriority() {

        return priority;
    }

    @Override
    public void setPriority(int priority) {

        this.priority = priority;
    }

    @Override
    public boolean isFullChainValidationEnable() {

        return fullChainValidationEnabled;
    }

    @Override
    public void setFullChainValidation(boolean fullChainValidationEnabled) {

        this.fullChainValidationEnabled = fullChainValidationEnabled;
    }

    @Override
    public int getRetryCount() {

        return retryCount;
    }

    @Override
    public void setRetryCount(int retryCount) {

        this.retryCount = retryCount;
    }
}
