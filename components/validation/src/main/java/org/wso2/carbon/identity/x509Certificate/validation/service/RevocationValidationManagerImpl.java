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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.util.CertificateValidationUtil;
import org.wso2.carbon.identity.x509Certificate.validation.model.RevocationStatus;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.validator.RevocationValidator;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Manager class responsible for validating client certificates.
 * This class will invoke the available validators based on the configured priorities.
 */
public class RevocationValidationManagerImpl implements RevocationValidationManager {

    private static final Log log = LogFactory.getLog(RevocationValidationManagerImpl.class);
    private static Comparator<RevocationValidator> revocationValidatorComparator =
            (revocationValidator1, revocationValidator2) -> {
                if (revocationValidator1.getPriority() > revocationValidator2.getPriority()) {
                    return 1;
                } else if (revocationValidator1.getPriority() < revocationValidator2.getPriority()) {
                    return -1;
                } else {
                    return 0;
                }
            };

    @Override
    public boolean verifyRevocationStatus(X509Certificate peerCertificate) throws CertificateValidationException {

        List<RevocationValidator> enabledRevocationValidators =
                CertificateValidationUtil.loadEnabledValidatorConfigFromRegistry();
        Collections.sort(enabledRevocationValidators, revocationValidatorComparator);
        int validatorCount = enabledRevocationValidators.size();

        for (RevocationValidator validator : enabledRevocationValidators) {
            --validatorCount;
            try {
                return isRevoked(validator, peerCertificate);
            } catch (CertificateValidationException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Certificate validation is not successful.", e);
                }
                if (validatorCount <= 0) {
                    throw new CertificateValidationException("Couldn't validate the certificate revocation from" +
                            "any of the validators.", e);
                }
            }
        }
        return false;
    }

    private boolean isRevoked(RevocationValidator validator, X509Certificate certificate)
            throws CertificateValidationException {

        log.info("X509 Certificate validation with " + validator.getClass().getSimpleName());
        List<CACertificate> caCertificateList = CertificateValidationUtil.loadCaCertsFromRegistry(certificate);
        for (CACertificate caCertificate : caCertificateList) {
            RevocationStatus revocationStatus;
            try {
                revocationStatus = validator.checkRevocationStatus(certificate, caCertificate.getX509Certificate(),
                        validator.getRetryCount());
            } catch (CertificateValidationException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error when validation certificate revocation with " +
                            validator.getClass().getSimpleName() + ". So check with the next CA certificate in the " +
                            "list.", e);
                }
                continue;
            }

            if (RevocationStatus.UNKNOWN.equals(revocationStatus)) {
                if (log.isDebugEnabled()) {
                    log.debug("OCSP Responder/CRL Urls has no information about the requested certificate with " +
                            "serial num: " + certificate.getSerialNumber() + "So check with the next CA certificate " +
                            "in the list.");
                }
            } else if (RevocationStatus.REVOKED.equals(revocationStatus)) {
                if (log.isDebugEnabled()) {
                    log.debug("Certificate with serial num: " + certificate.getSerialNumber() + " is revoked.");
                }
                return true;
            } else if (validator.isFullChainValidationEnable() && !caCertificate.getX509Certificate().getIssuerDN()
                    .equals(caCertificate.getX509Certificate().getSubjectDN())) {
                if (log.isDebugEnabled()) {
                    log.debug("Full chain validation is enabled and validating CA certificate with serial num: " +
                            caCertificate.getX509Certificate().getSerialNumber());
                }
                return isRevoked(validator, caCertificate.getX509Certificate());
            } else if (RevocationStatus.GOOD.equals(revocationStatus)) {
                if (log.isDebugEnabled()) {
                    log.debug("Certificate with serial num: " + certificate.getSerialNumber() + " is not revoked.");
                }
                return false;
            }
        }
        throw new CertificateValidationException("Validator: " + validator.getClass().getSimpleName() +
                "couldn't validate the revocation status of certificate with serial num: " +
                certificate.getSerialNumber());
    }

}
