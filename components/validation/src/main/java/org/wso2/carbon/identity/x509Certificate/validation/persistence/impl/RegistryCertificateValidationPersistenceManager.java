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

import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.decodeCertificate;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.encodeCertificate;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.generateCertificateHash;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getAIALocations;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCACertRegFullPath;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCRLUrls;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getNormalizedName;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.isSelfSignedCert;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.resourceToValidatorObject;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CA_CERT_REG_CRL;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CA_CERT_REG_CRL_OCSP_SEPERATOR;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CA_CERT_REG_OCSP;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CA_CERT_REG_PATH;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CERTFICATE_ID;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CRL_VALIDATOR;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.OCSP_VALIDATOR;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_NAME;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_REG_PATH;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT;
import static org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST;
import static org.wso2.carbon.registry.core.RegistryConstants.PATH_SEPARATOR;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationManagementClientException;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.internal.CertValidationDataHolder;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.CertificateValidationPersistenceManager;
import org.wso2.carbon.identity.x509Certificate.validation.util.CertificateValidationManagementExceptionHandler;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;

/**
 * This implementation handles the keystore storage/persistence related logics in the Registry.
 */
public class RegistryCertificateValidationPersistenceManager implements CertificateValidationPersistenceManager {

    private static final Log LOG = LogFactory.getLog(RegistryCertificateValidationPersistenceManager.class);
    private static final String REGISTRY_PATH_SEPARATOR = "/";

    @Override
    public List<Validator> getValidators(String tenantDomain) throws CertificateValidationManagementException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            if (registry.resourceExists(VALIDATOR_CONF_REG_PATH)) {
                LOG.debug("Validator configurations are available in registry path: " + VALIDATOR_CONF_REG_PATH);
                return getValidatorsFromRegistryResource(registry, VALIDATOR_CONF_REG_PATH);
            } else {
                return new ArrayList<>();
            }
        } catch (RegistryException | CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATORS, e);
        }
    }

    @Override
    public Validator getValidator(String name, String tenantDomain) throws CertificateValidationManagementException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            String validatorConfRegPath = VALIDATOR_CONF_REG_PATH + REGISTRY_PATH_SEPARATOR + name;
            if (registry.resourceExists(validatorConfRegPath)) {
                LOG.debug("Validator configurations are available in registry path: " + validatorConfRegPath);
                return getEnabledValidatorFromRegistryResource(registry, validatorConfRegPath);
            } else {
                throw CertificateValidationManagementExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, name, tenantDomain);
            }
        } catch (RegistryException | CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATOR_BY_NAME, e);
        }
    }

    @Override
    public Validator updateValidator(Validator validator, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            String validatorConfRegPath =
                    VALIDATOR_CONF_REG_PATH + REGISTRY_PATH_SEPARATOR + validator.getDisplayName();
            if (registry.resourceExists(validatorConfRegPath)) {
                LOG.debug("Validator configurations are available in registry path: " + validatorConfRegPath);
                return updateValidatorInRegistryResource(registry, validatorConfRegPath, validator);
            } else {
                throw CertificateValidationManagementExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, validator.getDisplayName(), tenantDomain);
            }
        } catch (RegistryException | CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_UPDATING_VALIDATOR, e);
        }
    }

    @Override
    public List<CACertificateInfo> getCACertificates(String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            String caRegPath = CA_CERT_REG_PATH;
            if (registry.resourceExists(caRegPath)) {
                LOG.debug("CA Certificate configurations are available in registry path: " + caRegPath);
                List<CACertificateInfo> caCertificateList = new ArrayList<>();
                Collection issuerCollection = (Collection) registry.get(caRegPath);
                if (issuerCollection != null) {
                    String[] childrenList1 = issuerCollection.getChildren();
                    for (String issuer : childrenList1) {
                        Collection certificateCollection = (Collection) registry.get(issuer);
                        if (certificateCollection != null) {
                            String[] childrenList2 = certificateCollection.getChildren();
                            for (String certChild : childrenList2) {
                                Resource certResource = registry.get(certChild);
                                CACertificate caCertificate = resourceToCACertObject(certResource);
                                X509Certificate x509Cert = caCertificate.getX509Certificate();

                                String certId = certResource.getProperty(CERTFICATE_ID);

                                if (certId == null) {
                                    certId = generateCertificateHash(x509Cert);
                                }

                                CACertificateInfo caCertificateInfo = new CACertificateInfo();
                                caCertificateInfo.setCertId(certId);
                                caCertificateInfo.setIssuerDN(
                                        getNormalizedName(x509Cert.getIssuerDN().getName()));
                                caCertificateInfo.setSerialNumber(
                                        getNormalizedName(x509Cert.getSerialNumber().toString(16))); // Use Hex
                                caCertificateInfo.setCrlUrls(caCertificate.getCrlUrl());
                                caCertificateInfo.setOcspUrls(caCertificate.getOcspUrl());

                                caCertificateList.add(caCertificateInfo);
                            }
                        }
                    }
                }
                return caCertificateList;
            } else {
                return new ArrayList<>();
            }
        } catch (CertificateValidationException | RegistryException | NoSuchAlgorithmException e) {
            return new ArrayList<>();
        }
    }

    @Override
    public CACertificateInfo addCACertificate(String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            X509Certificate caCertificate = decodeCertificate(encodedCertificate);
            String caCertRegPath = getCACertRegFullPath(caCertificate);
            if (!registry.resourceExists(caCertRegPath)) {
                CACertificate addedCACertificate = addCACertificateInRegistry(registry, caCertRegPath,
                        caCertificate,
                        getValidators(tenantDomain));
                CACertificateInfo caCertificateInfo = new CACertificateInfo();
                caCertificateInfo.setCertId(generateCertificateHash(addedCACertificate.getX509Certificate()));
                caCertificateInfo.setIssuerDN(
                        getNormalizedName(addedCACertificate.getX509Certificate().getIssuerDN().getName()));
                caCertificateInfo.setSerialNumber(getNormalizedName(addedCACertificate.getX509Certificate()
                        .getSerialNumber().toString()));
                caCertificateInfo.setCrlUrls(addedCACertificate.getCrlUrl());
                caCertificateInfo.setOcspUrls(addedCACertificate.getOcspUrl());
                return caCertificateInfo;
            } else {
                throw CertificateValidationManagementExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_CA_CERTIFICATE_ALREADY_EXISTS, caCertificate.getSerialNumber().toString(),
                                tenantDomain);
            }
        } catch (UnsupportedEncodingException | CertificateValidationException | RegistryException |
                 CertificateException | NoSuchAlgorithmException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public CACertificateInfo getCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            CACertificate certificate = getCACertificateFromRegistry(getGovernanceRegistry(tenantDomain),
                    certificateId);
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certificateId);
            caCertificateInfo.setIssuerDN(
                    getNormalizedName(certificate.getX509Certificate().getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(certificate.getX509Certificate()
                    .getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(certificate.getCrlUrl());
            caCertificateInfo.setOcspUrls(certificate.getOcspUrl());
            return caCertificateInfo;
        } catch (CertificateValidationException | RegistryException | CertificateException |
                 NoSuchAlgorithmException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATE_BY_ID, e);
        }
    }

    @Override
    public CACertificateInfo updateCACertificate(String certificateId, String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            X509Certificate certificate = decodeCertificate(encodedCertificate);
            String caCertRegPath = getCACertRegFullPath(certificate);
            CACertificate caCertificate = updateCACertificateInRegistry(registry, caCertRegPath, certificate,
                    getValidators(tenantDomain), certificateId);
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certificateId);
            caCertificateInfo.setIssuerDN(
                    getNormalizedName(caCertificate.getX509Certificate().getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(caCertificate.getX509Certificate()
                    .getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(caCertificate.getCrlUrl());
            caCertificateInfo.setOcspUrls(caCertificate.getOcspUrl());
            return caCertificateInfo;
        } catch (UnsupportedEncodingException | CertificateValidationException | RegistryException |
                 CertificateException | NoSuchAlgorithmException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_UPDATING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public void deleteCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Registry registry = getGovernanceRegistry(tenantDomain);
            if (!deleteCertificateById(registry, certificateId)) {
                throw CertificateValidationManagementExceptionHandler.handleClientException
                        (ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST);
            }
        } catch (CertificateValidationException | RegistryException |
                 CertificateException | NoSuchAlgorithmException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_DELETING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public List<CACertificate> getCACertsByIssuer(String issuerDN, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            return getCACertsFromRegResource(getCACertsRegPathByIssuer(issuerDN));
        } catch (RegistryException | CertificateValidationException | UnsupportedEncodingException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_RETIREVING_CA_CERTIFICATE_BY_ISSUER, e, issuerDN, tenantDomain);
        }
    }

    @Override
    public void addValidators(List<Validator> validators, String tenatDomain)
            throws CertificateValidationManagementException {

        try {
            addValidatorsToRegistry(getGovernanceRegistry(tenatDomain), validators, tenatDomain);
        } catch (RegistryException | CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler.handleServerException
                    (ErrorMessage.ERROR_WHILE_ADDING_VALIDATORS, e, tenatDomain);
        }
    }

    @Override
    public void addCACertificates(List<Validator> validators, List<X509Certificate> trustedCertificates,
                                  String tenantDomain) throws CertificateValidationManagementException {

        for (X509Certificate certificate : trustedCertificates) {
            String caCertRegPath = null;
            try {
                caCertRegPath = getCACertRegFullPath(certificate);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("CA certificate registry path: " + caCertRegPath);
                }
                if (!getGovernanceRegistry(tenantDomain).resourceExists(caCertRegPath)) {
                    addCACertificateInRegistry(getGovernanceRegistry(tenantDomain), caCertRegPath, certificate,
                            validators);
                }
            } catch (UnsupportedEncodingException | CertificateValidationException | RegistryException e) {
                throw CertificateValidationManagementExceptionHandler.handleServerException
                        (ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATES, e, tenantDomain);
            }
        }
    }

    public static Registry getGovernanceRegistry(String tenantDomain) throws CertificateValidationException {

        Registry registry;
        try {
            registry = CertValidationDataHolder.getInstance().getRegistryService().getGovernanceSystemRegistry(
                    CertValidationDataHolder.getInstance().getRealmService().getTenantManager()
                            .getTenantId(tenantDomain));
        } catch (UserStoreException | RegistryException e) {
            throw new CertificateValidationException("Error while get tenant registry.", e);
        }
        return registry;
    }

    private static List<CACertificate> getCACertsFromRegResource(String caRegPath) throws RegistryException,
            CertificateValidationException {

        List<CACertificate> caCertificateList = new ArrayList<>();
        //get tenant registry for loading validator configurations
        Registry registry = getGovernanceRegistry(
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());

        if (registry.resourceExists(caRegPath)) {
            Collection collection = (Collection) registry.get(caRegPath);
            if (collection != null) {
                String[] children = collection.getChildren();
                for (String child : children) {
                    Resource resource = registry.get(child);
                    CACertificate caCertificate = resourceToCACertObject(resource);
                    caCertificateList.add(caCertificate);
                }
            }
        }
        return caCertificateList;
    }

    private static List<Validator> getValidatorsFromRegistryResource(Registry registry,
                                                                     String validatorConfRegPath)
            throws RegistryException {

        List<Validator> validators = new ArrayList<>();
        Collection collection = (Collection) registry.get(validatorConfRegPath);
        if (collection != null) {
            String[] children = collection.getChildren();
            for (String child : children) {
                Resource resource = registry.get(child);
                validators.add(resourceToValidatorObject(resource));
            }
        }

        return validators;
    }

    private static Validator getEnabledValidatorFromRegistryResource(Registry registry, String validatorConfRegPath)
            throws RegistryException {

        Resource resource = registry.get(validatorConfRegPath);
        return resourceToValidatorObject(resource);
    }

    private static Validator updateValidatorInRegistryResource(Registry registry, String validatorConfRegPath,
                                                               Validator validator)
            throws RegistryException {

        Resource resource = registry.get(validatorConfRegPath);

        resource.setProperty(VALIDATOR_CONF_ENABLE, Boolean.toString(validator.isEnabled()));
        resource.setProperty(VALIDATOR_CONF_PRIORITY, Integer.toString(validator.getPriority()));
        resource.setProperty(VALIDATOR_CONF_FULL_CHAIN_VALIDATION,
                Boolean.toString(validator.isFullChainValidationEnabled()));
        resource.setProperty(VALIDATOR_CONF_RETRY_COUNT, Integer.toString(validator.getRetryCount()));
        registry.put(validatorConfRegPath, resource);
        return validator;
    }

    private static CACertificate addCACertificateInRegistry(Registry registry, String caCertRegPath,
                                                            X509Certificate certificate,
                                                            List<Validator> validators)
            throws CertificateValidationException {

        List<String> ocspUrls = new ArrayList<>();
        List<String> crlUrls = new ArrayList<>();
        try {
            boolean isSelfSignedCert = isSelfSignedCert(certificate);
            for (Validator validator : validators) {
                if (validator.isEnabled()) {
                    if (OCSP_VALIDATOR.equals(validator.getDisplayName()) &&
                            !isSelfSignedCert) {
                        ocspUrls = getAIALocations(certificate);
                    } else if (CRL_VALIDATOR.equals(validator.getDisplayName()) &&
                            !isSelfSignedCert) {
                        crlUrls = getCRLUrls(certificate);
                    }
                }
            }
            Resource resource = registry.newResource();
            StringBuilder crlUrlReg = new StringBuilder();
            if (CollectionUtils.isNotEmpty(crlUrls)) {
                for (String crlUrl : crlUrls) {
                    crlUrlReg.append(crlUrl).append(CA_CERT_REG_CRL_OCSP_SEPERATOR);
                }
            }

            StringBuilder ocspUrlReg = new StringBuilder();
            if (CollectionUtils.isNotEmpty(ocspUrls)) {
                for (String ocspUrl : ocspUrls) {
                    ocspUrlReg.append(ocspUrl).append(CA_CERT_REG_CRL_OCSP_SEPERATOR);
                }
            }
            resource.addProperty(CA_CERT_REG_CRL, crlUrlReg.toString());
            resource.addProperty(CA_CERT_REG_OCSP, ocspUrlReg.toString());
            resource.addProperty(CERTFICATE_ID, generateCertificateHash(certificate));
            resource.setContent(encodeCertificate(certificate));
            registry.put(caCertRegPath, resource);
            return new CACertificate(crlUrls, ocspUrls, certificate);
        } catch (RegistryException e) {
            throw new CertificateValidationException("Error adding default ca certificate with serial num:" +
                    certificate.getSerialNumber() + " in registry.", e);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            throw new CertificateValidationException("Error encoding ca certificate with serial num: " + certificate
                    .getSerialNumber() + " to add in registry.", e);
        }
    }

    private static CACertificate getCACertificateFromRegistry(Registry registry, String certificateId)
            throws CertificateValidationException, RegistryException, CertificateException, NoSuchAlgorithmException,
            CertificateValidationManagementClientException {

        if (!registry.resourceExists(CA_CERT_REG_PATH)) {
            throw new CertificateValidationException("No CA certificates found in registry.");
        }

        Collection collection = (Collection) registry.get(CA_CERT_REG_PATH);
        if (collection == null) {
            throw new CertificateValidationException("Invalid registry collection.");
        }

        for (String childPath : collection.getChildren()) {
            Collection childCollection = (Collection) registry.get(childPath);
            if (childCollection != null) {
                for (String child : childCollection.getChildren()) {
                    Resource resource = registry.get(child);
                    String storedCertId = resource.getProperty(CERTFICATE_ID);

                    if (storedCertId == null) {
                        X509Certificate storedCert = decodeCertificate(new String((byte[]) resource.getContent()));
                        storedCertId = generateCertificateHash(storedCert);
                    }
                    if (certificateId.equalsIgnoreCase(storedCertId)) {
                        return resourceToCACertObject(resource);
                    }
                }
            }
        }
        throw CertificateValidationManagementExceptionHandler.handleClientException
                (ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
    }

    private static CACertificate updateCACertificateInRegistry(Registry registry, String caCertRegPath,
                                                               X509Certificate certificate, List<Validator> validators,
                                                               String certificateId)
            throws CertificateValidationException, RegistryException, CertificateException, NoSuchAlgorithmException {

        if (!registry.resourceExists(CA_CERT_REG_PATH)) {
            throw new CertificateValidationException("No CA certificates found in registry.");
        }

        Collection collection = (Collection) registry.get(CA_CERT_REG_PATH);
        if (collection == null) {
            throw new CertificateValidationException("Invalid registry collection.");
        }

        boolean certificateExists = false;

        for (String childPath : collection.getChildren()) {
            Collection childCollection = (Collection) registry.get(childPath);
            if (childCollection != null) {
                for (String child : childCollection.getChildren()) {
                    Resource resource = registry.get(child);
                    X509Certificate storedCert = decodeCertificate(new String((byte[]) resource.getContent()));

                    String storedCertId = generateCertificateHash(storedCert);
                    if (!certificateId.equalsIgnoreCase(storedCertId)) {
                        continue; // Skip non-matching certificates
                    }

                    certificateExists = true;

                    if (storedCert.getIssuerDN().getName().equals(certificate.getIssuerDN().getName())) {
                        if (storedCert.getSerialNumber().equals(certificate.getSerialNumber())) {
                            // Update the certificate
                            return updateCertificateResource(registry, caCertRegPath, certificate, validators);
                        } else {
                            // Delete old certificate with same issuer but different serial number
                            registry.delete(child);
                            break;
                        }
                    } else {
                        // Delete old certificate with different issuer
                        registry.delete(child);
                        break;
                    }
                }
            }
        }

        // If certificate exists but was not updated (because serials didn't match)
        if (certificateExists) {
            return updateCertificateResource(registry, caCertRegPath, certificate, validators);
        }

        throw new CertificateValidationException("Certificate with serial number: " + certificate.getSerialNumber() +
                " does not exist in the registry.");
    }

    private static CACertificate updateCertificateResource(Registry registry, String caCertRegPath,
                                                           X509Certificate certificate, List<Validator> validators)
            throws RegistryException, CertificateException, CertificateValidationException {

        boolean isSelfSigned = isSelfSignedCert(certificate);
        List<String> crlUrls = new ArrayList<>();
        List<String> ocspUrls = new ArrayList<>();

        for (Validator validator : validators) {
            if (!validator.isEnabled() || isSelfSigned) {
                continue;
            }

            if (OCSP_VALIDATOR.equals(validator.getDisplayName())) {
                ocspUrls = getAIALocations(certificate);
            } else if (CRL_VALIDATOR.equals(validator.getDisplayName())) {
                crlUrls = getCRLUrls(certificate);
            }
        }

        // Create a new registry resource
        Resource resource = registry.newResource();
        resource.addProperty(CA_CERT_REG_CRL, String.join(CA_CERT_REG_CRL_OCSP_SEPERATOR, crlUrls));
        resource.addProperty(CA_CERT_REG_OCSP, String.join(CA_CERT_REG_CRL_OCSP_SEPERATOR, ocspUrls));
        resource.setContent(encodeCertificate(certificate));

        registry.put(caCertRegPath, resource);
        return new CACertificate(crlUrls, ocspUrls, certificate);
    }

    private static boolean deleteCertificateById(Registry registry, String certificateHash)
            throws RegistryException, CertificateException, NoSuchAlgorithmException {

        if (!registry.resourceExists(CA_CERT_REG_PATH)) {
            LOG.warn("No CA certificates found in registry.");
            return false;
        }

        Collection collection = (Collection) registry.get(CA_CERT_REG_PATH);
        if (collection == null || collection.getChildren().length == 0) {
            LOG.warn("No certificates available in the registry.");
            return false;
        }

        for (String childPath : collection.getChildren()) {
            Collection childCollection = (Collection) registry.get(childPath);
            if (childCollection != null) {
                for (String child : childCollection.getChildren()) {
                    Resource resource = registry.get(child);
                    X509Certificate storedCert = decodeCertificate(new String((byte[]) resource.getContent()));

                    String storedCertId = generateCertificateHash(storedCert);
                    if (certificateHash.equalsIgnoreCase(storedCertId)) {
                        registry.delete(childPath);
                        LOG.debug("Deleted certificate with id (hash): " + certificateHash);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static String getCACertsRegPathByIssuer(String issuerDN) throws UnsupportedEncodingException {

        return CA_CERT_REG_PATH + PATH_SEPARATOR + URLEncoder.encode(issuerDN, "UTF-8").replaceAll("%", ":");
    }

    private static void addValidatorsToRegistry(Registry registry, List<Validator> validators, String tenantDomain)
            throws RegistryException {

        for (Validator validator : validators) {
            String validatorConfRegPath =
                    VALIDATOR_CONF_REG_PATH + PATH_SEPARATOR + getNormalizedName(validator.getDisplayName());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Adding default validator configurations to registry in: " +
                        validatorConfRegPath);
            }
            try {
                if (!registry.resourceExists(validatorConfRegPath)) {
                    addValidatorConfigInRegistry(registry, validatorConfRegPath, validator);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("Validator configuration for %s is added to %s tenant registry.",
                                validator.getDisplayName(), tenantDomain));
                    }
                }
            } catch (RegistryException e) {
                LOG.error("Error while adding validator configurations in registry.", e);
            }
        }
    }

    private static void addValidatorConfigInRegistry(Registry registry, String validatorConfRegPath,
                                                     Validator validator) throws RegistryException {

        Resource resource = registry.newResource();
        resource.addProperty(VALIDATOR_CONF_NAME, validator.getName());
        resource.addProperty(VALIDATOR_CONF_ENABLE, Boolean.toString(validator.isEnabled()));
        resource.addProperty(VALIDATOR_CONF_PRIORITY, Integer.toString(validator.getPriority()));
        resource.addProperty(VALIDATOR_CONF_FULL_CHAIN_VALIDATION,
                Boolean.toString(validator.isFullChainValidationEnabled()));
        resource.addProperty(VALIDATOR_CONF_RETRY_COUNT, Integer.toString(validator.getRetryCount()));
        registry.put(validatorConfRegPath, resource);
    }

    public static CACertificate resourceToCACertObject(Resource resource) throws CertificateValidationException {

        List<String> crlUrls;
        List<String> ocspUrls;
        X509Certificate x509Certificate;
        try {
            String crlUrlReg = resource.getProperty(CA_CERT_REG_CRL);
            String ocspUrlReg = resource.getProperty(CA_CERT_REG_OCSP);
            crlUrls = crlUrlReg.isEmpty() ? Collections.emptyList() :
                    Arrays.asList(crlUrlReg.split(CA_CERT_REG_CRL_OCSP_SEPERATOR));
            ocspUrls = ocspUrlReg.isEmpty() ? Collections.emptyList() :
                    Arrays.asList(ocspUrlReg.split(CA_CERT_REG_CRL_OCSP_SEPERATOR));
            byte[] regContent = (byte[]) resource.getContent();
            x509Certificate = decodeCertificate(new String(regContent));
        } catch (RegistryException | CertificateException e) {
            throw new CertificateValidationException("Error when converting registry resource content.", e);
        }
        return new CACertificate(crlUrls, ocspUrls, x509Certificate);
    }
}
