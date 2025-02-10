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

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCES_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_ALREADY_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.decodeCertificate;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.encodeCertificate;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.generateCertificateHash;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getAIALocations;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getCRLUrls;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.getNormalizedName;
import static org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationUtil.isSelfSignedCert;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CERTS;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.CRL_VALIDATOR;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.OCSP_VALIDATOR;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_NAME;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.VALIDATOR_RESOURCE_TYPE;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.X509_CA_CERT_FILE;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.X509_CA_CERT_RESOURCE_TYPE;
import static org.wso2.carbon.identity.x509Certificate.validation.X509CertificateValidationConstants.X509_CERT_PREFIX;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.certificate.management.constant.CertificateMgtErrors;
import org.wso2.carbon.identity.certificate.management.exception.CertificateMgtException;
import org.wso2.carbon.identity.certificate.management.model.Certificate;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceFile;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.ModelSerializer;
import org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage;
import org.wso2.carbon.identity.x509Certificate.validation.exception.CertificateValidationManagementException;
import org.wso2.carbon.identity.x509Certificate.validation.internal.CertValidationDataHolder;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.CertObject;
import org.wso2.carbon.identity.x509Certificate.validation.model.IssuerDNMap;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.persistence.CertificateValidationPersistenceManager;
import org.wso2.carbon.identity.x509Certificate.validation.util.CertificateValidationManagementExceptionHandler;

/**
 * This implementation handles the keystore storage/persistence related logics in the Database.
 */
public class JDBCCertificateValidationPersistenceManager implements CertificateValidationPersistenceManager {

    private static final Log LOG = LogFactory.getLog(JDBCCertificateValidationPersistenceManager.class);

    @Override
    public void addValidators(List<Validator> validators, String tenatDomain)
            throws CertificateValidationManagementException {

        try {
            addValidatorsToConfigurationStore(validators);
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_ADDING_VALIDATORS, e, tenatDomain);
        }
    }

    @Override
    public void addCACertificates(List<Validator> validators, List<X509Certificate> trustedCertificates,
                                  String tenantDomain) throws CertificateValidationManagementException {

        try {
            addCACertificateInConfigurationStore(validators, trustedCertificates, tenantDomain);
        } catch (CertificateValidationException | CertificateMgtException | CertificateException | IOException |
                 NoSuchAlgorithmException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATES, e, tenantDomain);
        }
    }

    @Override
    public List<Validator> getValidators(String tenantDomain) throws CertificateValidationManagementException {

        try {
            return getValidatorsFromConfigStore(tenantDomain);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCES_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return new ArrayList<>();
            }
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATORS, e);
        }
    }

    @Override
    public Validator getValidator(String name, String tenantDomain) throws CertificateValidationManagementException {

        try {
            name = name.toLowerCase();
            Optional<Validator> validator = getValidatorFromConfigStoreByName(tenantDomain, name);

            if (!validator.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, name, tenantDomain);
            }
            return validator.get();
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_VALIDATOR_BY_NAME, e);
        }
    }

    @Override
    public Validator updateValidator(Validator validator, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<Validator> updatedValidator = updateValidatorInConfigStore(tenantDomain, validator);
            if (!updatedValidator.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_INVALID_VALIDATOR_NAME, validator.getName(),
                                tenantDomain);
            }
            return updatedValidator.get();
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_UPDATING_VALIDATOR, e);
        }
    }

    @Override
    public List<CACertificateInfo> getCACertificates(String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<List<CACertificateInfo>> caCertificateInfoList =
                    getCertificateListFromConfigurationStore(tenantDomain);
            return caCertificateInfoList.orElseGet(ArrayList::new);
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATES, e);
        }
    }

    @Override
    public CACertificateInfo addCACertificate(String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            X509Certificate caCertificate = decodeCertificate(encodedCertificate);
            Optional<CertObject> certObject = addCertificateInConfigurationStore(tenantDomain, caCertificate);
            if (!certObject.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_NO_CA_CERTIFICATES_CONFIGURED_ON_TENANT,
                                tenantDomain);
            }
            return getCACertificateInfo(caCertificate, certObject.get());
        } catch (CertificateValidationException | CertificateException | CertificateMgtException | IOException |
                 NoSuchAlgorithmException | ConfigurationManagementException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_ADDING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public CACertificateInfo getCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<CACertificate> caCertificate =
                    getCertificateFromConfigurationStoreByCertificateId(tenantDomain, certificateId);
            if (!caCertificate.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certificateId);
            caCertificateInfo.setIssuerDN(getNormalizedName(caCertificate.get()
                    .getX509Certificate().getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(caCertificate.get().getX509Certificate()
                    .getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(caCertificate.get().getCrlUrl());
            caCertificateInfo.setOcspUrls(caCertificate.get().getOcspUrl());
            return caCertificateInfo;
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETRIEVING_CA_CERTIFICATE_BY_ID, e);
        }
    }

    @Override
    public CACertificateInfo updateCACertificate(String certificateId, String encodedCertificate, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            X509Certificate certificate = decodeCertificate(encodedCertificate);
            Optional<CertObject> certObject =
                    updateCertificateInConfigurationStoreByCertificateId(certificateId, certificate, tenantDomain);
            if (!certObject.isPresent()) {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
            CACertificateInfo caCertificateInfo = new CACertificateInfo();
            caCertificateInfo.setCertId(certObject.get().getCertId());
            caCertificateInfo.setIssuerDN(getNormalizedName(certificate.getIssuerDN().getName()));
            caCertificateInfo.setSerialNumber(getNormalizedName(certificate.getSerialNumber().toString()));
            caCertificateInfo.setCrlUrls(certObject.get().getCrlUrls());
            caCertificateInfo.setOcspUrls(certObject.get().getOcspUrls());
            return caCertificateInfo;
        } catch (CertificateValidationException | CertificateException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_UPDATING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public void deleteCACertificate(String certificateId, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            Optional<CertObject> certObject =
                    deleteCertificateInConfigurationStoreByCertificateId(certificateId, tenantDomain);
            if (certObject.isPresent()) {
                deleteCACertificateFromCertificateManager(certificateId, tenantDomain);
            } else {
                throw CertificateValidationManagementExceptionHandler
                        .handleClientException(ErrorMessage.ERROR_CERTIFICATE_DOES_NOT_EXIST, certificateId,
                                tenantDomain);
            }
        } catch (CertificateValidationException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_DELETING_CA_CERTIFICATE, e);
        }
    }

    @Override
    public List<CACertificate> getCACertsByIssuer(String issuerDN, String tenantDomain)
            throws CertificateValidationManagementException {

        try {
            return getCACertsFromConfigStore(issuerDN);
        } catch (CertificateValidationException | ConfigurationManagementException e) {
            throw CertificateValidationManagementExceptionHandler
                    .handleServerException(ErrorMessage.ERROR_WHILE_RETIREVING_CA_CERTIFICATE_BY_ISSUER, e, issuerDN,
                            tenantDomain);
        }
    }

    /**
     * Get the certificate list from the configuration store.
     *
     * @param tenantDomain Tenant Domain.
     * @return List of CACertificateInfo.
     * @throws CertificateValidationException Error when getting certificate.
     */
    private static Optional<List<CACertificateInfo>> getCertificateListFromConfigurationStore(String tenantDomain)
            throws CertificateValidationException {

        try {
            Resource resource =
                    CertValidationDataHolder.getInstance().getConfigurationManager()
                            .getResourceByTenantId(IdentityTenantUtil.getTenantId(tenantDomain),
                                    X509_CA_CERT_RESOURCE_TYPE, CERTS);
            if (resource == null) {
                return Optional.empty();
            }
            InputStream inputStream = getResourceFileInputStream(resource);
            if (inputStream == null) {
                return Optional.empty();
            }
            return Optional.of(parseCertificateList(inputStream, tenantDomain));
        } catch (IOException | ConfigurationManagementException | CertificateException | CertificateMgtException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        }
    }

    private static InputStream getResourceFileInputStream(Resource resource) throws ConfigurationManagementException {

        List<ResourceFile> resourceFiles = resource.getFiles();
        if (resourceFiles == null || resourceFiles.isEmpty()) {
            LOG.debug("Resource files are empty for certificates in tenant: " + resource.getTenantDomain());
            return null;
        }
        ResourceFile resourceFile = resourceFiles.get(0);
        return resourceFile != null ? CertValidationDataHolder.getInstance().getConfigurationManager()
                .getFileById(X509_CA_CERT_RESOURCE_TYPE, CERTS, resourceFile.getId()) : null;
    }

    private static List<CACertificateInfo> parseCertificateList(InputStream inputStream, String tenantDomain)
            throws IOException, CertificateMgtException, CertificateException {

        List<CACertificateInfo> certificateList = new ArrayList<>();
        String fileContent = convertInputStreamToString(inputStream);
        IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(fileContent);
        for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.getIssuerCertMap().entrySet()) {
            for (CertObject certObject : entry.getValue()) {
                certificateList.add(convertCertObjectToCACertificateInfo(certObject, tenantDomain));
            }
        }
        return certificateList;
    }

    private static CACertificateInfo convertCertObjectToCACertificateInfo(CertObject certObject, String tenantDomain)
            throws CertificateMgtException, CertificateException {

        Certificate certificate = CertValidationDataHolder.getInstance()
                .getCertificateManagementService()
                .getCertificate(certObject.getCertificatePersistedId(), tenantDomain);
        X509Certificate x509Certificate = decodeCertificate(certificate.getCertificateContent());

        return getCACertificateInfo(x509Certificate, certObject);
    }

    /**
     * Get the certificate from the configuration store by serial number.
     *
     * @param caCertificate X509Certificate.
     * @param certObject    CertObject.
     * @return CACertificateInfo.
     */
    private static CACertificateInfo getCACertificateInfo(X509Certificate caCertificate, CertObject certObject) {

        CACertificateInfo caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCertId(certObject.getCertId());
        caCertificateInfo.setIssuerDN(getNormalizedName(caCertificate.getIssuerDN().getName()));
        caCertificateInfo.setSerialNumber(getNormalizedName(caCertificate.getSerialNumber().toString()));
        caCertificateInfo.setCrlUrls(certObject.getCrlUrls());
        caCertificateInfo.setOcspUrls(certObject.getOcspUrls());
        return caCertificateInfo;
    }

    /**
     * Update the CA certificate in the certificate manager.
     *
     * @param certificateId Certificate id
     * @param certificate   X509Certificate
     * @param tenantDomain  Tenant domain
     * @return X509Certificate
     * @throws CertificateValidationException Error when updating certificate
     */
    private static X509Certificate updateCACertificateInCertificateManager(String certificateId,
                                                                           X509Certificate certificate,
                                                                           String tenantDomain)
            throws CertificateValidationException {

        try {
            CertValidationDataHolder.getInstance()
                    .getCertificateManagementService()
                    .getCertificate(certificateId, tenantDomain);
            CertValidationDataHolder.getInstance()
                    .getCertificateManagementService()
                    .updateCertificateContent(certificateId, encodeCertificate(certificate), tenantDomain);
            LOG.debug("Successfully updated certificate with the id: " + certificateId + " in certificate manager.");
            return certificate;
        } catch (CertificateMgtException e) {
            if (CertificateMgtErrors.ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                throw new CertificateValidationException
                        ("Certificate with the id: " + certificateId + " does not exist.", e);
            }
            throw new CertificateValidationException("Error when updating certificate in certificate manager.", e);
        } catch (CertificateException e) {
            throw new CertificateValidationException("Error when encoding certificate.", e);
        }
    }

    /**
     * Get certificate from the configuration store by certificate id.
     *
     * @param tenantDomain  Tenant Domain
     * @param certificateId Certificate Id
     * @return CACertificate
     * @throws CertificateValidationException Error when getting certificate
     */
    private static Optional<CACertificate> getCertificateFromConfigurationStoreByCertificateId(String tenantDomain,
                                                                                               String certificateId)
            throws CertificateValidationException {

        try {
            Resource resource =
                    CertValidationDataHolder.getInstance().getConfigurationManager().getResourceByTenantId
                            (IdentityTenantUtil.getTenantId(tenantDomain), X509_CA_CERT_RESOURCE_TYPE, CERTS);
            List<ResourceFile> resourceFiles = resource.getFiles();
            if (resourceFiles == null || resourceFiles.isEmpty()) {
                LOG.debug("Resource files are empty for certificates in tenant: " + resource.getTenantDomain());
                return Optional.empty();
            }

            ResourceFile resourceFile = resourceFiles.get(0);
            if (resourceFile == null) {
                LOG.debug("Resource file is null for certificates in tenant: " + resource.getTenantDomain());
                return Optional.empty();
            }

            InputStream inputStream = CertValidationDataHolder.getInstance()
                    .getConfigurationManager()
                    .getFileById(X509_CA_CERT_RESOURCE_TYPE, CERTS, resourceFile.getId());

            if (inputStream == null) {
                LOG.debug("InputStream is null for the file in resource.");
                return Optional.empty();
            }

            String fileContent = convertInputStreamToString(inputStream);
            IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(fileContent);

            for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.getIssuerCertMap().entrySet()) {
                List<CertObject> certList = entry.getValue();
                Optional<CertObject> certObject = certList.stream()
                        .filter(cert -> cert.getCertId().equals(certificateId))
                        .findFirst();

                if (certObject.isPresent()) {
                    return Optional.of(new CACertificate(certObject.get().getCrlUrls(),
                            certObject.get().getOcspUrls(),
                            getCACertificateFromCertificateManager(certObject.get().getCertificatePersistedId(),
                                    tenantDomain)));
                }
            }
            return Optional.empty();
        } catch (ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        } catch (IOException e) {
            throw new CertificateValidationException("Error while reading the file content", e);
        }
    }

    private static X509Certificate getCACertificateFromCertificateManager(String certificateId,
                                                                          String tenantDomain)
            throws CertificateValidationException {

        try {
            Certificate certificate = CertValidationDataHolder.getInstance()
                    .getCertificateManagementService()
                    .getCertificate(certificateId, tenantDomain);

            return decodeCertificate(certificate.getCertificateContent());
        } catch (CertificateMgtException e) {
            LOG.debug("Error when getting certificate from certificate manager.", e);
            if (CertificateMgtErrors.ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                throw new CertificateValidationException
                        ("Certificate with the id: " + certificateId + " does not exist.", e);
            }
            throw new CertificateValidationException("Error when getting certificate from certificate manager.", e);
        } catch (CertificateException e) {
            throw new CertificateValidationException("Error when decoding certificate.", e);
        }
    }

    /**
     * Converts a Resource object into a Validator object.
     *
     * @param resource The resource object to convert.
     * @return A Validator object populated with resource attributes.
     */
    private static Validator resourceToValidatorObject(Resource resource) {

        Validator validator = new Validator();

        List<Attribute> attributes = resource.getAttributes();
        validator.setDisplayName(resource.getResourceName());
        if (attributes != null) {
            for (Attribute attribute : attributes) {
                String key = attribute.getKey();
                String value = attribute.getValue();

                switch (key) {
                    case VALIDATOR_CONF_NAME:
                        validator.setName(value);
                        break;
                    case VALIDATOR_CONF_ENABLE:
                        validator.setEnabled(Boolean.parseBoolean(value));
                        break;
                    case VALIDATOR_CONF_PRIORITY:
                        validator.setPriority(Integer.parseInt(value));
                        break;
                    case VALIDATOR_CONF_FULL_CHAIN_VALIDATION:
                        validator.setFullChainValidationEnabled(Boolean.parseBoolean(value));
                        break;
                    case VALIDATOR_CONF_RETRY_COUNT:
                        validator.setRetryCount(Integer.parseInt(value));
                        break;
                    default:
                        // Ignore unknown attributes.
                        break;
                }
            }
        }
        return validator;
    }

    /**
     * Update validator in the configuration store.
     *
     * @param tenantDomain Tenant Domain.
     * @param validator    Validator.
     * @return Validator object.
     * @throws CertificateValidationException Error when updating validator.
     */
    private static Optional<Validator> updateValidatorInConfigStore(String tenantDomain, Validator validator)
            throws CertificateValidationException {

        try {
            Resource resource =
                    CertValidationDataHolder.getInstance().getConfigurationManager()
                            .getResourceByTenantId(IdentityTenantUtil.getTenantId(tenantDomain),
                                    VALIDATOR_RESOURCE_TYPE, validator.getDisplayName());
            if (resource == null) {
                return Optional.empty();
            }
            createAttributeList(validator, resource);
            Resource updatedResource =
                    CertValidationDataHolder.getInstance().getConfigurationManager()
                            .replaceResource(VALIDATOR_RESOURCE_TYPE, resource);
            return Optional.of(resourceToValidatorObject(updatedResource));
        } catch (ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while fetching validator configurations.", e);
        }
    }

    /**
     * Get validator from the configuration store by name.
     *
     * @param tenantDomain Tenant Domain.
     * @param name         Validator name.
     * @return Validator object.
     * @throws CertificateValidationException Error when getting validator.
     */
    private static Optional<Validator> getValidatorFromConfigStoreByName(String tenantDomain, String name)
            throws CertificateValidationException {

        try {
            Resource resource = CertValidationDataHolder.getInstance().getConfigurationManager()
                    .getResourceByTenantId(IdentityTenantUtil.getTenantId(tenantDomain),
                            VALIDATOR_RESOURCE_TYPE, name);
            if (resource == null) {
                return Optional.empty();
            }
            return Optional.of(resourceToValidatorObject(resource));
        } catch (ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while fetching validator configurations.", e);
        }
    }

    /**
     * Get validators from the configuration store.
     *
     * @param tenantDomain Tenant Domain.
     * @return List of Validator.
     * @throws ConfigurationManagementException Error when getting resource.
     */
    private static List<Validator> getValidatorsFromConfigStore(String tenantDomain)
            throws ConfigurationManagementException {

        List<Validator> validators = new ArrayList<>();
        Resources resources = CertValidationDataHolder.getInstance().getConfigurationManager()
                .getResourcesByType(IdentityTenantUtil.getTenantId(tenantDomain), VALIDATOR_RESOURCE_TYPE);
        resources.getResources().forEach(resource -> validators.add(resourceToValidatorObject(resource)));
        return validators;
    }

    private static List<String> getValidationUrls(X509Certificate certificate, String tenantDomain,
                                                  String validatorType)
            throws ConfigurationManagementException, CertificateValidationException {

        List<String> urls = new ArrayList<>();
        if (!isSelfSignedCert(certificate)) {
            for (Validator validator : getValidatorsFromConfigStore(tenantDomain)) {
                if (validator.isEnabled() && validatorType.equals(validator.getDisplayName())) {
                    urls = OCSP_VALIDATOR.equals(validatorType) ? getAIALocations(certificate) :
                            getCRLUrls(certificate);
                }
            }
        }
        return urls;
    }

    /**
     * update the certificate in the configuration store by certificate id.
     *
     * @param certificateId certificate id.
     * @param certificate   X509Certificate.
     * @param tenantDomain  tenant domain.
     * @return CertObject.
     * @throws CertificateValidationException Error when updating certificate.
     */
    private static Optional<CertObject> updateCertificateInConfigurationStoreByCertificateId(String certificateId,
                                                                                             X509Certificate certificate,
                                                                                             String tenantDomain)
            throws CertificateValidationException {

        try {
            Resource resource = CertValidationDataHolder
                    .getInstance().getConfigurationManager()
                    .getResourceByTenantId(IdentityTenantUtil.getTenantId(tenantDomain),
                            X509_CA_CERT_RESOURCE_TYPE, CERTS);
            InputStream inputStream = getResourceFileInputStream(resource);
            if (inputStream == null) {
                return Optional.empty();
            }

            IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(convertInputStreamToString(inputStream));
            String issuerDN = getNormalizedName(certificate.getIssuerDN().getName());
            String serialNumber = getNormalizedName(certificate.getSerialNumber().toString());

            List<String> ocspUrls = getValidationUrls(certificate, tenantDomain, OCSP_VALIDATOR);
            List<String> crlUrls = getValidationUrls(certificate, tenantDomain, CRL_VALIDATOR);

            boolean certExistsInMap = false;
            String previousIssuer = null;

            // Check if certificateId exists anywhere in the issuer map
            for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.getIssuerCertMap().entrySet()) {
                for (CertObject cert : entry.getValue()) {
                    if (cert.getCertId().equals(certificateId)) {
                        certExistsInMap = true;
                        previousIssuer = entry.getKey();
                        break;
                    }
                }
                if (certExistsInMap) {
                    break;
                }
            }

            // If the certId is not found in the entire map, throw an error
            if (!certExistsInMap) {
                throw new CertificateValidationException("Certificate with certId: " + certificateId +
                        " does not exist in the issuer map.");
            }

            // Get the list of certificates for the given issuer
            List<CertObject> certList = issuerDNMap.getIssuerCertMap().getOrDefault(issuerDN, new ArrayList<>());
            int certIndex = -1;

            CertObject existingCertObject = null;
            // Check if the certId exists within this issuer
            for (int i = 0; i < certList.size(); i++) {
                if (certList.get(i).getCertId().equals(certificateId)) {
                    certIndex = i;
                    existingCertObject = certList.get(i);
                    break;
                }
            }

            // Create an updated CertObject
            CertObject updatedCertObject = new CertObject();
            updatedCertObject.setCertId(certificateId);
            updatedCertObject.setSerialNumber(serialNumber);
            updatedCertObject.setCrlUrls(crlUrls);
            updatedCertObject.setOcspUrls(ocspUrls);

            if (existingCertObject != null) {
                // Case 2: Cert ID exists under the same issuer → Update the certificate
                updatedCertObject.setCertificatePersistedId(existingCertObject.getCertificatePersistedId());
                updateCACertificateInCertificateManager(certificateId, certificate, tenantDomain);
                certList.set(certIndex, updatedCertObject);
            } else {
                // Case 3: Cert ID does not exist under this issuer → Add as a new cert
                String certPersistedId = addCertificateToManagementService(certificate, tenantDomain);
                updatedCertObject.setCertificatePersistedId(certPersistedId);
                certList.add(updatedCertObject);

                // Case 4: Remove the cert from the previous issuer (if different)
                if (!issuerDN.equals(previousIssuer) && previousIssuer != null) {
                    List<CertObject> previousCertList = issuerDNMap.getIssuerCertMap().get(previousIssuer);
                    previousCertList.removeIf(cert -> cert.getCertId().equals(certificateId));

                    // If no certificates remain for the old issuer, remove the issuer entry
                    if (previousCertList.isEmpty()) {
                        issuerDNMap.getIssuerCertMap().remove(previousIssuer);
                    } else {
                        // Otherwise, just update the cert list without removing the issuer
                        issuerDNMap.getIssuerCertMap().put(previousIssuer, previousCertList);
                    }
                }
            }

            // Update the issuer map with the modified cert list
            issuerDNMap.getIssuerCertMap().put(issuerDN, certList);

            saveUpdatedResource(resource, issuerDNMap);
            return Optional.of(updatedCertObject);
        } catch (ConfigurationManagementException | IOException | CertificateMgtException | CertificateException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        }
    }

    /**
     * Delete the ca certificate from the certificate manager.
     *
     * @param certificateId Certificate id
     * @param tenantDomain  Tenant domain
     * @throws CertificateValidationException Error when deleting certificate
     */
    private static void deleteCACertificateFromCertificateManager(String certificateId,
                                                                  String tenantDomain)
            throws CertificateValidationException {

        try {
            CertValidationDataHolder.getInstance()
                    .getCertificateManagementService()
                    .deleteCertificate(certificateId, tenantDomain);
        } catch (CertificateMgtException e) {
            if (CertificateMgtErrors.ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                throw new CertificateValidationException
                        ("Certificate with the id: " + certificateId + " does not exist.", e);
            }
            throw new CertificateValidationException("Error when getting certificate from certificate manager.", e);
        }
    }

    /**
     * Delete a certificate in the configuration store by certificate id.
     *
     * @param certificateId Certificate Id
     * @param tenantDomain  Tenant Domain
     * @return CertObject
     * @throws CertificateValidationException Error when deleting certificate
     */
    private static Optional<CertObject> deleteCertificateInConfigurationStoreByCertificateId(String certificateId,
                                                                                             String tenantDomain)
            throws CertificateValidationException {

        try {
            Resource resource = CertValidationDataHolder.getInstance().getConfigurationManager()
                    .getResourceByTenantId(IdentityTenantUtil.getTenantId(tenantDomain),
                            X509_CA_CERT_RESOURCE_TYPE, CERTS);
            InputStream inputStream = getResourceFileInputStream(resource);
            if (inputStream == null) {
                return Optional.empty();
            }

            IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(convertInputStreamToString(inputStream));

            for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.getIssuerCertMap().entrySet()) {
                List<CertObject> certList = entry.getValue();
                if (certList.removeIf(cert -> cert.getCertId().equals(certificateId))) {
                    if (certList.isEmpty()) {
                        issuerDNMap.getIssuerCertMap().remove(entry.getKey());
                    }
                    saveUpdatedResource(resource, issuerDNMap);
                    return Optional.of(new CertObject());
                }
            }
            return Optional.empty();
        } catch (IOException | ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        }
    }

    private static Optional<CertObject> addCertificateInConfigurationStore(String tenantDomain,
                                                                           X509Certificate certificate)
            throws CertificateValidationException, CertificateException, CertificateMgtException,
            IOException, NoSuchAlgorithmException, ConfigurationManagementException {

        try {
            Resource resource = getResource(tenantDomain);
            if (resource == null) {
                return Optional.empty();
            }

            IssuerDNMap issuerDNMap = getIssuerDNMap(resource);
            String issuerDN = getNormalizedName(certificate.getIssuerDN().getName());
            String serialNumber = getNormalizedName(certificate.getSerialNumber().toString());

            List<String> ocspUrls = getValidationUrls(certificate, tenantDomain, OCSP_VALIDATOR);
            List<String> crlUrls = getValidationUrls(certificate, tenantDomain, CRL_VALIDATOR);

            String certId = addCertificateToManagementService(certificate, tenantDomain);
            CertObject certObject = createCertObject(certificate, certId, serialNumber, ocspUrls, crlUrls);

            addCertObjectToIssuerDNMap(issuerDNMap, issuerDN, certObject, serialNumber);

            saveUpdatedResource(resource, issuerDNMap);
            return Optional.of(certObject);
        } catch (IOException | CertificateException | CertificateMgtException | NoSuchAlgorithmException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return handleResourceNotExists(certificate, tenantDomain);
            } else {
                throw new CertificateValidationException("Error while retrieving the resource", e);
            }
        }
    }

    private static Resource getResource(String tenantDomain) throws ConfigurationManagementException {

        return CertValidationDataHolder.getInstance().getConfigurationManager()
                .getResourceByTenantId(IdentityTenantUtil.getTenantId(tenantDomain), X509_CA_CERT_RESOURCE_TYPE, CERTS);
    }

    private static IssuerDNMap getIssuerDNMap(Resource resource) throws IOException, ConfigurationManagementException {

        InputStream inputStream = getResourceFileInputStream(resource);
        if (inputStream == null) {
            return new IssuerDNMap();
        }
        return ModelSerializer.deserializeIssuerDNMap(convertInputStreamToString(inputStream));
    }

    private static String addCertificateToManagementService(X509Certificate certificate, String tenantDomain)
            throws CertificateMgtException, CertificateException {

        Certificate newCert = new Certificate.Builder()
                .name(X509_CERT_PREFIX + UUID.randomUUID())
                .certificateContent(encodeCertificate(certificate))
                .build();
        return CertValidationDataHolder.getInstance().getCertificateManagementService()
                .addCertificate(newCert, tenantDomain);
    }

    private static CertObject createCertObject(X509Certificate certificate, String certId, String serialNumber,
                                               List<String> ocspUrls, List<String> crlUrls)
            throws NoSuchAlgorithmException {

        CertObject certObject = new CertObject();
        certObject.setCertId(generateCertificateHash(certificate));
        certObject.setCertificatePersistedId(certId);
        certObject.setSerialNumber(serialNumber);
        certObject.setCrlUrls(crlUrls);
        certObject.setOcspUrls(ocspUrls);
        return certObject;
    }

    private static void addCertObjectToIssuerDNMap(IssuerDNMap issuerDNMap, String issuerDN, CertObject certObject,
                                                   String serialNumber) throws CertificateValidationException {

        List<CertObject> certList = issuerDNMap.getIssuerCertMap().computeIfAbsent(issuerDN, k -> new ArrayList<>());
        boolean serialExists = certList.stream()
                .anyMatch(cert -> getNormalizedName(cert.getSerialNumber()).equals(serialNumber));

        if (serialExists) {
            throw new CertificateValidationException("Certificate with the serial number: " + serialNumber +
                    " already exists for the issuerDN: " + issuerDN);
        } else {
            LOG.debug("Adding new certificate with serial number: " + serialNumber + " for issuerDN: " + issuerDN);
            certList.add(certObject);
        }
    }

    private static Optional<CertObject> handleResourceNotExists(X509Certificate certificate, String tenantDomain)
            throws CertificateValidationException, CertificateException, CertificateMgtException,
            NoSuchAlgorithmException, ConfigurationManagementException, IOException {

        IssuerDNMap issuerDNMap = new IssuerDNMap();
        String issuerDN = getNormalizedName(certificate.getIssuerDN().getName());
        String serialNumber = getNormalizedName(certificate.getSerialNumber().toString());

        List<String> ocspUrls = getValidationUrls(certificate, tenantDomain, OCSP_VALIDATOR);
        List<String> crlUrls = getValidationUrls(certificate, tenantDomain, CRL_VALIDATOR);

        String certId = addCertificateToManagementService(certificate, tenantDomain);
        CertObject certObject = createCertObject(certificate, certId, serialNumber, ocspUrls, crlUrls);

        List<CertObject> certObjectList = new ArrayList<>();
        certObjectList.add(certObject);
        issuerDNMap.getIssuerCertMap().put(issuerDN, certObjectList);

        saveNewResource(issuerDNMap);
        return Optional.of(certObject);
    }

    private static void saveNewResource(IssuerDNMap issuerDNMap) throws IOException, CertificateValidationException {

        String serializedContent = ModelSerializer.serializeIssuerDNMap(issuerDNMap);
        InputStream inputStream = new ByteArrayInputStream(serializedContent.getBytes(StandardCharsets.UTF_8));

        ResourceFile resourceFile = new ResourceFile();
        resourceFile.setName(X509_CA_CERT_FILE);
        resourceFile.setInputStream(inputStream);

        Resource resource = new Resource(CERTS, X509_CA_CERT_RESOURCE_TYPE);
        resource.setHasFile(true);
        resource.setFiles(new ArrayList<>());
        resource.getFiles().add(resourceFile);

        addResource(resource);
    }

    private static void saveUpdatedResource(Resource resource, IssuerDNMap issuerDNMap)
            throws IOException, ConfigurationManagementException {

        String serializedContent = ModelSerializer.serializeIssuerDNMap(issuerDNMap);
        InputStream inputStreamUpdated = new ByteArrayInputStream(serializedContent.getBytes(StandardCharsets.UTF_8));

        ResourceFile resourceFileUpdated = new ResourceFile();
        resourceFileUpdated.setName(X509_CA_CERT_FILE);
        resourceFileUpdated.setInputStream(inputStreamUpdated);
        resource.getFiles().set(0, resourceFileUpdated);

        CertValidationDataHolder.getInstance().getConfigurationManager()
                .replaceResource(X509_CA_CERT_RESOURCE_TYPE, resource);
    }

    private static void addValidatorsToConfigurationStore(List<Validator> defaultValidatorConfig)
            throws CertificateValidationException {

        for (Validator validator : defaultValidatorConfig) {
            String displayName = validator.getDisplayName();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Adding the configurations for validator: " + displayName);
            }
            Resource validatorResource =
                    buildResourceFromValidator(validator, getNormalizedName(displayName));
            addResource(validatorResource);
        }
    }

    /**
     * Builds a Resource object from the Validator configuration.
     *
     * @param validator    Validator configuration object.
     * @param resourceName Resource name.
     * @return A new Resource object with the validator's properties.
     */
    private static Resource buildResourceFromValidator(Validator validator, String resourceName) {

        Resource resource = new Resource(resourceName, VALIDATOR_RESOURCE_TYPE);
        resource.setHasAttribute(true);
        createAttributeList(validator, resource);

        return resource;
    }

    private static void createAttributeList(Validator validator, Resource resource) {

        List<Attribute> attributes = new ArrayList<>();
        attributes.add(new Attribute(VALIDATOR_CONF_NAME, validator.getName()));
        attributes.add(new Attribute(VALIDATOR_CONF_ENABLE,
                Boolean.toString(validator.isEnabled())));
        attributes.add(new Attribute(VALIDATOR_CONF_PRIORITY,
                Integer.toString(validator.getPriority())));
        attributes.add(new Attribute(VALIDATOR_CONF_FULL_CHAIN_VALIDATION,
                Boolean.toString(validator.isFullChainValidationEnabled())));
        attributes.add(new Attribute(VALIDATOR_CONF_RETRY_COUNT,
                Integer.toString(validator.getRetryCount())));
        resource.setAttributes(attributes);
    }

    private static void addCACertificateInConfigurationStore(List<Validator> validators,
                                                             List<X509Certificate> trustedCertificates,
                                                             String tenantDomain) throws
            CertificateValidationException, CertificateException, CertificateMgtException, IOException,
            NoSuchAlgorithmException {

        Map<String, List<CertObject>> issuerDNMap = new HashMap<>();
        for (X509Certificate certificate : trustedCertificates) {
            String issuerDN = getNormalizedName(certificate.getIssuerDN().getName());
            String serialNumber = getNormalizedName(certificate.getSerialNumber().toString());

            // Check if the serial number already exists for the given IssuerDN
            List<CertObject> existingCertObjects = issuerDNMap.computeIfAbsent(issuerDN, k -> new ArrayList<>());
            boolean isSerialNumberAlreadyAdded = existingCertObjects.stream()
                    .anyMatch(certObject -> certObject.getSerialNumber().equals(serialNumber));

            if (isSerialNumberAlreadyAdded) {
                LOG.warn("Certificate with serial number " + serialNumber + " already exists for IssuerDN " +
                        issuerDN);
                continue;
            }

            List<String> ocspUrls = new ArrayList<>();
            List<String> crlUrls = new ArrayList<>();
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

            Certificate cert = new Certificate.Builder()
                    .name(X509_CERT_PREFIX + UUID.randomUUID())
                    .certificateContent(encodeCertificate(certificate))
                    .build();
            String certId = CertValidationDataHolder.getInstance().getCertificateManagementService()
                    .addCertificate(cert, tenantDomain);

            CertObject certObject = new CertObject();
            certObject.setCertId(generateCertificateHash(certificate));
            certObject.setCertificatePersistedId(certId);
            certObject.setSerialNumber(serialNumber);
            certObject.setCrlUrls(crlUrls);
            certObject.setOcspUrls(ocspUrls);

            existingCertObjects.add(certObject);
        }

        IssuerDNMap combinedIssuerDNMap = new IssuerDNMap();
        for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.entrySet()) {
            String issuerDN = entry.getKey();
            List<CertObject> certObjects = entry.getValue();
            combinedIssuerDNMap.getIssuerCertMap().put(issuerDN, certObjects);
        }

        String serializedContent = ModelSerializer.serializeIssuerDNMap(combinedIssuerDNMap);
        InputStream inputStream = new ByteArrayInputStream(serializedContent.getBytes(StandardCharsets.UTF_8));
        try {
            Resource existingResource = CertValidationDataHolder.getInstance()
                    .getConfigurationManager()
                    .getResource(X509_CA_CERT_RESOURCE_TYPE, CERTS);

            if (existingResource != null) {
                saveUpdatedResource(existingResource, combinedIssuerDNMap);
            }

        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                ResourceFile resourceFile = new ResourceFile();
                resourceFile.setName(X509_CA_CERT_FILE);
                resourceFile.setInputStream(inputStream);

                Resource resource =
                        new Resource(CERTS, X509_CA_CERT_RESOURCE_TYPE);
                resource.setHasFile(true);
                resource.setFiles(new ArrayList<>());
                resource.getFiles().add(resourceFile);
                addResource(resource);
            } else {
                throw new CertificateValidationException("Error while adding validator configurations.", e);
            }
        }


    }

    private static List<CACertificate> getCACertsFromConfigStore(String issuerDN)
            throws CertificateValidationException, ConfigurationManagementException {

        Resource resource = CertValidationDataHolder.getInstance()
                .getConfigurationManager()
                .getResource(X509_CA_CERT_RESOURCE_TYPE, CERTS);

        List<CACertificate> certificateList = new ArrayList<>();

        try {
            List<ResourceFile> resourceFiles = resource.getFiles();
            if (resourceFiles == null || resourceFiles.isEmpty()) {
                LOG.warn("Resource files are empty for certificates in tenant: " + resource.getTenantDomain());
                return certificateList;
            }

            ResourceFile resourceFile = resourceFiles.get(0);
            if (resourceFile == null) {
                LOG.warn("Resource file is null for certificates in tenant: " + resource.getTenantDomain());
                return certificateList;
            }

            InputStream inputStream = CertValidationDataHolder.getInstance()
                    .getConfigurationManager()
                    .getFileById(X509_CA_CERT_RESOURCE_TYPE, CERTS, resourceFile.getId());

            if (inputStream == null) {
                LOG.warn("InputStream is null for the file in resource for IssuerDN: " + issuerDN);
                return certificateList;
            }

            String fileContent = convertInputStreamToString(inputStream);
            IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(fileContent);

            List<CertObject> certObjects = issuerDNMap.getIssuerCertMap().get(issuerDN);
            if (certObjects != null) {
                for (CertObject certObject : certObjects) {
                    // Extract details from the CertObject
                    String certId = certObject.getCertId();
                    List<String> crlUrls = certObject.getCrlUrls();
                    List<String> ocspUrls = certObject.getOcspUrls();

                    Certificate certificate = CertValidationDataHolder.getInstance()
                            .getCertificateManagementService()
                            .getCertificate(certId, PrivilegedCarbonContext.getThreadLocalCarbonContext()
                                    .getTenantDomain());

                    X509Certificate x509Certificate = decodeCertificate(certificate.getCertificateContent());

                    CACertificate caCertificate = new CACertificate(crlUrls, ocspUrls, x509Certificate);
                    certificateList.add(caCertificate);
                }
            }
        } catch (IOException e) {
            LOG.error("Error while reading the file content for IssuerDN: " + issuerDN, e);
            throw new CertificateValidationException("Error while reading the file content for IssuerDN: " +
                    issuerDN, e);
        } catch (Exception e) {
            LOG.error("Error while processing the resource for IssuerDN: " + issuerDN, e);
            throw new CertificateValidationException("Error while processing the resource for IssuerDN: " +
                    issuerDN, e);
        }

        return certificateList;
    }

    /**
     * Adds specified resource to the configuration management system.
     *
     * @param resource The resource object to add.
     * @throws CertificateValidationException If an error occurs while adding the resource.
     */
    private static void addResource(Resource resource) throws CertificateValidationException {

        try {
            CertValidationDataHolder.getInstance().getConfigurationManager()
                    .addResource(resource.getResourceType(), resource);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_ALREADY_EXISTS.getCode().equals(e.getErrorCode())) {
                LOG.debug("Resource already exists in the tenant config store.");
            } else {
                throw new CertificateValidationException("Error while adding validator configurations.", e);
            }
        }
    }

    private static String convertInputStreamToString(InputStream inputStream) throws IOException {

        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
        }
        return stringBuilder.toString();
    }
}
