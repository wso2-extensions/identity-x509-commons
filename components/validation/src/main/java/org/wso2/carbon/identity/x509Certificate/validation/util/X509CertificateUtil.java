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

package org.wso2.carbon.identity.x509Certificate.validation.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
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
import org.wso2.carbon.identity.x509Certificate.validation.internal.CertValidationDataHolder;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificateInfo;
import org.wso2.carbon.identity.x509Certificate.validation.model.CertObject;
import org.wso2.carbon.identity.x509Certificate.validation.model.IssuerDNMap;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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

/**
 * This class is used to provide utility methods for X509 certificate related operations.
 */
public class X509CertificateUtil {

    private static final Log LOG = LogFactory.getLog(X509CertificateUtil.class);

    /**
     * Converts a Resource object into a Validator object.
     *
     * @param resource The resource object to convert.
     * @return A Validator object populated with resource attributes.
     */
    public static Validator resourceToValidatorObject(
            Resource resource) {

        Validator validator = new Validator();
        List<Attribute> attributes = resource.getAttributes();
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
     * Generate thumbprint of certificate.
     *
     * @param encodedCert Base64 encoded certificate
     * @return Decoded <code>Certificate</code>
     * @throws CertificateException Error when decoding certificate
     */
    public static X509Certificate decodeCertificate(String encodedCert) throws CertificateException {

        if (encodedCert != null) {
            byte[] bytes = Base64.decode(encodedCert);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory
                    .generateCertificate(new ByteArrayInputStream(bytes));
        } else {
            throw new IllegalArgumentException("Invalid encoded certificate: \'NULL\'");
        }
    }

    /**
     * Get normalized name for the given name.
     *
     * @param name Name to be normalized
     * @return Normalized name
     */
    public static String getNormalizedName(String name) {

        if (StringUtils.isNotBlank(name)) {
            return name.replaceAll("\\s+", "").toLowerCase();
            //~!@#;%^*+={}|<>,\\'\\\\"\\\\\\\\()[]
        }
        throw new IllegalArgumentException("Invalid validator name provided : " + name);
    }

    /**
     * Get the ca certificate from the certificate manager.
     *
     * @param certificateId Certificate id
     * @param tenantDomain Tenant domain
     * @return X509Certificate
     * @throws CertificateValidationException Error when getting certificate
     */
    public static X509Certificate getCACertificateFromCertificateManager(String certificateId,
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
            } else {
                throw new CertificateValidationException("Error when getting certificate from certificate manager.", e);
            }
        } catch (CertificateException e) {
            LOG.debug("Error when decoding certificate.", e);
            throw new CertificateValidationException("Error when decoding certificate.", e);
        }
    }

    /**
     * Delete the ca certificate from the certificate manager.
     *
     * @param certificateId Certificate id
     * @param tenantDomain Tenant domain
     * @throws CertificateValidationException Error when deleting certificate
     */
    public static void deleteCACertificateFromCertificateManager(String certificateId,
                                                                 String tenantDomain)
            throws CertificateValidationException {

        try {
            CertValidationDataHolder.getInstance()
                    .getCertificateManagementService()
                    .deleteCertificate(certificateId, tenantDomain);
        } catch (CertificateMgtException e) {
            LOG.debug("Error when getting certificate from certificate manager.", e);
            if (CertificateMgtErrors.ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                throw new CertificateValidationException
                        ("Certificate with the id: " + certificateId + " does not exist.", e);
            } else {
                throw new CertificateValidationException("Error when getting certificate from certificate manager.", e);
            }
        }
    }

    /**
     * Get ca certificate from the configuration store.
     *
     * @param issuerDN Issuer DN
     * @param tenantId Tenant Id
     * @return List of CACertificate
     * @throws ConfigurationManagementException Error when getting resource
     * @throws CertificateValidationException Error when getting certificate
     */
    public static List<CACertificate> getCACertsFromConfigStore(String issuerDN, int tenantId) throws
            ConfigurationManagementException, CertificateValidationException {

        Resource resource = CertValidationDataHolder.getInstance()
                .getConfigurationManager()
                .getResourceByTenantId(tenantId, X509_CA_CERT_RESOURCE_TYPE, CERTS);

        return getCertificateListFromResourceAndIssuerDN(resource, issuerDN);
    }

    private static List<CACertificate> getCertificateListFromResourceAndIssuerDN(
            Resource resource, String issuerDN)
            throws CertificateValidationException {

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
     * Add certificate list in the configuration store.
     *
     * @param trustedCertificates List of trusted certificates
     * @param tenantId Tenant Id
     * @throws CertificateValidationException Error when adding certificate
     * @throws CertificateException Error when encoding certificate
     * @throws CertificateMgtException Error when adding certificate
     * @throws JsonProcessingException Error when serializing object
     * @throws ConfigurationManagementException Error when adding resource
     */
    public static void addCertificateListInConfigurationStore(List<X509Certificate> trustedCertificates,
                                                              int tenantId) throws
            CertificateValidationException, CertificateException, CertificateMgtException, JsonProcessingException,
            ConfigurationManagementException {

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

            // Process default validators for this certificate
            for (Validator validator : getValidatorsFromConfigStore(tenantId)) {
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
                    .addCertificate(cert, IdentityTenantUtil.getTenantDomain(tenantId));

            CertObject certObject = new CertObject();
            certObject.setCertId(certId); // Assuming serialNumber as certId for simplicity
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

        ResourceFile resourceFile = new ResourceFile();
        resourceFile.setName(X509_CA_CERT_FILE);
        resourceFile.setInputStream(inputStream);

        Resource resource =
                new Resource(CERTS, X509_CA_CERT_RESOURCE_TYPE);
        resource.setHasFile(true);
        resource.setFiles(new ArrayList<>());
        resource.getFiles().add(resourceFile);

        // Add the resource to the configuration store
        addResource(resource);
    }

    /**
     * Get certificate from the configuration store by certificate id.
     *
     * @param tenantId Tenant Id
     * @param certificateId Certificate Id
     * @return CACertificate
     * @throws CertificateValidationException Error when getting certificate
     */
    public static CACertificate getCertificateFromConfigurationStoreByCertificateId(int tenantId,
                                                                                    String certificateId)
            throws CertificateValidationException {

        try {
            Resource resource =
                    CertValidationDataHolder.getInstance().getConfigurationManager().getResourceByTenantId
                            (tenantId, X509_CA_CERT_RESOURCE_TYPE, CERTS);
            List<ResourceFile> resourceFiles = resource.getFiles();
            if (resourceFiles == null || resourceFiles.isEmpty()) {
                LOG.warn("Resource files are empty for certificates in tenant: " + resource.getTenantDomain());
                return null;
            }

            ResourceFile resourceFile = resourceFiles.get(0);
            if (resourceFile == null) {
                LOG.warn("Resource file is null for certificates in tenant: " + resource.getTenantDomain());
                return null;
            }

            InputStream inputStream = CertValidationDataHolder.getInstance()
                    .getConfigurationManager()
                    .getFileById(X509_CA_CERT_RESOURCE_TYPE, CERTS, resourceFile.getId());

            if (inputStream == null) {
                LOG.warn("InputStream is null for the file in resource.");
                return null;
            }

            String fileContent = convertInputStreamToString(inputStream);
            IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(fileContent);

            for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.getIssuerCertMap().entrySet()) {
                List<CertObject> certList = entry.getValue();
                Optional<CertObject> certObject = certList.stream()
                        .filter(cert -> cert.getCertId().equals(certificateId))
                        .findFirst();

                if (certObject.isPresent()) {
                    return new CACertificate(certObject.get().getCrlUrls(),
                            certObject.get().getOcspUrls(),
                            getCACertificateFromCertificateManager(certificateId,
                                    IdentityTenantUtil.getTenantDomain(tenantId)));
                }
            }
            return null;
        } catch (ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        } catch (IOException e) {
            throw new CertificateValidationException("Error while reading the file content", e);
        }
    }

    /**
     * Get the certificate list from the configuration store.
     *
     * @param tenantId Tenant Id
     * @return List of CACertificateInfo
     * @throws CertificateValidationException Error when getting certificate
     */
    public static List<CACertificateInfo> getCertificateListFromConfigurationStore(int tenantId)
            throws CertificateValidationException {
        try {
            org.wso2.carbon.identity.configuration.mgt.core.model.Resource resource = getResourceByTenantId(tenantId);
            if (resource == null) {
                return null;
            }
            InputStream inputStream = getResourceFileInputStream(resource);
            if (inputStream == null) {
                return new ArrayList<>();
            }
            return parseCertificateList(inputStream, tenantId);
        } catch (IOException | ConfigurationManagementException | CertificateException | CertificateMgtException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        }
    }

    private static org.wso2.carbon.identity.configuration.mgt.core.model.Resource getResourceByTenantId(int tenantId)
            throws ConfigurationManagementException {
        return CertValidationDataHolder.getInstance().getConfigurationManager()
                .getResourceByTenantId(tenantId, X509_CA_CERT_RESOURCE_TYPE, CERTS);
    }

    private static InputStream getResourceFileInputStream
            (org.wso2.carbon.identity.configuration.mgt.core.model.Resource resource)
            throws ConfigurationManagementException {

        List<ResourceFile> resourceFiles = resource.getFiles();
        if (resourceFiles == null || resourceFiles.isEmpty()) {
            LOG.debug("Resource files are empty for certificates in tenant: " + resource.getTenantDomain());
            return null;
        }
        ResourceFile resourceFile = resourceFiles.get(0);
        return resourceFile != null ? CertValidationDataHolder.getInstance().getConfigurationManager()
                .getFileById(X509_CA_CERT_RESOURCE_TYPE, CERTS, resourceFile.getId()) : null;
    }

    private static List<CACertificateInfo> parseCertificateList(InputStream inputStream, int tenantId)
            throws IOException, CertificateMgtException, CertificateException {
        List<CACertificateInfo> certificateList = new ArrayList<>();
        String fileContent = convertInputStreamToString(inputStream);
        IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(fileContent);

        for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.getIssuerCertMap().entrySet()) {
            for (CertObject certObject : entry.getValue()) {
                certificateList.add(convertCertObjectToCACertificateInfo(certObject, tenantId));
            }
        }
        return certificateList;
    }

    private static CACertificateInfo convertCertObjectToCACertificateInfo(CertObject certObject, int tenantId)
            throws CertificateMgtException, CertificateException {
        Certificate certificate = CertValidationDataHolder.getInstance()
                .getCertificateManagementService()
                .getCertificate(certObject.getCertId(), IdentityTenantUtil.getTenantDomain(tenantId));
        X509Certificate x509Certificate = decodeCertificate(certificate.getCertificateContent());

        CACertificateInfo caCertificate = new CACertificateInfo();
        caCertificate.setCertId(certObject.getCertId());
        caCertificate.setIssuerDN(getNormalizedName(x509Certificate.getIssuerDN().getName()));
        caCertificate.setSerialNumber(getNormalizedName(x509Certificate.getSerialNumber().toString()));
        caCertificate.setCrlUrls(certObject.getCrlUrls());
        caCertificate.setOcspUrls(certObject.getOcspUrls());
        return caCertificate;
    }

    private static CertObject processCertificateInStore(int tenantId, X509Certificate certificate,
                                                        String certificateId, boolean isUpdate)
            throws CertificateValidationException {

        try {
            org.wso2.carbon.identity.configuration.mgt.core.model.Resource resource = getResourceByTenantId(tenantId);
            InputStream inputStream = getResourceFileInputStream(resource);
            if (inputStream == null) {
                return null;
            }

            IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(convertInputStreamToString(inputStream));
            String issuerDN = getNormalizedName(certificate.getIssuerDN().getName());
            String serialNumber = getNormalizedName(certificate.getSerialNumber().toString());

            List<String> ocspUrls = getValidationUrls(certificate, tenantId, OCSP_VALIDATOR);
            List<String> crlUrls = getValidationUrls(certificate, tenantId, CRL_VALIDATOR);

            CertObject certObject = new CertObject();
            certObject.setCertId(isUpdate ? certificateId : UUID.randomUUID().toString());
            certObject.setSerialNumber(serialNumber);
            certObject.setCrlUrls(crlUrls);
            certObject.setOcspUrls(ocspUrls);

            updateIssuerDNMap(issuerDNMap, issuerDN, serialNumber, certObject);

            return saveUpdatedResource(resource, issuerDNMap);
        } catch (ConfigurationManagementException | IOException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        }
    }

    private static List<String> getValidationUrls(X509Certificate certificate, int tenantId, String validatorType)
            throws ConfigurationManagementException, CertificateValidationException {

        List<String> urls = new ArrayList<>();
        if (!isSelfSignedCert(certificate)) {
            for (Validator validator : getValidatorsFromConfigStore(tenantId)) {
                if (validator.isEnabled() && validatorType.equals(validator.getDisplayName())) {
                    urls = validatorType.equals(OCSP_VALIDATOR) ? getAIALocations(certificate) :
                            getCRLUrls(certificate);
                }
            }
        }
        return urls;
    }

    private static void updateIssuerDNMap(IssuerDNMap issuerDNMap, String issuerDN, String serialNumber,
                                          CertObject certObject)
            throws CertificateValidationException {

        List<CertObject> certList = issuerDNMap.getIssuerCertMap().computeIfAbsent(issuerDN, k -> new ArrayList<>());
        boolean serialExists = certList.stream()
                .anyMatch(cert -> getNormalizedName(cert.getSerialNumber().toString()).equals(serialNumber));

        if (serialExists) {
            throw new CertificateValidationException("Certificate with serial number " + serialNumber +
                    " already exists.");
        }
        certList.add(certObject);
    }

    private static CertObject saveUpdatedResource
            (org.wso2.carbon.identity.configuration.mgt.core.model.Resource resource, IssuerDNMap issuerDNMap)
            throws IOException, ConfigurationManagementException {

        String serializedContent = ModelSerializer.serializeIssuerDNMap(issuerDNMap);
        InputStream inputStreamUpdated = new ByteArrayInputStream(serializedContent.getBytes(StandardCharsets.UTF_8));

        ResourceFile resourceFileUpdated = new ResourceFile();
        resourceFileUpdated.setName(X509_CA_CERT_FILE);
        resourceFileUpdated.setInputStream(inputStreamUpdated);
        resource.getFiles().set(0, resourceFileUpdated);

        CertValidationDataHolder.getInstance().getConfigurationManager()
                .replaceResource(X509_CA_CERT_RESOURCE_TYPE, resource);

        return new CertObject();
    }

    /**
     * Add a certificate in the configuration store.
     *
     * @param tenantId Tenant Id
     * @param certificate X509Certificate
     * @return CertObject
     * @throws CertificateValidationException Error when adding certificate
     * @throws CertificateException Error when encoding certificate
     * @throws CertificateMgtException Error when adding certificate
     */
    public static CertObject addCertificateInConfigurationStore(int tenantId, X509Certificate certificate)
            throws CertificateValidationException, CertificateException, CertificateMgtException {

        return processCertificateInStore(tenantId, certificate, null, false);
    }

    /**
     * Update a certificate in the configuration store by certificate id.
     *
     * @param certificateId Certificate Id
     * @param certificate X509Certificate
     * @param tenantId Tenant Id
     * @return CertObject
     * @throws CertificateValidationException Error when updating certificate
     * @throws CertificateException Error when encoding certificate
     * @throws CertificateMgtException Error when updating certificate
     */
    public static CertObject updateCertificateInConfigurationStoreByCertificateId(String certificateId,
                                                                                  X509Certificate certificate,
                                                                                  int tenantId)
            throws CertificateValidationException, CertificateException, CertificateMgtException {

        return processCertificateInStore(tenantId, certificate, certificateId, true);
    }

    /**
     * Delete a certificate in the configuration store by certificate id.
     *
     * @param certificateId Certificate Id
     * @param tenantId Tenant Id
     * @return CertObject
     * @throws CertificateValidationException Error when deleting certificate
     */
    public static CertObject deleteCertificateInConfigurationStoreByCertificateId(String certificateId, int tenantId)
            throws CertificateValidationException {

        try {
            org.wso2.carbon.identity.configuration.mgt.core.model.Resource resource = getResourceByTenantId(tenantId);
            InputStream inputStream = getResourceFileInputStream(resource);
            if (inputStream == null) {
                return null;
            }

            IssuerDNMap issuerDNMap = ModelSerializer.deserializeIssuerDNMap(convertInputStreamToString(inputStream));

            for (Map.Entry<String, List<CertObject>> entry : issuerDNMap.getIssuerCertMap().entrySet()) {
                List<CertObject> certList = entry.getValue();
                if (certList.removeIf(cert -> cert.getCertId().equals(certificateId))) {
                    if (certList.isEmpty()) {
                        issuerDNMap.getIssuerCertMap().remove(entry.getKey());
                    }
                    return saveUpdatedResource(resource, issuerDNMap);
                }
            }
            return null;
        } catch (IOException | ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while processing the resource", e);
        }
    }

    /**
     * Update the CA certificate in the certificate manager.
     *
     * @param certificateId Certificate id
     * @param certificate X509Certificate
     * @param tenantDomain Tenant domain
     * @return X509Certificate
     * @throws CertificateValidationException Error when updating certificate
     */
    public static X509Certificate updateCACertificateInCertificateManager(String certificateId,
                                                                          X509Certificate certificate,
                                                                          String tenantDomain)
            throws CertificateValidationException {

        try {
            Certificate deletedCertificate = CertValidationDataHolder.getInstance()
                    .getCertificateManagementService()
                    .getCertificate(certificateId, tenantDomain);
            CertValidationDataHolder.getInstance()
                    .getCertificateManagementService()
                    .updateCertificateContent(certificateId, encodeCertificate(certificate), tenantDomain);
            LOG.debug("Successfully updated certificate with the id: " + certificateId + " in certificate manager.");
            return decodeCertificate(deletedCertificate.getCertificateContent());
        } catch (CertificateMgtException e) {
            LOG.debug("Error when getting certificate from certificate manager.", e);
            if (CertificateMgtErrors.ERROR_CERTIFICATE_DOES_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                throw new CertificateValidationException
                        ("Certificate with the id: " + certificateId + " does not exist.", e);
            } else {
                throw new CertificateValidationException("Error when updating certificate in certificate manager.", e);
            }
        } catch (CertificateException e) {
            LOG.debug("Error when decoding certificate.", e);
            throw new CertificateValidationException("Error when encoding certificate.", e);
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

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point" extension in a X.509 certificate.
     * If CRL distribution point extension or CRL Urls are unavailable, throw an exception.
     *
     * @param cert X509 certificate
     * @return List of CRL Urls in the certificate
     * @throws CertificateValidationException certificateValidationException
     */
    public static List<String> getCRLUrls(X509Certificate cert) throws CertificateValidationException {

        List<String> crlUrls;
        byte[] crlDPExtensionValue = getCRLDPExtensionValue(cert);
        if (crlDPExtensionValue == null) {
            throw new CertificateValidationException("Certificate with serial num:" + cert.getSerialNumber() +
                    " doesn't have CRL Distribution points");
        }
        CRLDistPoint distPoint = getCrlDistPoint(crlDPExtensionValue);
        crlUrls = getCrlUrlsFromDistPoint(distPoint);

        if (crlUrls.isEmpty()) {
            throw new CertificateValidationException("Cant get CRL urls from certificate with serial num:" +
                    cert.getSerialNumber());
        }
        return crlUrls;
    }

    private static List<String> getCrlUrlsFromDistPoint(CRLDistPoint distPoint) {

        List<String> crlUrls = new ArrayList<>();
        //Loop through ASN1Encodable DistributionPoints
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            //get ASN1Encodable DistributionPointName
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                //Create ASN1Encodable General Names
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                // Look for a URI
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        // ASN1IA5String contains an ascii string.
                        // A IA5String is a restricted character string type in the ASN.1 notation
                        String url = ASN1IA5String.getInstance(genName.getName()).getString().trim();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

    private static CRLDistPoint getCrlDistPoint(byte[] crlDPExtensionValue) throws CertificateValidationException {

        //crlDPExtensionValue is encoded in ASN.1 format
        ASN1InputStream asn1In = new ASN1InputStream(crlDPExtensionValue);
        //DER (Distinguished Encoding Rules) is one of ASN.1 encoding rules defined in ITU-T X.690, 2002, specification.
        //ASN.1 encoding rules can be used to encode any data object into a binary file. Read the object in octets.
        CRLDistPoint distPoint;
        try {
            DEROctetString crlDEROctetString = (DEROctetString) asn1In.readObject();
            //Get Input stream in octets
            ASN1InputStream asn1InOctets = new ASN1InputStream(crlDEROctetString.getOctets());
            ASN1Primitive crlDERObject = asn1InOctets.readObject();
            distPoint = CRLDistPoint.getInstance(crlDERObject);
        } catch (IOException e) {
            throw new CertificateValidationException("Cannot read certificate to get CRL urls", e);
        }
        return distPoint;
    }

    private static byte[] getCRLDPExtensionValue(X509Certificate cert) {

        //DER-encoded octet string of the extension value for CRLDistributionPoints identified by the passed-in oid
        return cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
    }

    /**
     * Builds a Resource object from the Validator configuration.
     *
     * @param validator     Validator configuration object.
     * @param resourceName  Resource name.
     * @return A new Resource object with the validator's properties.
     */
    public static Resource buildResourceFromValidator(
            Validator validator, String resourceName) {

        Resource resource =
                new Resource(resourceName,
                        VALIDATOR_RESOURCE_TYPE);
        resource.setHasAttribute(true);
        createAttributeList(validator, resource);

        return resource;
    }

    /**
     * Adds specified resource to the configuration management system.
     *
     * @param resource                          The resource object to add.
     * @throws CertificateValidationException   If an error occurs while adding the resource.
     */
    public static Validator addResource(
            Resource resource)
            throws ConfigurationManagementException {

        Resource updatedResource =
                CertValidationDataHolder.getInstance().getConfigurationManager()
                        .addResource(resource.getResourceType(), resource);
        return resourceToValidatorObject(updatedResource);
    }

    /**
     * Authority Information Access (AIA) is a non-critical extension in an X509 Certificate. This contains the
     * URL of the OCSP endpoint if one is available.
     *
     * @param cert is the certificate
     * @return a list of URLs in AIA extension of the certificate which will hopefully contain an OCSP endpoint
     * @throws CertificateValidationException certificateValidationException
     */
    public static List<String> getAIALocations(X509Certificate cert) throws CertificateValidationException {

        List<String> ocspUrlList;
        byte[] aiaExtensionValue = getAiaExtensionValue(cert);
        if (aiaExtensionValue == null) {
            throw new CertificateValidationException("Certificate with serial num: " +
                    cert.getSerialNumber() + " doesn't have Authority Information Access points");
        }
        AuthorityInformationAccess authorityInformationAccess = getAuthorityInformationAccess(aiaExtensionValue);
        ocspUrlList = getOcspUrlsFromAuthorityInfoAccess(authorityInformationAccess);

        if (ocspUrlList.isEmpty()) {
            throw new CertificateValidationException("Cant get OCSP urls from certificate with serial num: " +
                    cert.getSerialNumber());
        }

        return ocspUrlList;
    }

    private static List<String> getOcspUrlsFromAuthorityInfoAccess(AuthorityInformationAccess
                                                                           authorityInformationAccess) {

        List<String> ocspUrlList = new ArrayList<>();
        AccessDescription[] accessDescriptions;
        if (authorityInformationAccess != null) {
            accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (AccessDescription accessDescription : accessDescriptions) {
                if (X509ObjectIdentifiers.ocspAccessMethod.equals(accessDescription.getAccessMethod())) {
                    GeneralName gn = accessDescription.getAccessLocation();
                    if (gn != null && gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        ASN1IA5String str = ASN1IA5String.getInstance(gn.getName());
                        String accessLocation = str.getString();
                        ocspUrlList.add(accessLocation);
                    }
                }
            }
        }
        return ocspUrlList;
    }

    private static AuthorityInformationAccess getAuthorityInformationAccess(byte[] aiaExtensionValue)
            throws CertificateValidationException {

        AuthorityInformationAccess authorityInformationAccess;
        try {
            DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(aiaExtensionValue))
                    .readObject());
            authorityInformationAccess = AuthorityInformationAccess.getInstance(new ASN1InputStream(oct.getOctets())
                    .readObject());
        } catch (IOException e) {
            throw new CertificateValidationException("Cannot read certificate to get OSCP urls", e);
        }
        return authorityInformationAccess;
    }

    private static byte[] getAiaExtensionValue(X509Certificate cert) {

        //Gets the DER-encoded OCTET string for the extension value for Authority information access Points
        return cert.getExtensionValue(Extension.authorityInfoAccess.getId());
    }

    /**
     * Encode X509 Certificate.
     *
     * @param certificate certificate to get encoded
     * @return encoded certificate
     * @throws CertificateException certificateException
     */
    private static String encodeCertificate(X509Certificate certificate) throws CertificateException {

        if (certificate != null) {
            return Base64.encode(certificate.getEncoded());
        } else {
            String errorMsg = "Invalid encoded certificate: \'NULL\'";
            LOG.debug(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
    }

    /**
     * Checks whether the given certificate is a self-signed certificate.
     *
     * @param cert X509Certificate
     * @return true if the certificate is self-signed, false otherwise
     */
    private static boolean isSelfSignedCert(X509Certificate cert) {

        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (CertificateException | NoSuchProviderException | SignatureException | NoSuchAlgorithmException |
                 InvalidKeyException e) {
            return false;
        }
    }

    /**
     * Get validators from the configuration store.
     *
     * @param tenantId Tenant Id
     * @return List of Validator
     * @throws ConfigurationManagementException Error when getting resource
     */
    public static List<Validator> getValidatorsFromConfigStore(int tenantId)
            throws ConfigurationManagementException {

        List<Validator> validators = new ArrayList<>();
        Resources resources = CertValidationDataHolder.getInstance().getConfigurationManager()
                .getResourcesByType(tenantId, VALIDATOR_RESOURCE_TYPE);
        resources.getResources().forEach(resource -> validators
                .add(resourceToValidatorObject(resource)));
        return validators;
    }

    /**
     * Get validator from the configuration store by name.
     *
     * @param tenantId Tenant Id
     * @param name Validator name
     * @return Validator
     * @throws CertificateValidationException Error when getting validator
     */
    public static Validator getValidatorFromConfigStoreByName(int tenantId, String name)
            throws CertificateValidationException {

        try {
            Resource resource =
                    CertValidationDataHolder.getInstance().getConfigurationManager()
                            .getResourceByTenantId(tenantId, VALIDATOR_RESOURCE_TYPE, name);
            if (resource == null) {
                return null;
            }
            return resourceToValidatorObject(resource);
        } catch (ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while fetching validator configurations.", e);
        }
    }

    /**
     * Update validator in the configuration store.
     *
     * @param tenantId Tenant Id
     * @param validator Validator
     * @return Validator
     * @throws CertificateValidationException Error when updating validator
     */
    public static Validator updateValidatorInConfigStore(int tenantId, Validator validator)
            throws CertificateValidationException {

        try {
            Resource resource =
                    CertValidationDataHolder.getInstance().getConfigurationManager()
                            .getResourceByTenantId(tenantId, VALIDATOR_RESOURCE_TYPE, validator.getName());
            if (resource == null) {
                return null;
            }
            createAttributeList(validator, resource);
            Resource updatedResource =
                    CertValidationDataHolder.getInstance().getConfigurationManager()
                            .replaceResource(VALIDATOR_RESOURCE_TYPE, resource);
            return resourceToValidatorObject(updatedResource);
        } catch (ConfigurationManagementException e) {
            throw new CertificateValidationException("Error while fetching validator configurations.", e);
        }
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

    /**
     * Start tenant flow.
     *
     * @param tenantId Tenant Id
     */
    public static void startTenantFlow(int tenantId) {

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
            carbonContext.setTenantId(tenantId);
            carbonContext.setTenantDomain(tenantDomain);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}
