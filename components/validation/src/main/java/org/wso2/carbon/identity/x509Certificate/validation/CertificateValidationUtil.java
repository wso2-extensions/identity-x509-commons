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

package org.wso2.carbon.identity.x509Certificate.validation;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.x509Certificate.validation.cache.CRLCache;
import org.wso2.carbon.identity.x509Certificate.validation.cache.CRLCacheEntry;
import org.wso2.carbon.identity.x509Certificate.validation.internal.CertValidationDataHolder;
import org.wso2.carbon.identity.x509Certificate.validation.model.CACertificate;
import org.wso2.carbon.identity.x509Certificate.validation.model.Validator;
import org.wso2.carbon.identity.x509Certificate.validation.validator.RevocationValidator;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.CarbonUtils;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.registry.core.RegistryConstants.PATH_SEPARATOR;

public class CertificateValidationUtil {

    private static final String BC = "BC";
    private static final String CONTENT_TYPE = "text/xml; charset=utf-8";

    private static final Log log = LogFactory.getLog(CertificateValidationUtil.class);

    /**
     * ********************************************
     * Util methods for Validator Configurations
     * ********************************************
     */
    public static void addDefaultValidationConfigInRegistry(String tenantDomain) {

        File validatorConfigFile = getValidatorConfigFile();
        if (validatorConfigFile != null) {
            if (tenantDomain == null) {
                tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            }

            InputStream inputStream = null;
            try {
                inputStream = new FileInputStream(validatorConfigFile);
                StAXOMBuilder builder = new StAXOMBuilder(inputStream);

                OMElement documentElement = builder.getDocumentElement();
                Iterator iterator = documentElement.getChildElements();
                while (iterator.hasNext()) {
                    OMElement childElement = (OMElement) iterator.next();
                    if (isValidatorConfigProperty(childElement)) {
                        addDefaultValidatorConfig(childElement, tenantDomain);
                    } else if (isTrustStoreConfigProperty(childElement)) {
                        addDefaultCACertificates(childElement, tenantDomain);
                    }
                }
            } catch (XMLStreamException | FileNotFoundException e) {
                log.warn("Error while loading default validator configurations to the registry.", e);
            } finally {
                try {
                    if (inputStream != null) {
                        inputStream.close();
                    }
                } catch (IOException e) {
                    log.error("Error while closing input stream", e);
                }
            }
        }
    }

    /**
     * Load Validator Configurations from Registry and return the enabled validators' configurations
     *
     * @return List of registered validators
     * @throws CertificateValidationException certificateValidationException
     */
    public static List<RevocationValidator> loadEnabledValidatorConfigFromRegistry()
            throws CertificateValidationException {

        String validatorConfRegPath = X509CertificateValidationConstants.VALIDATOR_CONF_REG_PATH;
        List<RevocationValidator> validators = null;

        try {
            if (log.isDebugEnabled()) {
                log.debug("Loading X509 certificate validator configurations from registry in: " +
                        validatorConfRegPath);
            }
            //get tenant registry for loading validator configurations
            Registry registry = getGovernanceRegistry(
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            if (registry.resourceExists(validatorConfRegPath)) {
                if (log.isDebugEnabled()) {
                    log.debug("Validator configurations are available in registry path: " + validatorConfRegPath);
                }
                validators = getEnabledValidatorsFromRegistryResource(registry, validatorConfRegPath);
            }
        } catch (RegistryException e) {
            throw new CertificateValidationException("Error while loading validator configurations from registry in: " +
                    validatorConfRegPath, e);
        }
        return validators;
    }

    private static File getValidatorConfigFile() {

        String configFilePath = CarbonUtils.getCarbonConfigDirPath() + File.separator +
                X509CertificateValidationConstants.CERT_VALIDATION_CONF_DIRECTORY + File.separator +
                X509CertificateValidationConstants.CERT_VALIDATION_CONF_FILE;

        File configFile = new File(configFilePath);
        if (!configFile.exists()) {
            log.error("Certification validation Configuration File is not available at: " + configFilePath);
            return null;
        }
        return configFile;
    }

    private static boolean isTrustStoreConfigProperty(OMElement childElement) {

        return childElement.getLocalName().equals(X509CertificateValidationConstants.TRUSTSTORE_CONF);
    }

    private static boolean isValidatorConfigProperty(OMElement childElement) {

        return childElement.getLocalName().equals(X509CertificateValidationConstants.VALIDATOR_CONF);
    }

    private static void addDefaultValidatorConfig(OMElement validatorsElement, String tenantDomain) {

        List<Validator> defaultValidatorConfig = getDefaultValidatorConfig(validatorsElement);

        // iterate through the validator config list and write to the the registry
        for (Validator validator : defaultValidatorConfig) {
            String validatorConfRegPath = X509CertificateValidationConstants.VALIDATOR_CONF_REG_PATH +
                    PATH_SEPARATOR + getNormalizedName(validator.getDisplayName());
            if (log.isDebugEnabled()) {
                log.debug("Adding default validator configurations to registry in: " +
                        validatorConfRegPath);
            }
            try {
                Registry registry = getGovernanceRegistry(tenantDomain);
                if (!registry.resourceExists(validatorConfRegPath)) {
                    addValidatorConfigInRegistry(registry, validatorConfRegPath, validator);
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Validator configuration for %s is added to %s tenant registry.",
                                validator.getDisplayName(), tenantDomain));
                    }
                }
            } catch (RegistryException | CertificateValidationException e) {
                log.error("Error while adding validator configurations in registry.", e);
            }
        }
    }

    private static List<Validator> getDefaultValidatorConfig(OMElement validatorsElement) {

        List<Validator> defaultValidatorConfig = new ArrayList<>();
        Iterator validatorIterator = validatorsElement.getChildElements();
        while (validatorIterator.hasNext()) {
            OMElement validatorElement = (OMElement) validatorIterator.next();
            String name = validatorElement.getAttributeValue(
                    new QName(X509CertificateValidationConstants.VALIDATOR_CONF_NAME));
            String displayName = validatorElement.getAttributeValue(
                    new QName(X509CertificateValidationConstants.VALIDATOR_CONF_DISPLAY_NAME));
            String enable = validatorElement.getAttributeValue(
                    new QName(X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE));

            Map<String, String> validatorProperties = getValidatorProperties(validatorElement);
            String priority = validatorProperties.get(X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY);
            String fullChainValidation = validatorProperties.get(
                    X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION);
            String retryCount = validatorProperties.get(X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT);

            Validator validator = new Validator(name, displayName, Boolean.parseBoolean(enable),
                    Integer.parseInt(priority), Boolean.parseBoolean(fullChainValidation), Integer.parseInt(retryCount));
            defaultValidatorConfig.add(validator);
        }
        return defaultValidatorConfig;
    }

    private static void addValidatorConfigInRegistry(Registry registry, String validatorConfRegPath,
                                                     Validator validator) throws RegistryException {

        Resource resource = registry.newResource();
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_NAME, validator.getName());
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE,
                Boolean.toString(validator.isEnabled()));
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY,
                Integer.toString(validator.getPriority()));
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION,
                Boolean.toString(validator.isFullChainValidationEnabled()));
        resource.addProperty(X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT,
                Integer.toString(validator.getRetryCount()));
        registry.put(validatorConfRegPath, resource);
    }

    private static Map<String, String> getValidatorProperties(OMElement validatorElement) {

        Map<String, String> validatorProperties = new HashMap<>();
        Iterator it = validatorElement.getChildElements();
        while (it.hasNext()) {
            OMElement validatorParamElement = (OMElement) it.next();
            if (validatorParamElement != null) {
                String attributeName = validatorParamElement.getAttributeValue(new QName(
                        X509CertificateValidationConstants.VALIDATOR_CONF_ELEMENT_PROPERTY_NAME));
                String attributeValue = validatorParamElement.getText();
                validatorProperties.put(attributeName, attributeValue);
            }
        }
        return validatorProperties;
    }

    private static List<RevocationValidator> getEnabledValidatorsFromRegistryResource(Registry registry,
                                                                                      String validatorConfRegPath)
            throws RegistryException {

        List<RevocationValidator> validators = new ArrayList<>();
        Collection collection = (Collection) registry.get(validatorConfRegPath);
        if (collection != null) {
            String[] children = collection.getChildren();
            for (String child : children) {
                Resource resource = registry.get(child);
                Validator validator = resourceToValidatorObject(resource);

                if (validator.isEnabled()) {
                    RevocationValidator revocationValidator;
                    try {
                        Class<?> clazz = Class.forName(validator.getName());
                        Constructor<?> constructor = clazz.getConstructor();
                        revocationValidator = (RevocationValidator) constructor.newInstance();
                    } catch (ClassNotFoundException | InvocationTargetException | NoSuchMethodException |
                            InstantiationException | IllegalAccessException e) {
                        continue;
                    }
                    revocationValidator.setEnable(validator.isEnabled());
                    revocationValidator.setPriority(validator.getPriority());
                    revocationValidator.setFullChainValidation(validator.isFullChainValidationEnabled());
                    revocationValidator.setRetryCount(validator.getRetryCount());
                    validators.add(revocationValidator);
                }
            }
        }
        return validators;
    }

    private static Validator resourceToValidatorObject(Resource resource) {

        Validator validator = new Validator();
        validator.setName(resource.getProperty(X509CertificateValidationConstants.VALIDATOR_CONF_NAME));
        validator.setEnabled(Boolean.parseBoolean(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_ENABLE)));
        validator.setPriority(Integer.parseInt(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_PRIORITY)));
        validator.setFullChainValidationEnabled(Boolean.parseBoolean(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_FULL_CHAIN_VALIDATION)));
        validator.setRetryCount(Integer.parseInt(resource.getProperty(
                X509CertificateValidationConstants.VALIDATOR_CONF_RETRY_COUNT)));
        return validator;
    }

    /**
     * ****************************************
     * Util methods for CA Cert Configuration
     * ****************************************
     */

    /**
     * Load CA certificates from registry
     *
     * @param peerCertificate peer certificate
     * @return List of issuer CA certificates
     * @throws CertificateValidationException certificateValidationException
     */
    public static List<CACertificate> loadCaCertsFromRegistry(X509Certificate peerCertificate)
            throws CertificateValidationException {

        List<CACertificate> caCertificateList;
        String caRegPath = null;
        try {
            caRegPath = getCACertsRegPath(peerCertificate);
            if (log.isDebugEnabled()) {
                log.debug("CA certificate registry full path: " + caRegPath);
            }
            caCertificateList = getCACertsFromRegResource(caRegPath);
        } catch (RegistryException | UnsupportedEncodingException e) {
            throw new CertificateValidationException("Error while loading CA certificates from registry in:" +
                    caRegPath, e);
        }
        return caCertificateList;
    }

    private static void addDefaultCACertificates(OMElement trustStoresElement, String tenantDomain) {

        try {
            Iterator trustStoreIterator = trustStoresElement.getChildElements();
            Registry registry = getGovernanceRegistry(tenantDomain);
            List<X509Certificate> trustedCertificates = new ArrayList<>();

            while (trustStoreIterator.hasNext()) {
                getAllTrustedCerts(trustStoreIterator, trustedCertificates);
            }

            for (X509Certificate certificate : trustedCertificates) {
                String caCertRegPath = getCACertRegFullPath(certificate);
                if (log.isDebugEnabled()) {
                    log.debug("CA certificate registry path: " + caCertRegPath);
                }
                addDefaultCACertificateInRegistry(registry, caCertRegPath, certificate);
            }

        } catch (UnsupportedEncodingException | CertificateValidationException e) {
            log.error("Error while adding validator configurations in registry.", e);
        }
    }

    private static String getCACertRegFullPath(X509Certificate certificate) throws UnsupportedEncodingException {

        return X509CertificateValidationConstants.CA_CERT_REG_PATH +
                PATH_SEPARATOR +
                URLEncoder.encode(getNormalizedName(certificate.getSubjectDN().getName()), "UTF-8").
                        replaceAll("%", ":") + PATH_SEPARATOR +
                getNormalizedName(certificate.getSerialNumber().toString());
    }

    private static String getCACertsRegPath(X509Certificate peerCertificate) throws UnsupportedEncodingException {

        return X509CertificateValidationConstants.CA_CERT_REG_PATH +
                PATH_SEPARATOR + URLEncoder.encode(getNormalizedName(peerCertificate.getIssuerDN().getName()), "UTF-8").
                replaceAll("%", ":");
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

    private static CACertificate resourceToCACertObject(Resource resource) throws CertificateValidationException {

        List<String> crlUrls;
        List<String> ocspUrls;
        X509Certificate x509Certificate;
        try {
            String crlUrlReg = resource.getProperty(X509CertificateValidationConstants.CA_CERT_REG_CRL);
            String ocspUrlReg = resource.getProperty(X509CertificateValidationConstants.CA_CERT_REG_OCSP);
            crlUrls = Arrays.asList(crlUrlReg.split(
                    X509CertificateValidationConstants.CA_CERT_REG_CRL_OCSP_SEPERATOR));
            ocspUrls = Arrays.asList(ocspUrlReg.split(
                    X509CertificateValidationConstants.CA_CERT_REG_CRL_OCSP_SEPERATOR));
            byte[] regContent = (byte[]) resource.getContent();
            x509Certificate = decodeCertificate(new String(regContent));
        } catch (RegistryException | CertificateException e) {
            throw new CertificateValidationException("Error when converting registry resource content.", e);
        }
        return new CACertificate(crlUrls, ocspUrls, x509Certificate);
    }

    private static void addDefaultCACertificateInRegistry(Registry registry, String caCertRegPath,
                                                          X509Certificate certificate)
            throws CertificateValidationException {

        try {
            if (!registry.resourceExists(caCertRegPath)) {
                Resource resource = registry.newResource();
                List<String> crlUrls = getCRLUrls(certificate);
                StringBuilder crlUrlReg = new StringBuilder();
                if (CollectionUtils.isNotEmpty(crlUrls)) {
                    for (String crlUrl : crlUrls) {
                        crlUrlReg.append(crlUrl).append(X509CertificateValidationConstants.
                                CA_CERT_REG_CRL_OCSP_SEPERATOR);
                    }
                }

                List<String> ocspUrls = getAIALocations(certificate);
                StringBuilder ocspUrlReg = new StringBuilder();
                if (CollectionUtils.isNotEmpty(ocspUrls)) {
                    for (String ocspUrl : ocspUrls) {
                        ocspUrlReg.append(ocspUrl).append(X509CertificateValidationConstants.
                                CA_CERT_REG_CRL_OCSP_SEPERATOR);
                    }
                }
                resource.addProperty(X509CertificateValidationConstants.CA_CERT_REG_CRL, crlUrlReg.toString());
                resource.addProperty(X509CertificateValidationConstants.CA_CERT_REG_OCSP, ocspUrlReg.toString());
                resource.setContent(encodeCertificate(certificate));
                registry.put(caCertRegPath, resource);
            }
        } catch (RegistryException e) {
            throw new CertificateValidationException("Error adding default ca certificate with serial num:" +
                    certificate.getSerialNumber() + " in registry.", e);
        } catch (CertificateException e) {
            throw new CertificateValidationException("Error encoding ca certificate with serial num: " +
                    certificate.getSerialNumber() + " to add in registry.", e);
        }
    }

    private static void getAllTrustedCerts(Iterator trustStoreIterator, List<X509Certificate> trustedCertificates) {

        OMElement trustStoreElement = (OMElement) trustStoreIterator.next();
        String trustStoreFile = trustStoreElement.getAttributeValue(
                new QName(X509CertificateValidationConstants.TRUSTSTORE_CONF_FILE));
        String trustStorePassword = trustStoreElement.getAttributeValue(
                new QName(X509CertificateValidationConstants.TRUSTSTORE_CONF_PASSWORD));

        KeyStore keyStore = CertificateValidationUtil.loadKeyStoreFromFile(trustStoreFile, trustStorePassword, null);
        try {
            trustedCertificates.addAll(CertificateValidationUtil.exportCertificateChainFromKeyStore(keyStore));
        } catch (KeyStoreException e) {
            log.error("Error while exporting certificate chain from trust store.", e);
        }
    }

    /**
     * ****************************************
     * Util methods for CRL Validation
     * ****************************************
     */

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

    /**
     * Get revocation status of a certificate using CRL Url
     *
     * @param peerCert   peer certificate
     * @param retryCount retry count to connect to CRL Url and get the CRL
     * @param crlUrls    List of CRL Urls
     * @return Revocation status of the certificate
     * @throws CertificateValidationException certificateValidationException
     */
    public static RevocationStatus getRevocationStatus(X509Certificate peerCert, int retryCount, List<String> crlUrls)
            throws CertificateValidationException {

        //check with distributions points in the list one by one. if one fails go to the other.
        for (String crlUrl : crlUrls) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to get CRL for URL: " + crlUrl);
            }

            X509CRL x509CRL = getCRLFromCache(crlUrl);
            try {
                if (x509CRL != null) {
                    if (isValidX509Crl(x509CRL, peerCert)) {
                        if (log.isDebugEnabled()) {
                            log.debug("CRL is taking from cache.");
                        }
                        return getRevocationStatusFromCRL(x509CRL, peerCert);
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("CRL is too old. Removing from cache.");
                        }
                        CRLCache.getInstance().clearCacheEntry(crlUrl);
                    }
                }

                x509CRL = downloadCRLFromWeb(crlUrl, retryCount, peerCert);
                if (x509CRL != null) {
                    addCRLToCache(crlUrl, x509CRL);
                    if (log.isDebugEnabled()) {
                        log.debug("CRL is added into cache.");
                    }
                    return getRevocationStatusFromCRL(x509CRL, peerCert);
                }
            } catch (Exception e) {
                log.info("Either url is bad or cant build X509CRL. So check with the next url in the list.");
                if (log.isDebugEnabled()) {
                    log.debug("Error when getting the X509 CRL for certificate: " + peerCert.getSerialNumber(), e);
                }
            }
        }
        throw new CertificateValidationException("Cannot check revocation status with the certificate");
    }

    private static boolean isValidX509Crl(X509CRL x509CRL, X509Certificate peerCert)
            throws CertificateValidationException {

        Date currentDate = new Date();
        Date nextUpdate = x509CRL.getNextUpdate();
        boolean isValid = false;

        if (isValidX509CRLFromIssuerDN(x509CRL, peerCert)) {
            isValid = isValidX509CRLFromNextUpdate(x509CRL, currentDate, nextUpdate);
        }
        return isValid;
    }

    private static boolean isValidX509CRLFromIssuerDN(X509CRL x509CRL, X509Certificate peerCert)
            throws CertificateValidationException {

        if (peerCert.getIssuerDN().equals(x509CRL.getIssuerDN())) {
            return true;
        } else {
            throw new CertificateValidationException("X509 CRL is not valid. Issuer DN in the peer certificate: " +
                    peerCert.getIssuerDN() + " is not matched with the Issuer DN in the X509 CRL: " +
                    x509CRL.getIssuerDN());
        }
    }

    private static boolean isValidX509CRLFromNextUpdate(X509CRL x509CRL, Date currentDate, Date nextUpdate)
            throws CertificateValidationException {

        if (nextUpdate != null) {
            if (log.isDebugEnabled()) {
                log.debug("Validating the next update date: " + nextUpdate.toString() + " with the current date: " +
                        currentDate.toString());
            }
            if (currentDate.before(x509CRL.getNextUpdate())) {
                return true;
            } else {
                throw new CertificateValidationException("X509 CRL is not valid. Next update date: " +
                        nextUpdate.toString() + " is before the current date: " + currentDate.toString());
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Couldn't validate the X509 CRL, next update date is not available.");
            }
        }
        return false;
    }

    private static X509CRL downloadCRLFromWeb(String crlURL, int retryCount, X509Certificate peerCert)
            throws IOException, CertificateValidationException {

        InputStream crlStream = null;
        X509CRL x509CRL = null;
        try {
            URL url = new URL(crlURL);
            crlStream = url.openStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL x509CRLDownloaded = (X509CRL) cf.generateCRL(crlStream);
            if (log.isDebugEnabled()) {
                log.debug("CRL is downloaded from CRL Url: " + crlURL);
            }

            if (isValidX509Crl(x509CRLDownloaded, peerCert)) {
                x509CRL = x509CRLDownloaded;
            }
        } catch (MalformedURLException e) {
            throw new CertificateValidationException("CRL Url is malformed", e);
        } catch (IOException e) {
            if (retryCount == 0) {
                throw new CertificateValidationException("Cant reach the CRL Url: " + crlURL, e);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Cant reach CRL Url: " + crlURL + ". Retrying to connect - attempt " + retryCount);
                }
                downloadCRLFromWeb(crlURL, --retryCount, peerCert);
            }
        } catch (CertificateException e) {
            throw new CertificateValidationException("Error when generating certificate factory.", e);
        } catch (CRLException e) {
            throw new CertificateValidationException("Cannot generate X509CRL from the stream data", e);
        } finally {
            if (crlStream != null)
                crlStream.close();
        }
        return x509CRL;
    }

    private static RevocationStatus getRevocationStatusFromCRL(X509CRL x509CRL, X509Certificate peerCert) {

        if (x509CRL.isRevoked(peerCert)) {
            return RevocationStatus.REVOKED;
        } else {
            return RevocationStatus.GOOD;
        }
    }

    private static byte[] getCRLDPExtensionValue(X509Certificate cert) {

        //DER-encoded octet string of the extension value for CRLDistributionPoints identified by the passed-in oid
        return cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
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
                        //DERIA5String contains an ascii string.
                        //A IA5String is a restricted character string type in the ASN.1 notation
                        String url = DERIA5String.getInstance(genName.getName()).getString().trim();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

    private static X509CRL getCRLFromCache(String crlUrl) {

        X509CRL x509CRL = null;
        CRLCacheEntry crlCacheValue = CRLCache.getInstance().getValueFromCache(crlUrl);
        if (crlCacheValue != null) {
            x509CRL = crlCacheValue.getX509CRL();
        }
        return x509CRL;
    }

    private static void addCRLToCache(String crlUrl, X509CRL x509CRL) {

        CRLCacheEntry crlCacheEntry = new CRLCacheEntry();
        crlCacheEntry.setX509CRL(x509CRL);
        CRLCache.getInstance().addToCache(crlUrl, crlCacheEntry);
    }

    /**
     * ****************************************
     * Util methods for OCSP Validation
     * ****************************************
     */

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

    /**
     * This method generates an OCSP Request to be sent to an OCSP endpoint.
     *
     * @param issuerCert   is the Certificate of the Issuer of the peer certificate we are interested in
     * @param serialNumber of the peer certificate
     * @return generated OCSP request
     * @throws CertificateValidationException certificateValidationException
     */
    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
            throws CertificateValidationException {

        // Add provider BC
        Security.addProvider(new BouncyCastleProvider());
        try {

            byte[] issuerCertEnc = issuerCert.getEncoded();
            X509CertificateHolder certificateHolder = new X509CertificateHolder(issuerCertEnc);
            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();

            // CertID structure is used to uniquely identify certificates that are the subject of
            // an OCSP request or response and has an ASN.1 definition. CertID structure is defined in RFC 2560
            CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), certificateHolder,
                    serialNumber);

            // basic request generation with nonce
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(id);

            // create details for nonce extension. The nonce extension is used to bind a request to a response to
            // prevent replay attacks. As the name implies, the nonce value is something that the client should only
            // use once within a reasonably small period.
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());

            // create the request Extension
            builder.setRequestExtensions(new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(nonce.toByteArray()))));

            return builder.build();
        } catch (Exception e) {
            throw new CertificateValidationException("Cannot generate OSCP Request with the given certificate with " +
                    "serial num: " + serialNumber, e);
        }
    }

    /**
     * Get revocation status of a certificate using OCSP Url
     *
     * @param peerCert   peer certificate
     * @param issuerCert issuer certificate of peer
     * @param retryCount retry count to connect to OCSP Url and get the OCSP response
     * @param locations  AIA locations
     * @return Revocation status of the certificate
     * @throws CertificateValidationException certificateValidationException
     */
    public static RevocationStatus getRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert,
                                                       int retryCount, List<String> locations)
            throws CertificateValidationException {

        OCSPReq request = generateOCSPRequest(issuerCert, peerCert.getSerialNumber());
        for (String serviceUrl : locations) {
            SingleResp[] responses;
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to get OCSP Response from : " + serviceUrl);
                }
                OCSPResp ocspResponse = CertificateValidationUtil.getOCSPResponse(serviceUrl, request, retryCount);
                if (OCSPResponseStatus.SUCCESSFUL != ocspResponse.getStatus()) {
                    if (log.isDebugEnabled()) {
                        log.debug("OCSP Response is not successfully received.");
                    }
                    continue;
                }

                BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                responses = (basicResponse == null) ? null : basicResponse.getResponses();
            } catch (Exception e) {
                continue;
            }

            if (responses != null && responses.length == 1) {
                return CertificateValidationUtil.getRevocationStatusFromOCSP(responses[0]);
            }
        }
        throw new CertificateValidationException("Cant get Revocation Status from OCSP using any of the OCSP Urls " +
                "for certificate with serial num:" + peerCert.getSerialNumber());
    }

    private static List<String> getOcspUrlsFromAuthorityInfoAccess(AuthorityInformationAccess
                                                                           authorityInformationAccess) {

        List<String> ocspUrlList = new ArrayList<>();
        AccessDescription[] accessDescriptions;
        if (authorityInformationAccess != null) {
            accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (AccessDescription accessDescription : accessDescriptions) {

                GeneralName gn = accessDescription.getAccessLocation();
                if(accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod)){
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    DERIA5String str = DERIA5String.getInstance(gn.getName());
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
     * Gets an ASN.1 encoded OCSP response (as defined in RFC 2560) from the given service URL. Currently supports
     * only HTTP.
     *
     * @param serviceUrl URL of the OCSP endpoint.
     * @param request    an OCSP request object.
     * @return OCSP response encoded in ASN.1 structure.
     * @throws CertificateValidationException certificateValidationException
     */
    private static OCSPResp getOCSPResponse(String serviceUrl, OCSPReq request, int retryCount)
            throws CertificateValidationException {

        OCSPResp ocspResp = null;
        try {
            HttpPost httpPost = new HttpPost(serviceUrl);
            setRequestProperties(request.getEncoded(), httpPost);
            DefaultHttpClient httpClient = new DefaultHttpClient();
            HttpResponse httpResponse = httpClient.execute(httpPost);
            //Check errors in response:
            if (httpResponse.getStatusLine().getStatusCode() / 100 != 2) {
                throw new CertificateValidationException("Error getting ocsp response." +
                        "Response code is " + httpResponse.getStatusLine().getStatusCode());
            }
            InputStream in = httpResponse.getEntity().getContent();
            ocspResp = new OCSPResp(in);
        } catch (IOException e) {
            if (retryCount == 0) {
                throw new CertificateValidationException("Cannot get ocspResponse from url: " + serviceUrl, e);
            } else {
                log.info("Cant reach URI: " + serviceUrl + ". Retrying to connect - attempt " + retryCount);
                getOCSPResponse(serviceUrl, request, --retryCount);
            }
        }
        return ocspResp;
    }


    private static void setRequestProperties(byte[] message, HttpPost httpPost) {

        httpPost.addHeader(X509CertificateValidationConstants.HTTP_CONTENT_TYPE,
                X509CertificateValidationConstants.HTTP_CONTENT_TYPE_OCSP);
        httpPost.addHeader(X509CertificateValidationConstants.HTTP_ACCEPT,
                X509CertificateValidationConstants.HTTP_ACCEPT_OCSP);

        httpPost.setEntity(new ByteArrayEntity(message, ContentType.create(CONTENT_TYPE)));
    }

    private static RevocationStatus getRevocationStatusFromOCSP(SingleResp resp)
            throws CertificateValidationException {

        Object status = resp.getCertStatus();
        if (status == CertificateStatus.GOOD) {
            return RevocationStatus.GOOD;
        } else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
            return RevocationStatus.REVOKED;
        } else if (status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
            return RevocationStatus.UNKNOWN;
        }
        throw new CertificateValidationException("Cant recognize Certificate Status");
    }

    /**
     * Generic Util Methods
     */

    /**
     * Generate thumbprint of certificate
     *
     * @param encodedCert Base64 encoded certificate
     * @return Decoded <code>Certificate</code>
     * @throws java.security.cert.CertificateException Error when decoding certificate
     */
    private static X509Certificate decodeCertificate(String encodedCert) throws CertificateException {

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
     * Encode X509 Certificate
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
            log.debug(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
    }

    private static KeyStore loadKeyStoreFromFile(String keyStorePath, String password, String type) {

        if (type == null) {
            type = X509CertificateValidationConstants.TRUSTSTORE_CONF_TYPE_DEFAULT;
        }
        CarbonUtils.checkSecurity();
        String absolutePath = new File(keyStorePath).getAbsolutePath();
        FileInputStream inputStream = null;
        try {
            KeyStore store = KeyStore.getInstance(type);
            inputStream = new FileInputStream(absolutePath);
            store.load(inputStream, password.toCharArray());
            return store;
        } catch (Exception e) {
            String errorMsg = "Error loading the key store from the location: " + absolutePath;
            log.error(errorMsg);
            throw new SecurityException(errorMsg, e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                log.warn("Error when closing the input stream.", e);
            }
        }
    }

    private static List<X509Certificate> exportCertificateChainFromKeyStore(KeyStore keyStore)
            throws KeyStoreException {

        Enumeration<String> aliases = keyStore.aliases();
        List<X509Certificate> certificates = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            certificates.add((X509Certificate) keyStore.getCertificate(alias));
        }
        return certificates;
    }

    private static String getNormalizedName(String name) {

        if (StringUtils.isNotBlank(name)) {
            return name.replaceAll("\\s+", "").toLowerCase();
            //~!@#;%^*+={}|<>,\\'\\\\"\\\\\\\\()[]
        }
        throw new IllegalArgumentException("Invalid validator name provided : " + name);
    }

    private static Registry getGovernanceRegistry(String tenantDomain) throws CertificateValidationException {

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

}
