/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.extension.identity.x509Certificate.valve;

import org.apache.axiom.om.util.Base64;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.x509Certificate.valve.config.X509ServerConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
public class X509CertificateAuthenticationValveTest {

    private static final String X509_REQUEST_HEADER = "X-SSL-CERT";
    private static final String DUMMY_CERTIFICATE = "-----BEGIN CERTIFICATE-----\tMIIDiDCCAnACCQDMyyUcmVh40DANBgkqhki" +
            "G9w0BAQsFADCBhTELMAkGA1UEBhMC\tc2wxEDAOBgNVBAgMB3dlc3Rlcm4xEDAOBgNVBAcMB2NvbG9tYm8xDTALBgNVBAoM\tBHdzbzI" +
            "xCzAJBgNVBAsMAmlzMRMwEQYDVQQDDAp3c28yaXMuY29tMSEwHwYJKoZI\thvcNAQkBFhJwaXJhdmVlbmFAd3NvMi5jb20wHhcNMTkwM" +
            "TE3MDQyMjE4WhcNMjAw\tMTE3MDQyMjE4WjCBhTELMAkGA1UEBhMCc2wxEDAOBgNVBAgMB3dlc3Rlcm4xEDAO\tBgNVBAcMB2NvbG9tY" +
            "m8xDTALBgNVBAoMBHdzbzIxCzAJBgNVBAsMAmlzMRMwEQYD\tVQQDDAp3c28yaXMuY29tMSEwHwYJKoZIhvcNAQkBFhJwaXJhdmVlbmF" +
            "Ad3NvMi5j\tb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPAM8uk8/Pv+C8oOj8\tUOB7hn+FYBVyBlzvEJOmy+oBYbs" +
            "gpci9YlBv/kCZ9FU4ZmVCbjXJ9vpA1N54VSyk\txMa8LIG/YOLJhsHKq+5PygFfOKceo37wnh5aaf08CT+4JWkOj1I6sDQc7pySIzjW" +
            "\tCma9p+A/vzSPco+u0A0itcm3On0H72oOJDMWebApzelEx4leqitUNLoqvYU8JgEi\tIelXnyuLmoe1dcTCsu1guiF7TooFA+iPI/64" +
            "axMnH6P0QIKoKHXIOAefqjz3kmFX\tIxVZEFa6qKmfG9QGgeu1DJMU/BuTYRf0GoaxHJe/Qmr/dz/A537dJ/a44tanJVfU\tqT4zAgMB" +
            "AAEwDQYJKoZIhvcNAQELBQADggEBAJxlIv81kSgZ+pMgc4h8eBz628F3\tJa+t4P3+K/F8lUcTheyQ16QSXm/n0i4qPFn6TEb5UADAC6" +
            "dLvsA+8P/AymgmV2TS\t4nl8KJsuvLnDHsbE+y4EgWdhCBI6nhmgho2p2yFqFno7QkEWV2MA5VETI+KnAaq1\tK+8m6xVqOt2MgKNF4C" +
            "1MrgPDUFrxn2QF3CjaKp+pfxK2c0uDAJ2120AsQWZbMHq8\tR1avwudUwwlSBBzvh8t1xbd5ERiglzwfhU/K7G3riG0CijxAzeC6RYYx" +
            "E2Es+pJK\tmvY3G7zYqc4/3FCLfj9OLYC2puo84lBURu39Qgenkv0OvyKfZ4Iyp9Oq5sA=\t-----END CERTIFICATE-----";
    private static final String CERT_PEM_START = "[-]+(BEGIN CERTIFICATE)[-]+[\t]*[\n]*";
    private static final String CERT_PEM_END = "[-]+(END CERTIFICATE)[-]+";
    private static final Pattern PATTERN = Pattern.compile(CERT_PEM_START + "([^-]+)" + CERT_PEM_END);
    private static final String X509CERT_NAME = "X509";
    private static final String X_509_CERTIFICATE = "javax.servlet.request.X509Certificate";
    private static final String FAULTY_CERTIFICATE = "-----BEGIN CERTIFICATE-----\tbbbhityukAssu==-----END CERTIFICAT" +
            "E-----";

    Request request;
    Response response;
    private Valve valve;

    private X509CertificateAuthenticationValve x509CertificateAuthenticationValve;
    MockedStatic<X509ServerConfiguration> x509ServerConfigurationMockedStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        x509CertificateAuthenticationValve = new X509CertificateAuthenticationValve();
        request = mock(Request.class);
        response = mock(Response.class);
        valve = mock(Valve.class);
        X509ServerConfiguration x509ServerConfiguration = mock(X509ServerConfiguration.class);
        x509ServerConfigurationMockedStatic = mockStatic(X509ServerConfiguration.class);

        when(X509ServerConfiguration.getInstance()).thenReturn(x509ServerConfiguration);
        when(x509ServerConfiguration.getX509requestHeader()).thenReturn(X509_REQUEST_HEADER);
    }

    @AfterMethod
    public void tearDown() {

        x509ServerConfigurationMockedStatic.close();
    }

    @Test
    public void testInvoke() throws Exception {

        setCertificate();
        invokeX509AuthenticationValve();
        assertNotNull(request.getAttribute(X_509_CERTIFICATE), "Error occurred in setting X509 Certificate");
    }

    private void setCertificate() throws CertificateException {

        when(request.getHeader(X509_REQUEST_HEADER)).thenReturn(DUMMY_CERTIFICATE);
        Matcher matcher = PATTERN.matcher(DUMMY_CERTIFICATE);
        X509Certificate certificate = null;
        if (matcher.matches()) {
            String pemCertBody = DUMMY_CERTIFICATE.replaceAll(CERT_PEM_START, "").replaceAll(CERT_PEM_END, "");
            byte[] certificateData = Base64.decode(pemCertBody);

            certificate = (X509Certificate) CertificateFactory.getInstance(X509CERT_NAME)
                    .generateCertificate(new ByteArrayInputStream(certificateData));
            X509Certificate[] certificates = new X509Certificate[]{certificate};
            request.setAttribute(X_509_CERTIFICATE, certificates);
            when(request.getAttribute(X_509_CERTIFICATE)).thenReturn(certificates);
        }
    }

    @Test
    public void testInvokeForException() {

        when(request.getHeader(X509_REQUEST_HEADER)).thenReturn(FAULTY_CERTIFICATE);
        Matcher matcher = PATTERN.matcher(FAULTY_CERTIFICATE);

        if (matcher.matches()) {
            String pemCertBody = FAULTY_CERTIFICATE.replaceAll(CERT_PEM_START, "").replaceAll(CERT_PEM_END, "");
            byte[] certificateData = Base64.decode(pemCertBody);
            try {
                X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance(X509CERT_NAME)
                        .generateCertificate(new ByteArrayInputStream(certificateData));
            } catch (CertificateException e) {
                assertTrue(e.getMessage().equals("Could not parse certificate: java.io.IOException: Empty input"),
                        "This is a valid pem format of certificate");
            }
        }
    }

    private void invokeX509AuthenticationValve() throws IOException, ServletException {

        doNothing().when(valve).invoke(request, response);
        x509CertificateAuthenticationValve.setNext(valve);
        x509CertificateAuthenticationValve.invoke(request, response);
    }
}
