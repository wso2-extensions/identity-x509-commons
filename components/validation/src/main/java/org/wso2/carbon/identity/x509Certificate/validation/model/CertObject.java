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
 *
 */

package org.wso2.carbon.identity.x509Certificate.validation.model;

import java.util.List;

/**
 * Represents a certificate object.
 */
public class CertObject {

    private List<String> crlUrls;
    private List<String> ocspUrls;
    private String certId;
    private String serialNumber;

    public List<String> getCrlUrls() {

        return crlUrls;
    }

    public void setCrlUrls(List<String> crlUrls) {

        this.crlUrls = crlUrls;
    }

    public List<String> getOcspUrls() {

        return ocspUrls;
    }

    public void setOcspUrls(List<String> ocspUrls) {

        this.ocspUrls = ocspUrls;
    }

    public String getCertId() {

        return certId;
    }

    public void setCertId(String certId) {

        this.certId = certId;
    }

    public String getSerialNumber() {

        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {

        this.serialNumber = serialNumber;
    }

    @Override
    public String toString() {

        return "CertObject{" +
                "crlUrls=" + crlUrls +
                ", ocspUrls=" + ocspUrls +
                ", certId='" + certId + '\'' +
                ", serialNumber='" + serialNumber + '\'' +
                '}';
    }
}
