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

/**
 * This is used to get Revocation Status message.
 */
public enum RevocationStatus {

    GOOD("Good"), UNKNOWN("Unknown"), REVOKED("Revoked"),;
    private String message;

    RevocationStatus(String message) {

        this.message = message;
    }

    /**
     * Get revocation status message.
     *
     * @return status message
     */
    public String getMessage() {

        return message;
    }

}
