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

package org.wso2.carbon.identity.x509Certificate.validation.constant.error;

/**
 * Error messages.
 */
public enum ErrorMessage {

    // Client errors.
    ERROR_INVALID_VALIDATOR_NAME("60001", "Invalid validator name.",
            "Invalid validator name %s in the tenant %s."),
    ERROR_NO_VALIDATORS_CONFIGURED_ON_TENANT("60002", "Unable to perform the operation.",
            "No validator is configured on the given tenant %s."),
    ERROR_NO_CA_CERTIFICATES_CONFIGURED_ON_TENANT("60003", "Unable to perform the operation.",
            "No CA Certificate is configured on the given tenant %s."),
    ERROR_CERTIFICATE_DOES_NOT_EXIST("60004", "Unable to perform the operation.", "Certificate " +
            "with the id: %s does not exist in tenant %s."),

    // Server errors.
    ERROR_WHILE_RETRIEVING_VALIDATORS("65001", "Error while retrieving validators.",
            "Error while retrieving validators from the system."),
    ERROR_WHILE_RETRIEVING_VALIDATOR_BY_NAME("65002", "Error while retrieving validator by name.",
            "Error while retrieving validator from the system."),
    ERROR_WHILE_UPDATING_VALIDATOR("65003", "Error while updating Validator.",
            "Error while updating Validator in the system."),
    ERROR_WHILE_RETRIEVING_CA_CERTIFICATES("65004", "Error while retrieving CA Certificates.",
            "Error while retrieving CA Certificates from the system."),
    ERROR_WHILE_ADDING_CA_CERTIFICATE("65005", "Error while adding CA Certificate.",
            "Error while persisting CA Certificate in the system."),
    ERROR_WHILE_UPDATING_CA_CERTIFICATE("65006", "Error while updating CA Certificate.",
            "Error while updating CA Certificate in the system."),
    ERROR_WHILE_RETRIEVING_CA_CERTIFICATE_BY_ID("65007", "Unable to perform the operation.",
            "Error while retrieving CA Certificate by ID %s from tenant %s."),
    ERROR_WHILE_DELETING_CA_CERTIFICATE("65008", "Error while deleting CA Certificate.", "Error " +
            "while deleting CA Certificate from the system.");

    private final String code;
    private final String message;
    private final String description;

    ErrorMessage(String code, String message, String description) {

        this.code = code;
        this.message = message;
        this.description = description;
    }

    public String getCode() {

        return code;
    }

    public String getMessage() {

        return message;
    }

    public String getDescription() {

        return description;
    }
}
