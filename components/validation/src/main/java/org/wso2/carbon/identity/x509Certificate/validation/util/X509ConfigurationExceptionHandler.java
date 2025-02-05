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

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.x509Certificate.validation.constant.error.ErrorMessage;
import org.wso2.carbon.identity.x509Certificate.validation.exception.X509ConfigurationClientException;
import org.wso2.carbon.identity.x509Certificate.validation.exception.X509ConfigurationServerException;

/**
 * Utility class for X509 Configuration.
 */
public class X509ConfigurationExceptionHandler {

    private X509ConfigurationExceptionHandler() {
    }

    /**
     * Handle X509 Configuration client exceptions.
     *
     * @param error Error message.
     * @param data  Data.
     * @return X509ConfigurationClientException.
     */
    public static X509ConfigurationClientException handleClientException(ErrorMessage error, String... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }

        return new X509ConfigurationClientException(error.getMessage(), description, error.getCode());
    }

    /**
     * Handle X509 Configuration server exceptions.
     *
     * @param error Error message.
     * @param e     Throwable.
     * @param data  Data.
     * @return X509ConfigurationServerException.
     */
    public static X509ConfigurationServerException handleServerException
    (ErrorMessage error, Throwable e, String... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }

        return new X509ConfigurationServerException(error.getMessage(), description, error.getCode(), e);
    }
}
