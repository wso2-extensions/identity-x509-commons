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

package org.wso2.carbon.identity.x509Certificate.validation.model;

/**
 * Model representation of a Certificate Validator.
 */
public class Validator {

    private String name;
    private String displayName;
    private boolean enabled;
    private int priority;
    private boolean fullChainValidationEnabled;
    private int retryCount;

    public Validator() {

    }

    public Validator(String name, String displayName, boolean enabled, int priority, boolean fullChainValidationEnabled,
                     int retryCount) {
        this.name = name;
        this.displayName = displayName;
        this.enabled = enabled;
        this.priority = priority;
        this.fullChainValidationEnabled = fullChainValidationEnabled;
        this.retryCount = retryCount;
    }

    /**
     * Get validator name.
     *
     * @return validator name
     */
    public String getName() {

        return name;
    }

    /**
     * Set validator name.
     *
     * @param name validator name
     */
    public void setName(String name) {

        this.name = name;
    }

    /**
     * Get validator display name.
     *
     * @return validator display name
     */
    public String getDisplayName() {

        return displayName;
    }

    /**
     * Set validator display name.
     *
     * @param displayName validator display name
     */
    public void setDisplayName(String displayName) {

        this.displayName = displayName;
    }

    /**
     * Get whether the validator is enabled or not.
     *
     * @return true if validator is enabled
     */
    public boolean isEnabled() {

        return enabled;
    }

    /**
     * Set validator enabled or not.
     *
     * @param enabled true if validator to be enabled
     */
    public void setEnabled(boolean enabled) {

        this.enabled = enabled;
    }

    /**
     * Get validator priority.
     *
     * @return validator priority
     */
    public int getPriority() {

        return priority;
    }

    /**
     * Set validator priority.
     *
     * @param priority validator priority
     */
    public void setPriority(int priority) {

        this.priority = priority;
    }

    /**
     * Get validator retry count.
     *
     * @return validator retry count
     */
    public int getRetryCount() {

        return retryCount;
    }

    /**
     * Set validator retry count.
     *
     * @param retryCount validator retry count
     */
    public void setRetryCount(int retryCount) {

        this.retryCount = retryCount;
    }

    /**
     * Check whether full chain validation enabled.
     *
     * @return true if full chain validation enabled
     */
    public boolean isFullChainValidationEnabled() {

        return fullChainValidationEnabled;
    }

    /**
     * Set whether full chain validation enabled or not.
     *
     * @param fullChainValidationEnabled true if full chain validation to be enabled
     */
    public void setFullChainValidationEnabled(boolean fullChainValidationEnabled) {

        this.fullChainValidationEnabled = fullChainValidationEnabled;
    }
}
