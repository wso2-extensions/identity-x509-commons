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

package org.wso2.carbon.identity.x509Certificate.validation.cache;

import java.io.Serializable;
import java.security.cert.X509CRL;
import java.util.Date;

/**
 * CRL cache entry with X509CRL.
 */
public class CRLCacheEntry implements Serializable {

    private static final long serialVersionUID = 1591693579088522864L;

    private X509CRL x509CRL;
    
    private boolean updateInProgress = false;  // Used as key for Singleton Update flow
    
    private Date nextUpdate;  // In case CRL does not have nextUpdate, this will be used. Always set to 24 hours after setX509CRL is called.

    /**
     * Get X509 CRL.
     *
     * @return X509 CRL
     */
    public X509CRL getX509CRL() {

        return x509CRL;
    }

    /**
     * Set X509 CRL.
     *
     * @param x509CRL X509 CRL
     */
    public void setX509CRL(X509CRL x509CRL) {

        this.x509CRL = x509CRL;
        nextUpdate = new Date(System.currentTimeMillis()+ (3600000));
    }

	public boolean isUpdateInProgress() {
		return updateInProgress;
	}

	public void setUpdateInProgress(boolean updateInProgress) {
		this.updateInProgress = updateInProgress;
	}

	public Date getNextUpdate() {
		return nextUpdate;
	}

}
