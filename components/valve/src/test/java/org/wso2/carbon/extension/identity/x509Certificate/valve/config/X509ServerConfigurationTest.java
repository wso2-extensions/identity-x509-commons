/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.extension.identity.x509Certificate.valve.config;

import org.apache.axiom.om.OMElement;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.mockito.Matchers.eq;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;

@PrepareForTest({IdentityConfigParser.class})
public class X509ServerConfigurationTest extends PowerMockIdentityBaseTest {

    @Mock
    IdentityConfigParser configParser;

    @Mock
    OMElement x509ConfigElement;

    @DataProvider(name = "provideDataForTestGetInstance")
    public Object[][] provideDataForTestGetInstance() {

        return new Object[][]{
                {x509ConfigElement}, {null}
        };
    }

    @Test(dataProvider = "provideDataForTestGetInstance")
    public void testGetInstance(Object x509ConfigElement) {

        mockStatic(IdentityConfigParser.class);
        when(IdentityConfigParser.getInstance()).thenReturn(configParser);
        when(configParser.getConfigElement(eq("X509"))).thenReturn((OMElement) x509ConfigElement);
        assertNotNull(X509ServerConfiguration.getInstance());
    }
}
