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
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;

public class X509ServerConfigurationTest {

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

    @BeforeClass
    public void setUp() {

        configParser = mock(IdentityConfigParser.class);
        x509ConfigElement = mock(OMElement.class);
    }

    @Test(dataProvider = "provideDataForTestGetInstance")
    public void testGetInstance(Object x509ConfigElement) {

        try (MockedStatic<IdentityConfigParser> identityConfigParser = mockStatic(IdentityConfigParser.class)) {
            identityConfigParser.when(IdentityConfigParser::getInstance).thenReturn(configParser);
            when(configParser.getConfigElement(eq("X509"))).thenReturn((OMElement) x509ConfigElement);
            assertNotNull(X509ServerConfiguration.getInstance());
        }
    }
}
