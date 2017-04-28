/*
Copyright (c) 2017 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Written by Christopher Williams, Ph.D. (cwilliams@exponent.com)
*/

package exponent.derivedcred.CA;

import exponent.derivedcred.dhsdemo.ByteUtil;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Embedded implementation of CA/DODJITCIDCA_41.cer
 *
 * This implementation for demonstration only, this functionality would download cert in real app
 */


public class DODCACert
{
    private X509Certificate dodCaCert= null;

    public DODCACert()
    {
        ByteArrayInputStream bis=new ByteArrayInputStream(ByteUtil.hexStringToByteArray("308204c6308203aea00302010202011c300d" +
                "06092a864886f70d01010b05003060310b300906035504061302555331183016060355040a130f552e532e20476f7665726e6d656e74" +
                "310c300a060355040b1303446f44310c300a060355040b1303504b49311b301906035504031312446f44204a49544320526f6f742043" +
                "412033301e170d3135313032303030303030305a170d3231313032303030303030305a305f310b300906035504061302555331183016" +
                "060355040a130f552e532e20476f7665726e6d656e74310c300a060355040b1303446f44310c300a060355040b1303504b49311a3018" +
                "06035504031311444f44204a4954432049442043412d343130820122300d06092a864886f70d01010105000382010f003082010a0282" +
                "010100b133d6446a5ce726743cf020e98e2e059ec38905969f5929ccdd56a6ef68d2347eda2c8ba8e4e55af80d80fb0e84993e66935c" +
                "08d2f8c66b973e03e7426199c5de0aa1328d9475049db3708dc7d548dbea9e9cb822e41f1bda0dc1e22c80e15bfe859dda7da8732484" +
                "52ec90ffb416603104a411337b1d5798be0e0ba5f8293012da55b13679f90242e022c3f4746e84e93e5b812ea59290649bfd1a0c6b1e" +
                "9da906f45d70cac580d5a3c792b1cbbd7077e29865cf654422ac87f95af8e0ae11087bccdec08480cb9ea60168378688820ba05b7191" +
                "15b78f82cb45902ad31e3f18c77c52de6c656e436738f991614641b313ef3b97d3410a79e26342ebe487db0203010001a382018a3082" +
                "0186301f0603551d23041830168014f0aebd4a3a2e2251e8c28cbecef7a46ad234aac5301d0603551d0e0416041486bd62f894c18db3" +
                "fc3cad92caf473e9d5ce2945300e0603551d0f0101ff040403020186304c0603551d2004453043300b0609608648016502010b24300b" +
                "0609608648016502010b27300b0609608648016502010b2a300c060a6086480165030201300b300c060a6086480165030201300d3012" +
                "0603551d130101ff040830060101ff020100300c0603551d2404053003800100303f0603551d1f043830363034a032a030862e687474" +
                "703a2f2f63726c2e6e69742e646973612e6d696c2f63726c2f444f444a495443524f4f544341332e63726c30818206082b0601050507" +
                "010104763074304206082b060105050730028636687474703a2f2f63726c2e6e69742e646973612e6d696c2f697373756564746f2f44" +
                "4f444a495443524f4f544341335f49542e703763302e06082b060105050730018622687474703a2f2f6f6373702e6e736e302e726376" +
                "732e6e69742e646973612e6d696c300d06092a864886f70d01010b050003820101000e9443c8ec980f6cfd6df7b047ef0dfd0ef372d3" +
                "3da851fc2f8a2d1a139eb71b38db8fe51652057a526b9edf37af7e20dc68d9a5a5566587c35c2b3064d5dbfd1220d2dc936b02b40c01" +
                "1f3c6140382ecf455a2109d01a4a6fe2f9f505008694da6028d1e3fb1a0fa72365bc71b5f8f9ad093addc220c35594b01982e4ae0fef" +
                "bd87aee788936bde17d0efd223a26431f4e703a449745ff2a219533b7e6ac0d2f47d6608ad1343a9688bba1b80c351444581e6dd3a65" +
                "e3e9f7e076a830690d8bed8f0840d322c467ae2df15586c7d3044acc54b21a8e55c9d31a1230ea515d0db5690ecf369aac04b0d2e3d1" +
                "b1f3597e94635f2f802dd1d56fb94101f6d50a01"));


        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            dodCaCert = (X509Certificate) cf.generateCertificate(bis);
            dodCaCert.checkValidity();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        }
    }

    public X509Certificate getDODCert()
    {
        return dodCaCert;
    }
}