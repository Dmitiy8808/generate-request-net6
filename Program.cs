// See https://aka.ms/new-console-template for more information
using LibCore.Security.Cryptography;
using System.Security.Cryptography;
using System.Security;
using LibCore.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.X509Certificates;
using static System.Net.Mime.MediaTypeNames;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using System.Text;

Console.WriteLine("###########");
LibCore.Initializer.Initialize();

var provider =
    new Gost3410_2012_256CryptoServiceProvider(
        new CspParameters()
        {
            Flags = CspProviderFlags.NoPrompt,
            KeyContainerName = $"0000_test_{Guid.NewGuid()}",
            ProviderName = "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
            ProviderType = 80,
            KeyNumber = 2
        });

var dnString = "CN = Ступин Дмитрий Алексеевич, SN = Ступин, G = Дмитрий Алексеевич, C = RU, E = dmitriy-stupin@mail.ru, OID.1.2.643.100.3 = 14979582340, OID.1.2.643.3.131.1.1 = 575108813048";

X500DistinguishedName subjectName = new X500DistinguishedName(dnString, X500DistinguishedNameFlags.UseUTF8Encoding);

var certificateRequest = new CpCertificateRequest(
    subjectName,
    (Gost3410_2012_256)provider,
    CpHashAlgorithmName.Gost3411_2012_256);

certificateRequest.CertificateExtensions.Add(
    new X509KeyUsageExtension(
        X509KeyUsageFlags.DigitalSignature
        | X509KeyUsageFlags.NonRepudiation
        | X509KeyUsageFlags.KeyEncipherment
        | X509KeyUsageFlags.DataEncipherment
        | X509KeyUsageFlags.KeyAgreement,

        false));

var oidCollection = new OidCollection();
// Проверка подлинности клиента (1.3.6.1.5.5.7.3.2)
oidCollection.Add(new Oid("1.3.6.1.5.5.7.3.2"));
// Защищенная электронная почта (1.3.6.1.5.5.7.3.4)
oidCollection.Add(new Oid("1.3.6.1.5.5.7.3.4"));
// Пользователь Центра Регистрации, HTTP, TLS клиент (1.2.643.2.2.34.6)
oidCollection.Add(new Oid("1.2.643.2.2.34.6"));

// класс средства ЭП КС 1 (1.2.643.100.113.1)
var policyKC1 = new DerObjectIdentifier("1.2.643.100.113.1");
var policyInformationKC1 = new PolicyInformation(policyKC1);

// класс средства ЭП КС 2 (1.2.643.100.113.2)
var policyKC2 = new DerObjectIdentifier("1.2.643.100.113.2");
var policyInformationKC2 = new PolicyInformation(policyKC2);

// Create a new X509Extension object with the policy information
var policyExtension = new System.Security.Cryptography.X509Certificates.X509Extension(
    new AsnEncodedData(
        new Oid("2.5.29.32", "Certificate Policies"),
        new CertificatePolicies(new[] { policyInformationKC1, policyInformationKC2 }).GetDerEncoded()),
    critical: false);

// Добавляем расширение Singn Tool
certificateRequest.CertificateExtensions.Add(policyExtension);

var signToolExtensionValue = Encoding.UTF8.GetBytes("КриптоПро CSP (ГОСТ 2012/256)");
var encodedSignToolExtensionValue = new DerUtf8String(Encoding.UTF8.GetString(signToolExtensionValue));
var encodedExtension = new AsnEncodedData(new Oid("1.2.643.100.111"), encodedSignToolExtensionValue.GetDerEncoded());

var signToolExtension = new System.Security.Cryptography.X509Certificates.X509Extension(
   encodedExtension,
    critical: false);

certificateRequest.CertificateExtensions.Add(signToolExtension);

// Добавляем расширение Identification Kind

var encodedIdKindExtensionValue = new DerInteger(0);
var encodedIdKindExtension = new AsnEncodedData(new Oid("1.2.643.100.114"), encodedIdKindExtensionValue.GetDerEncoded());

var idKindExtension = new System.Security.Cryptography.X509Certificates.X509Extension(
   encodedIdKindExtension,
    critical: false);

certificateRequest.CertificateExtensions.Add(idKindExtension);

certificateRequest.CertificateExtensions.Add(
new X509EnhancedKeyUsageExtension(
    oidCollection,
    true));

certificateRequest.CertificateExtensions.Add(
new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

Console.WriteLine(Convert.ToBase64String(certificateRequest.CreateSigningRequest()));