using System.Security.Cryptography.X509Certificates;

X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine, OpenFlags.ReadOnly);
X509Certificate2? wantedCertificate = null;
foreach (var certificate in store.Certificates)
{
    if (certificate.Issuer == "CN=localhost")
    {
        wantedCertificate = certificate;
    }
}

if (wantedCertificate == null)
{
    Console.WriteLine("Can't find IIS Express certificate.");
    return;
}

var rawData = wantedCertificate.RawData;
using (var write = new StreamWriter(@"C:\temp\Sample.crt"))
{
    write.WriteLine("-----BEGIN CERTIFICATE-----");
    write.WriteLine(Convert.ToBase64String(rawData, Base64FormattingOptions.InsertLineBreaks));
    write.WriteLine("-----END CERTIFICATE-----");
}

var privateKey = wantedCertificate.GetRSAPrivateKey();
if (privateKey != null)
{
    var keyData = privateKey.ExportRSAPrivateKey();
    using (var write = new StreamWriter(@"C:\temp\Sample.key"))
    {
        write.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
        write.WriteLine(Convert.ToBase64String(keyData, Base64FormattingOptions.InsertLineBreaks));
        write.WriteLine("-----END RSA PRIVATE KEY-----");
    }
}

Console.WriteLine("Finish generate certificate.");
Console.ReadKey();
