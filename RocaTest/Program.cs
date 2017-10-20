using System;

using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;

namespace RocaCmTest
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 1)
            {
                System.Console.WriteLine("Usage1: RocaCmTest.exe ... test cert stores");
                System.Console.WriteLine("Usage2: RocaCmTest.exe <cert_file> ... test cert file");
                System.Console.WriteLine("Usage3: RocaCmTest.exe <directory> ... test directory");
                return;
            }

            int iTPMGenKeyFlag = -1; // -1 ... not done, 0 ... tested OK, 1 ... tested vulnerable
            int iTPMCertFlag = -1; // -1 ... not done, 0 ... tested OK, 1 ... tested vulnerable

            try
            {
                // Phase 1. Check TPM behavior
                Console.WriteLine("*** RocaCmTest tool will check for ROCA (CVE-2017-15361) vulnerability ***\n");
                System.Console.WriteLine("Usage1: RocaCmTest.exe ... test cert stores");
                System.Console.WriteLine("Usage2: RocaCmTest.exe <cert_file> ... test cert file");
                System.Console.WriteLine("Usage3: RocaCmTest.exe <directory> ... test directory");
                Console.WriteLine("\nStep 1: Try to generate RSA keypair using Platform Crypto Provider(TPM) and inspect it");
                
                // Detect TPM
                bool isTpmPresent = false;
                try
                {
                    // Create management class object
                    ManagementClass mc = new ManagementClass("/root/CIMv2/Security/MicrosoftTpm:Win32_Tpm");
                    //collection to store all management objects
                    ManagementObjectCollection moc = mc.GetInstances();
                    // Retrieve single instance of WMI management object
                    ManagementObjectCollection.ManagementObjectEnumerator moe = moc.GetEnumerator();
                    moe.MoveNext();
                    ManagementObject mo = (ManagementObject)moe.Current;

                    if (null == mo)
                    {
                        isTpmPresent = false;
                        Console.WriteLine("TPM is not detected");
                    }
                    else
                    {
                        isTpmPresent = true;
                        Console.WriteLine("TPM chip detected");
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine("TPM detection error: " + e.Message);
                }

                if (isTpmPresent)
                {
                    string containerName = "TestRoca_" + Guid.NewGuid().ToString();
                    string providerName = "Microsoft Platform Crypto Provider";
                    if (Environment.OSVersion.Version.Major > 6 || (Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor >= 2))
                    {
                        try
                        {
                            // Win 8 and newer
                            CngKeyCreationParameters keyParams = new CngKeyCreationParameters();
                            keyParams.KeyUsage = CngKeyUsages.Signing;
                            keyParams.ExportPolicy = CngExportPolicies.None;
                            keyParams.KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey;
                            keyParams.Provider = new CngProvider(providerName);
                            keyParams.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

                            // Generate a key
                            CngKey cngKey = CngKey.Create(new CngAlgorithm("RSA"), containerName, keyParams);

                            // Display the key information to the console.  
                            Console.WriteLine("RSA Key generated successfully");

                            StringWriter sw = new StringWriter();
                            ExportPublicKeyCng(cngKey, sw);
                            
                            StringReader sr = new StringReader(sw.ToString());

                            // Check vulnerbility
                            ConsoleColor old_color = Console.ForegroundColor;
                            if (KeyIsVulnerable(sr))
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Alert: TPM generated RSA key is vulnerable to ROCA (CVE-2017-15361)");
                                Console.ForegroundColor = old_color;
                                iTPMGenKeyFlag = 1;
                            }
                            else
                            {
                                Console.WriteLine("TPM generated RSA key is OK");
                                iTPMGenKeyFlag = 0;
                            }

                            // Delete the key
                            cngKey.Delete();
                        }
                        catch(Exception e)
                        {
                            Console.WriteLine("Error: " + e.Message);
                            Console.WriteLine("TPM RSA Key generation and check was not done. We continue with further checks.");
                        }
                    }
                    else
                    {
                        // We are on Win 7 or older
                        providerName = "Charismathics Smart Security Interface Platform Extended";

                        try
                        {
                            // Create the CspParameters object and set the key container name used to store the RSA key pair.  
                            CspParameters cp = new CspParameters(0x18);
                            cp.KeyContainerName = containerName;
                            cp.ProviderName = providerName;
                            cp.Flags = CspProviderFlags.UseNonExportableKey;

                            // Create a new instance of RSACryptoServiceProvider that accesses  
                            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, cp);

                            // Display the key information to the console.  
                            Console.WriteLine("RSA Key generated successfully");

                            // Export the key to PEM
                            StringWriter sw = new StringWriter();
                            ExportPublicKey(rsa, sw);

                            rsa.Clear();

                            // Get the key to string
                            StringReader sr = new StringReader(sw.ToString());
                            ConsoleColor old_color = Console.ForegroundColor;
                            if (KeyIsVulnerable(sr))
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Alert: TPM generated RSA key is vulnerable to ROCA (CVE-2017-15361)");
                                Console.ForegroundColor = old_color;
                                iTPMGenKeyFlag = 1;
                            }
                            else
                            {
                                Console.WriteLine("TPM generated RSA key is OK");
                                iTPMGenKeyFlag = 0;
                            }

                            // Create the CspParameters object and set the key container name used to store the RSA key pair.  
                            CspParameters cp2 = new CspParameters(0x18);
                            cp2.KeyContainerName = containerName;
                            cp2.ProviderName = providerName;

                            // Create a new instance of RSACryptoServiceProvider that accesses  
                            // the key container.  
                            RSACryptoServiceProvider rsa2 = new RSACryptoServiceProvider(cp2);

                            // Delete the key entry in the container.  
                            rsa2.PersistKeyInCsp = false;

                            // Call Clear to release resources and delete the key from the container.  
                            rsa2.Clear();

                            Console.WriteLine("Key deleted");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Error: " + e.Message);
                            Console.WriteLine("TPM RSA Key generation and check was not done. We continue with further checks.");
                        }
                    }                   
                }
                else
                {
                    Console.WriteLine("No TPM found on this machine");
                }

                if (args.Length == 0)
                {
                    Console.WriteLine("Step 2: Validate all certificates in user & system stores");
                    int sum = 0;
                    if(PrintVulnerableResultStore(StoreLocation.CurrentUser))
                    {
                        sum++;
                    }
                    if(PrintVulnerableResultStore(StoreLocation.LocalMachine))
                    {
                        sum++;
                    }
                    if (sum > 0)
                    {
                        ConsoleColor old_color = Console.ForegroundColor;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\nALERT - " + sum + " store containing vulnerable ROCA (CVE-2017-15361) certificate(s) found!");
                        Console.ForegroundColor = old_color;
                        iTPMCertFlag = 1;
                    }
                    else
                    {
                        Console.WriteLine("\nSUCCESS - No vulnerable certificate stores found");
                        iTPMCertFlag = 0;
                    }
                }
                else if (args.Length == 1)
                {
                    // Phase 2. checking certs
                    string param = args[0];

                    // get the file attributes for file or directory
                    FileAttributes attr = File.GetAttributes(param);

                    // Detect whether its a directory or file
                    if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                    {
                        Console.WriteLine("Step 2: Validate all certificates in " + param);
                        // Its a directory
                        int sum = 0;
                        foreach (string certFile in Directory.GetFiles(param))
                        {
                            if(PrintIsVulnerableResult(certFile))
                            {
                                sum++;
                            }
                        }
                        if (sum > 0)
                        {
                            ConsoleColor old_color = Console.ForegroundColor;
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("\nALERT - " + sum + " vulnerable ROCA (CVE-2017-15361) certificate(s) found!");
                            Console.ForegroundColor = old_color;
                            iTPMCertFlag = 1;
                        }
                        else
                        {
                            Console.WriteLine("\nSUCCESS - No vulnerable certificates found");
                            iTPMCertFlag = 0;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Step 2: Validate certificate - " + param);
                        if(PrintIsVulnerableResult(param))
                        {
                            iTPMCertFlag = 1;
                        }
                        else
                        {
                            iTPMCertFlag = 0;
                        }
                    }
                }
                else
                {
                    // Should not get here
                    System.Console.WriteLine("Bad syntax\n");
                }
            }
            catch(Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
            }

            Console.WriteLine("");
            Console.WriteLine("----------------------------------------------");
            Console.WriteLine("--- ROCA (CVE-2017-15361) Analysis Summary ---");
            Console.WriteLine("----------------------------------------------");
            ConsoleColor o_color = Console.ForegroundColor;
            if (iTPMGenKeyFlag == 1)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("TPM GenKey Test    : ... Tested TPM chip vulnerable!");
            }
            else if (iTPMGenKeyFlag == 0)
            {
                Console.WriteLine("TPM GenKey Test    : ... Tested TPM chip OK");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("TPM GenKey Test    : ... not done");
                
            }
            Console.ForegroundColor = o_color;

            if (iTPMCertFlag == 1)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Certificate(s) Test: ... Vulnerable certs found!");
            }
            else if (iTPMCertFlag == 0)
            {
                Console.WriteLine("Certificate(s) Test: ... Certificate(s) OK");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Certificate(s) Test: ... not done");
            }
            Console.ForegroundColor = o_color;

            // Detect if we run by double-click and keep the console open till user presses ENTER
            var myId = Process.GetCurrentProcess().Id;
            var query = string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", myId);
            var search = new ManagementObjectSearcher("root\\CIMV2", query);
            var results = search.Get().GetEnumerator();
            results.MoveNext();
            var queryObj = results.Current;
            var parentId = (uint)queryObj["ParentProcessId"];
            var parent = Process.GetProcessById((int)parentId);
            if(parent.ProcessName.Contains("explorer"))
            {
                Console.WriteLine("... Press ENTER to quit the test ...");
                Console.ReadLine();
            }           
        }

        private static bool PrintVulnerableResultStore(StoreLocation location)
        {
            var store = new X509Store(location);

            store.Open(OpenFlags.ReadOnly);

            var certificates = store.Certificates;
            int sum = 0;
            foreach (var certificate in certificates)
            {
                if (PrintIsVulnerableResult(certificate))
                {
                    sum++;
                }
            }

            store.Close();
            if (sum > 0)
            {
                ConsoleColor old_color = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nALERT - " + sum + " vulnerable ROCA (CVE-2017-15361) certificates found!");
                Console.ForegroundColor = old_color;
                return true;
            }
            
            return false;
        }
        private static bool PrintIsVulnerableResult(string certFile)
        {
            try
            {
                ConsoleColor old_color = Console.ForegroundColor;
                if (CertIsVulnerable(certFile))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(certFile + " ... vulnerable to ROCA (CVE-2017-15361)");
                    Console.ForegroundColor = old_color;
                    return true;
                }
                else
                {
                    Console.WriteLine(certFile + " ... OK");
                }
            }
            catch (Exception e)
            {
                ConsoleColor old_color_ex = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(certFile + " ... not checked!");
                Console.WriteLine("Error: " + e.Message);
                Console.ForegroundColor = old_color_ex;
            }
            return false;
        }

        private static bool PrintIsVulnerableResult(X509Certificate2 cert)
        {
            var subject = cert.Subject;
            var issuer = cert.Issuer;
            var finger = cert.Thumbprint.ToString();
            
            try
            {
                ConsoleColor old_color = Console.ForegroundColor;
                if (CertIsVulnerable(cert))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\nSubject: " + subject +"\nIssuer: " + issuer + "\nThumbprint: " + finger + "\nStatus: ... vulnerable to ROCA (CVE-2017-15361)");
                    Console.ForegroundColor = old_color;
                    return true;
                }
                else
                {
                    Console.WriteLine("\nSubject: " + subject + "\nIssuer: " + issuer + "\nThumbprint: " + finger + "\nStatus: ... OK");
                }
            }
            catch (Exception e)
            {
                ConsoleColor old_color_ex = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\nSubject: " + subject + "\nIssuer: " + issuer + "\nThumbprint: " + finger + "\nStatus: ... not checked!");
                Console.WriteLine("Error: " + e.Message);
                Console.ForegroundColor = old_color_ex;
            }
            return false;
        }

        private static bool CertIsVulnerable(string certFile)
        {
            X509CertificateParser x509CertificateParser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(File.ReadAllBytes(certFile));
            RsaKeyParameters rsaKeyParameters = x509Certificate.GetPublicKey() as RsaKeyParameters;
            if (rsaKeyParameters == null)
                throw new InvalidOperationException("Incorrect X509 cert data read from " + certFile);
            return RocaCmTest.IsVulnerable(rsaKeyParameters);
        }
        private static bool CertIsVulnerable(X509Certificate2 cert)
        {
            X509CertificateParser x509CertificateParser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate x509Certificate = DotNetUtilities.FromX509Certificate(cert);
            RsaKeyParameters rsaKeyParameters = x509Certificate.GetPublicKey() as RsaKeyParameters;
            if (rsaKeyParameters == null)
                throw new InvalidOperationException("Incorrect X509Certificate2 data processed");
            return RocaCmTest.IsVulnerable(rsaKeyParameters);
        }

        private static bool KeyIsVulnerable(StringReader pem_stream)
        {        
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(pem_stream);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)pemReader.ReadObject();
            if (rsaKeyParameters == null)
                throw new InvalidOperationException("Incorrect PEM data processed");           
            return RocaCmTest.IsVulnerable(rsaKeyParameters);
        }
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
        private static void ExportPublicKey(RSACryptoServiceProvider csp, StringWriter outputStream)
        {
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END PUBLIC KEY-----");                
            }
        }
        private static void ExportPublicKeyCng(CngKey key, StringWriter outputStream)
        {
            // This structure is as the header for the CngKey
            // all should be byte arrays in Big-Endian order
            //typedef struct _BCRYPT_RSAKEY_BLOB {
            //  ULONG Magic; 
            //  ULONG BitLength; 
            //  ULONG cbPublicExp;
            //  ULONG cbModulus;
            //  ULONG cbPrime1;  private key only
            //  ULONG cbPrime2;  private key only
            //} BCRYPT_RSAKEY_BLOB;

            // This is the actual Key Data that is attached to the header
            //BCRYPT_RSAKEY_BLOB
            //  PublicExponent[cbPublicExp] 
            //  Modulus[cbModulus]

            // Example
            //52 53 41 31 = Magic 0x31415352
            //00 08 00 00 = Bit len 0x00000800
            //03 00 00 00 = cbPubExp 0x00000003
            //00 01 00 00 = cbModulus 0x00000100
            //00 00 00 00 = cbPrime1(not used)
            //00 00 00 00 = cbPrime2(not used)

            //01 00 01 = PublicExponent(len = 0x03)

            //bf 25 39 99 54 3f 4e 48 1f 02 b5 8b bb a9 8b 7a 69 18 a7 d7 77 2d 84 f7 f8 b9 64 cf d2 26 35 1d
            //9e 09 c3 e4 49 9a 94 1b df 9c f5 87 8e cc ed fa 06 a1 c8 2c 8f 68 f5 43 64 cc 76 01 a1 39 3d cf
            //5b 7b ed 75 5b 61 c4 bb a3 27 c9 c5 c6 64 ca 9e 8d 16 22 b0 cb 37 78 5f 79 92 ee d4 73 04 da 35
            //79 fe 14 51 46 5c 2d 5b 28 90 e6 94 2b 37 b8 25 da c8 38 76 23 81 31 5b 87 ed 0f b1 dc ee f9 cd
            //8a 4f f0 5c 6b 2b 0a 67 99 a8 1e d7 dd 02 f5 ac de 0c e9 7a bf e7 03 37 86 2c 99 f8 5e 43 75 69
            //a4 82 b2 7d 30 1c 25 ac 0a da 43 b3 0b 6c 29 0f bf 90 4f 45 ef 2a 46 66 65 77 59 ac e3 b2 6e b3
            //84 5a 2e aa d1 01 24 7b 6f 5e 7c ec 87 71 8e 5b e6 5d b8 a4 04 ec 4e 8c d9 e9 92 6c a9 42 be 04
            //2d f2 0a 62 e6 6c a8 0f d1 bc ac fd 7a 52 42 73 52 22 4a 0a e3 25 77 31 5d a0 af 7a a7 fe 19 35 = Modulus(len 0x100)

            // The blob has the above format (big-endian!!)
            byte[] pubKeyBlob = key.Export(CngKeyBlobFormat.GenericPublicBlob);

            // Now get the 2 members of RSA key
            uint cbPubExp = BitConverter.ToUInt32(pubKeyBlob, 8); // Starts at index 8
            uint cbModulus = BitConverter.ToUInt32(pubKeyBlob, 12); // Starts at index 12
            byte[] modulus = new byte[cbModulus];
            byte[] exponent = new  byte[cbPubExp];
            Buffer.BlockCopy(pubKeyBlob, 24, exponent, 0, (int)cbPubExp);
            Buffer.BlockCopy(pubKeyBlob, 24 + (int)cbPubExp, modulus, 0, (int)cbModulus);

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END PUBLIC KEY-----");
            }
        }    
    }
}
