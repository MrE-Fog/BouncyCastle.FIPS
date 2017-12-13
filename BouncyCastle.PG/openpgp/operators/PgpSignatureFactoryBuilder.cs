using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using Org.BouncyCastle.Crypto.Fips;
using System.IO;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class PgpSignatureFactoryBuilder
    {
        private PublicKeyAlgorithmTag keyAlg;
        private HashAlgorithmTag hashAlg;

        public PgpSignatureFactoryBuilder(PublicKeyAlgorithmTag keyAlg, HashAlgorithmTag hashAlg)
        {
            this.keyAlg = keyAlg;
            this.hashAlg = hashAlg;
        }

        public ISignatureWithDigestFactory<PgpSignatureIdentifier> Build(PgpPrivateKey privateKey)
        {
            RsaSecretBcpgKey rsaKey = privateKey.Key as RsaSecretBcpgKey;
            if (rsaKey != null)
            {
                RsaPublicBcpgKey pubKey = (RsaPublicBcpgKey)privateKey.PublicKeyPacket.Key;

                return Build(privateKey.KeyId, new AsymmetricRsaPrivateKey(FipsRsa.Alg, rsaKey.Modulus, pubKey.PublicExponent, rsaKey.PrivateExponent, rsaKey.PrimeP, rsaKey.PrimeQ, rsaKey.PrimeExponentP, rsaKey.PrimeExponentQ, rsaKey.CrtCoefficient));
            }

            throw new ArgumentException("unknown key algorithm"); 
        }

        public ISignatureWithDigestFactory<PgpSignatureIdentifier> Build(long keyId, AsymmetricRsaPrivateKey privateKey)
        {
            return new SigWithDigestFactory(keyAlg, hashAlg, keyId, privateKey);
        }

        private class SigWithDigestFactory : ISignatureWithDigestFactory<PgpSignatureIdentifier>
        {
            private HashAlgorithmTag hashAlg;
            private PublicKeyAlgorithmTag keyAlg;
            private long keyId;
            private AsymmetricRsaPrivateKey privateKey;
            private ISignatureFactory<IParameters<Algorithm>> sigFact;
            private IDigestFactory<IParameters<Algorithm>> digFact;

            public SigWithDigestFactory(PublicKeyAlgorithmTag keyAlg, HashAlgorithmTag hashAlg, long keyId, AsymmetricRsaPrivateKey privateKey)
            {
                this.keyAlg = keyAlg;
                this.hashAlg = hashAlg;
                this.keyId = keyId;
                this.privateKey = privateKey;

                sigFact = CryptoServicesRegistrar.CreateService(privateKey, new SecureRandom()).CreateSignatureFactory(FipsRsa.Pkcs1v15.WithDigest((FipsDigestAlgorithm)PgpUtils.digests[hashAlg]));
                digFact = CryptoServicesRegistrar.CreateService((FipsShs.Parameters)PgpUtils.digests[hashAlg]);
            }

            public PgpSignatureIdentifier AlgorithmDetails
            {
                get
                {
                    return new PgpSignatureIdentifier(keyId, keyAlg, hashAlg);
                }
            }

            public IStreamCalculator<IBlockResult> CreateCalculator()
            {
                return sigFact.CreateCalculator();
            }

            public IStreamCalculator<IBlockResultWithDigest> CreateCalculatorWithDigest()
            {
                return new SigWithDigest(sigFact, digFact);
            }

            private class SigWithDigest : IStreamCalculator<IBlockResultWithDigest>
            {
                private readonly IStreamCalculator<IBlockResult> sigCalc;
                private readonly IStreamCalculator<IBlockResult> digCalc;
                private readonly Stream jointStream;

                internal SigWithDigest(ISignatureFactory<IParameters<Algorithm>> sigFact, IDigestFactory<IParameters<Algorithm>> digFact)
                {
                    this.sigCalc = sigFact.CreateCalculator();
                    this.digCalc = digFact.CreateCalculator();
                    this.jointStream = new TeeOutputStream(sigCalc.Stream, digCalc.Stream);
                }

                public Stream Stream
                {
                    get
                    {
                        return jointStream;
                    }
                }

                public IBlockResultWithDigest GetResult()
                {
                    return new Result(sigCalc.GetResult(), digCalc.GetResult());
                }

                private class Result : IBlockResultWithDigest
                {
                    private IBlockResult sigResult;
                    private IBlockResult digResult;

                    public Result(IBlockResult sigResult, IBlockResult digResult)
                    {
                        this.sigResult = sigResult;
                        this.digResult = digResult;
                    }

                    public int Length
                    {
                        get
                        {
                            return sigResult.Length;
                        }
                    }

                    public byte[] Collect()
                    {
                        return sigResult.Collect();
                    }

                    public int Collect(byte[] destination, int offset)
                    {
                        return sigResult.Collect(destination, offset);
                    }

                    public byte[] CollectDigest()
                    {
                        return digResult.Collect();
                    }

                    public int CollectDigest(byte[] destination, int offset)
                    {
                        return digResult.Collect(destination, offset);
                    }
                }
            }
        }
    }
}
