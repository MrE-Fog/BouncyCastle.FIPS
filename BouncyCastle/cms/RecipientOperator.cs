using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using System.IO;

namespace Org.BouncyCastle.Cms
{
    public class RecipientOperator
    {
        private readonly AlgorithmIdentifier algorithmIdentifier;
        private readonly object op;
        private IStreamCalculator<IBlockResult> macCalc;

        public RecipientOperator(ICipherBuilder<AlgorithmIdentifier> decryptor)
        {
            this.algorithmIdentifier = decryptor.AlgorithmDetails;
            this.op = decryptor;
        }

        public RecipientOperator(IMacFactory<AlgorithmIdentifier> macCalculator)
        {
            this.algorithmIdentifier = macCalculator.AlgorithmDetails;
            this.op = macCalculator;
        }

        public Stream GetStream(Stream dataIn)
        {
            if (op is ICipherBuilder<AlgorithmIdentifier>)
            {
                return ((ICipherBuilder<AlgorithmIdentifier>)op).BuildCipher(dataIn).Stream;
            }
            else
            {
                macCalc = ((IMacFactory<AlgorithmIdentifier>)op).CreateCalculator();

                return new TeeInputStream(dataIn, macCalc.Stream);
            }
        }

        public bool IsMacBased
        {
            get
            {
                return op is IMacFactory<AlgorithmIdentifier>;
            }
        }

        public byte[] GetMac()
        {
            macCalc.Stream.Close();

            return macCalc.GetResult().Collect();
        }
    }
}