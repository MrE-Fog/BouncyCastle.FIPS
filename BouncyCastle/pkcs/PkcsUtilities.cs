
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Parameters;

namespace Org.BouncyCastle.Pkcs
{
    internal class PkcsUtilities
    {
        internal static MacData CreateMacData(IMacFactory<Pkcs12MacAlgDescriptor> macCalcFactory, byte[] data)
        {
            IStreamCalculator<IBlockResult> mdCalc = macCalcFactory.CreateCalculator();

            using (var str = mdCalc.Stream)
            {
                str.Write(data, 0, data.Length);
            }

            Pkcs12MacAlgDescriptor macAlg = macCalcFactory.AlgorithmDetails;

            return new MacData(new DigestInfo(macAlg.DigestAlgorithm, mdCalc.GetResult().Collect()), macAlg.GetIV(), macAlg.IterationCount);
        }
    }
}
