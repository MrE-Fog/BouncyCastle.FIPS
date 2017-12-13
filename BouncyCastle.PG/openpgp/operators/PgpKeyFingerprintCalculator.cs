using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class PgpKeyFingerprintCalculator : IKeyFingerPrintCalculator
    {
        public byte[] CalculateFingerprint(PublicKeyPacket publicPk)
        {
            IBcpgKey key = publicPk.Key;

            if (publicPk.Version <= 3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey)key;

                try
                {
                    // TODO: MD5 needs to go in the main API...
                    MD5Digest digest = new MD5Digest();

                    byte[] bytes = new MPInteger(rK.Modulus).GetEncoded();
                    digest.BlockUpdate(bytes, 2, bytes.Length - 2);

                    bytes = new MPInteger(rK.PublicExponent).GetEncoded();
                    digest.BlockUpdate(bytes, 2, bytes.Length - 2);

                    byte[] digBuf = new byte[digest.GetDigestSize()];

                    digest.DoFinal(digBuf, 0);

                    return digBuf;
                }
                catch (IOException e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
            }
            else
            {
                try
                {
                    byte[] kBytes = publicPk.GetEncodedContents();

                    IStreamCalculator<IBlockResult> hashCalc = CryptoServicesRegistrar.CreateService(FipsShs.Sha1).CreateCalculator();
                    Stream hStream = hashCalc.Stream;

                    hStream.WriteByte((byte)0x99);
                    hStream.WriteByte((byte)(kBytes.Length >> 8));
                    hStream.WriteByte((byte)kBytes.Length);
                    hStream.Write(kBytes, 0, kBytes.Length);

                    hStream.Close();

                    return hashCalc.GetResult().Collect();
                }
                catch (IOException e)
                {
                    throw new PgpException("can't encode key components: " + e.Message, e);
                }
            }
        }
    }
}
