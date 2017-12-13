using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Fips
{
    public class FipsPrfKmg : IKMGenerator
    {
        private readonly FipsPrfAlgorithm prfAlgorithm;
        private readonly byte[] salt;

        public FipsPrfKmg(FipsPrfAlgorithm prfAlgorithm): this(prfAlgorithm, null)
        {
        }

        /// <summary>
        /// Contruct a PRF algorithm and salt to process the Z value with (as in SP 800-56C)
        /// </summary>
        /// <param name="prfAlgorithm">PRF represent the HMAC algorithm to use.</param>
        /// <param name="salt">The salt to use to initialise the PRF</param>
        public FipsPrfKmg(FipsPrfAlgorithm prfAlgorithm, byte[] salt)
        {
            this.prfAlgorithm = prfAlgorithm;
            this.salt = Arrays.Clone(salt);
        }

        public byte[] Generate(byte[] agreed)
        {
            IMac prfMac;
            if (prfAlgorithm == FipsPrfAlgorithm.AesCMac)
            {
                Internal.IBlockCipher aesEng = FipsAes.ENGINE_PROVIDER.CreateEngine(EngineUsage.GENERAL);
                aesEng.Init(true, new KeyParameter(salt ?? new byte[16]));

                prfMac = new CMac(aesEng);
                prfMac.Init(null);
            }
            else
            {
                prfMac = FipsShs.CreateHmac((DigestAlgorithm)prfAlgorithm.BaseAlgorithm);
                prfMac.Init(new KeyParameter(salt ?? new byte[((HMac)prfMac).GetUnderlyingDigest().GetByteLength()]));
            }

            byte[] mac = Macs.DoFinal(prfMac, agreed, 0, agreed.Length);

            // ZEROIZE
            Arrays.Fill(agreed, (byte)0);

            return mac;
        }
    }
}
