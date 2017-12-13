using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Parameters
{
    internal class Utils
    {
        internal static int CheckIv(AlgorithmMode mode, byte[] iv, int defaulIvSize)
        {
            switch (mode)
            {
                case AlgorithmMode.CBC:
                case AlgorithmMode.CFB128:
                case AlgorithmMode.CFB8:
                case AlgorithmMode.CFB64:
                case AlgorithmMode.OFB128:
                case AlgorithmMode.OFB64:
                    if (iv != null && iv.Length != defaulIvSize)
                    {
                        throw new ArgumentException("IV must be " + defaulIvSize + " bytes long");
                    }
                    break;
                case AlgorithmMode.CTR:
                    if (iv != null && iv.Length > defaulIvSize)
                    {
                        throw new ArgumentException("CTR IV must be less than " + defaulIvSize + " bytes long");
                    }
                    break;
            }

            return defaulIvSize;
        }
    }
}
