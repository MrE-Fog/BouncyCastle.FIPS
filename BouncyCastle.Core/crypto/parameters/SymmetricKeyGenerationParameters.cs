using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class SymmetricKeyGenerationParameters<TAlg>: Parameters<TAlg> where TAlg: Algorithm
    {
        private readonly int sizeInBits;

        internal SymmetricKeyGenerationParameters(TAlg algorithm, int sizeInBits): base(algorithm)
        {
            this.sizeInBits = sizeInBits;
        }

        public int KeySize
        {
            get
            {
                return sizeInBits;
            }
        }
    }
}
