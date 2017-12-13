using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.OpenPgp.Operators.Parameters
{
    public class PgpPbeKeyEncryptionParameters
    {
        private byte[] mIv;

        public PgpPbeKeyEncryptionParameters(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, byte[] iv)
        {
            this.Algorithm = encAlgorithm;
            this.S2k = s2k;
            this.mIv = Arrays.Clone(iv);
        }

        public SymmetricKeyAlgorithmTag Algorithm { get; private set; }

        public S2k S2k { get; private set; }

        internal byte[] GetIV()
        {
            return Arrays.Clone(mIv);
        }
    }
}
