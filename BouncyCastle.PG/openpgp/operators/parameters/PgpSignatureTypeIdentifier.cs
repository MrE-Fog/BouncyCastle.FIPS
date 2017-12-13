using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.OpenPgp.Operators.Parameters
{
    public class PgpSignatureTypeIdentifier
    {
        private readonly PublicKeyAlgorithmTag mKeyAlgorithm;
        private readonly HashAlgorithmTag mHashAlgorithm;

        public PgpSignatureTypeIdentifier(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm)
        {
            this.mKeyAlgorithm = keyAlgorithm;
            this.mHashAlgorithm = hashAlgorithm;
        }

        public HashAlgorithmTag HashAlgorithm { get { return mHashAlgorithm; } }

        public PublicKeyAlgorithmTag KeyAlgorithm { get { return mKeyAlgorithm; } }
    }
}
