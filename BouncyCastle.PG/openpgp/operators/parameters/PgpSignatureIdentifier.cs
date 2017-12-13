using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.OpenPgp.Operators.Parameters
{
    public class PgpSignatureIdentifier
    {
        private readonly long mKeyId;
        private readonly PublicKeyAlgorithmTag mKeyAlgorithm;
        private readonly HashAlgorithmTag mHashAlgorithm;

        public PgpSignatureIdentifier(long keyId, PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm)
        {
            this.mKeyId = keyId;
            this.mKeyAlgorithm = keyAlgorithm;
            this.mHashAlgorithm = hashAlgorithm;
        }

        public HashAlgorithmTag HashAlgorithm { get { return mHashAlgorithm;  } }

        public PublicKeyAlgorithmTag KeyAlgorithm { get { return mKeyAlgorithm; } }

        public long KeyId {  get { return mKeyId;  } }
    }
}
