using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg;

namespace Org.BouncyCastle.OpenPgp.Operators.Parameters
{
    public class PgpDigestTypeIdentifier
    {
        private readonly HashAlgorithmTag hashAlg;

        public PgpDigestTypeIdentifier(HashAlgorithmTag hashAlg)
        {
            this.hashAlg = hashAlg;
        }

        public HashAlgorithmTag Algorithm { get { return hashAlg; } }
    }
}
