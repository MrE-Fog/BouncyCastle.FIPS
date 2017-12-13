using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.OpenPgp
{
    public interface IPbeSecretKeyDecryptorProvider : IKeyUnwrapperProvider<PgpPbeKeyEncryptionParameters>, IDigestFactoryProvider<PgpDigestTypeIdentifier>
    {
    }
}
