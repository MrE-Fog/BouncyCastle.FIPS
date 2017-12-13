using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto
{
    public interface IStreamCipherService
    {
        ICipherBuilder<A> CreateDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;

        ICipherBuilder<A> CreateEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
