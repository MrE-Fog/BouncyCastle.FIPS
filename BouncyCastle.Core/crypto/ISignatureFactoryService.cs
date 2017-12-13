using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for a service to support the creation of signature factories.
    /// </summary>
    public interface ISignatureFactoryService
    {
        /// <summary>
        /// Return a signature factory for signature algorithm described in the passed in algorithm details object.
        /// </summary>
        /// <param name="algorithmDetails">The details of the signature algorithm verification is required for.</param>
        /// <returns>A new signature factory.</returns>
        ISignatureFactory<A> CreateSignatureFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>;
    }
}
