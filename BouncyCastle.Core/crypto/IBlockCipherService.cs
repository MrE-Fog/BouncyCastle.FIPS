using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Service interface for block ciphers.
    /// </summary>
    public interface IBlockCipherService: IMacFactoryService
    {
        /// <summary>
        /// Return a block cipher builder for decrypting block ciphers.
        /// </summary>
        /// <typeparam name="A">The type of the details for the block cipher to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of block cipher to be produced.</param>
        /// <returns>A builder for decrypting block ciphers for the passed in details.</returns>
        IBlockCipherBuilder<A> CreateBlockDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;

        /// <summary>
        /// Return a block cipher builder for encrypting block ciphers.
        /// </summary>
        /// <typeparam name="A">The type of the details for the block cipher to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of block cipher to be produced.</param>
        /// <returns>A builder for encrypting block ciphers for the passed in details.</returns>
        IBlockCipherBuilder<A> CreateBlockEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;

        /// <summary>
        /// Return a block cipher builder for decrypting ciphers.
        /// </summary>
        /// <typeparam name="A">The type of the details for the cipher to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of cipher to be produced.</param>
        /// <returns>A builder for decrypting ciphers for the passed in details.</returns>
        ICipherBuilder<A> CreateDecryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;

        /// <summary>
        /// Return a block cipher builder for encrypting ciphers.
        /// </summary>
        /// <typeparam name="A">The type of the details for the cipher to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of cipher to be produced.</param>
        /// <returns>A builder for encrypting ciphers for the passed in details.</returns>
        ICipherBuilder<A> CreateEncryptorBuilder<A>(A algorithmDetails) where A : IParameters<Algorithm>;

        /// <summary>
        /// Return a key wrapper.
        /// </summary>
        /// <typeparam name="A">The type of the details for the key wrapper to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of key wrapper to be produced.</param>
        /// <returns>A key wrapper for the passed in details.</returns>
        IKeyWrapper<A> CreateKeyWrapper<A>(A algorithmDetails) where A : ISymmetricWrapParameters<A, Algorithm>;

        /// <summary>
        /// Return a key unwrapper.
        /// </summary>
        /// <typeparam name="A">The type of the details for the key unwrapper to be produced.</typeparam>
        /// <param name="algorithmDetails">The algorithm and parameter details for the type of key unwrapper to be produced.</param>
        /// <returns>A key unwrapper for the passed in details.</returns>
        IKeyUnwrapper<A> CreateKeyUnwrapper<A>(A algorithmDetails) where A : ISymmetricWrapParameters<A, Algorithm>;
    }
}
