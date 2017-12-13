using System;

namespace Org.BouncyCastle.Crypto.Internal
{
    /**
     * base interface for general purpose byte derivation functions.
     */
    internal interface IDerivationFunction
    {
        void Init(IDerivationParameters parameters);

        /**
         * return the message digest used as the basis for the function
         */
        IDigest Digest
        {
            get;
        }

        int GenerateBytes(byte[] output, int outOff, int length);
        //throws DataLengthException, ArgumentException;
    }

}
