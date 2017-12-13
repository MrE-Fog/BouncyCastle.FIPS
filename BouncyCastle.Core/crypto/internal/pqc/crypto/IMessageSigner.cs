using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto.Internal.Pqc.Crypto
{
    internal interface IMessageSigner
    {
        /// <summary>
        ///  initialise the signer for signature generation or signature verification.
        /// </summary>
        /// <param name="forSigning">true if we are generating a signature, false otherwise</param>
        /// <param name="param">key parameters for signature generation.</param>
        void Init(bool forSigning, ICipherParameters param);

        /// <summary>
        /// sign the passed in message (usually the output of a hash function).
        /// </summary>
        /// <param name="message">the message to be signed.</param>
        /// <returns>the signature of the message</returns>
        byte[] GenerateSignature(byte[] message);

        /// <summary>
        /// verify the message message against the signature value
        /// </summary>
        /// <param name="message">the message that was supposed to have been signed.</param>
        /// <param name="signature">the signature of the message.</param>
        /// <returns></returns>
        bool VerifySignature(byte[] message, byte[] signature);
    }
}
