using System;

using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Utilities
{
    internal static class Digests
    {
        internal static byte[] DoFinal(IDigest digest)
        {
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        internal static byte[] DoFinal(IDigest digest, byte[] input, int inOff, int inLen)
        {
            digest.BlockUpdate(input, inOff, inLen);
            return DoFinal(digest);
        }
    }
}
