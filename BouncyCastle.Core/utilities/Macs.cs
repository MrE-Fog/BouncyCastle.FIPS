using System;

using Org.BouncyCastle.Crypto.Internal;

namespace Org.BouncyCastle.Utilities
{
    internal static class Macs
    {
        internal static byte[] DoFinal(IMac mac)
        {
            byte[] result = new byte[mac.GetMacSize()];
            mac.DoFinal(result, 0);
            return result;
        }

        internal static byte[] DoFinal(IMac mac, byte[] input, int inOff, int inLen)
        {
            mac.BlockUpdate(input, inOff, inLen);
            return DoFinal(mac);
        }

        internal static byte[] DoFinal(IMac mac, ICipherParameters cipherParameters, byte[] input, int inOff, int inLen)
        {
            mac.Init(cipherParameters);
            return DoFinal(mac, input, inOff, inLen);
        }
    }
}
