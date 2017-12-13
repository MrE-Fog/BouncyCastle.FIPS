using System;

using Org.BouncyCastle.Crypto.Internal.Parameters;

namespace Org.BouncyCastle.Crypto.Internal.Wrappers
{
    abstract class SP80038FWrapper : IWrapper
    {
        protected static readonly byte[] ivKW = {
                                  (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6,
                                  (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6 };
        protected static readonly byte[] ivKWP = {
                              (byte)0xa6, (byte)0x59, (byte)0x59, (byte)0xa6 };

        protected readonly bool wrapCipherMode;
        protected readonly IBlockCipher engine;
        protected readonly int delta;
        protected readonly byte[] iv;

        protected KeyParameter param;
        protected bool forWrapping;

        protected SP80038FWrapper(IBlockCipher engine, byte[] iv, bool useReverseDirection)
        {
            this.engine = engine;
            this.wrapCipherMode = (useReverseDirection) ? false : true;
            this.delta = engine.GetBlockSize() / 2;
            this.iv = new byte[iv.Length > delta ? delta : iv.Length];
            Array.Copy(iv, 0, this.iv, 0, this.iv.Length);
        }

        public void Init(
            bool forWrapping,
            ICipherParameters param)
        {
            this.forWrapping = forWrapping;

            if (param is KeyParameter)
            {
                this.param = (KeyParameter)param;
            }
            else if (param is ParametersWithIV)
            {
                byte[] newIv = ((ParametersWithIV)param).GetIV();
                if (newIv.Length != iv.Length)
                {
                    throw new ArgumentException("IV not equal to " + ivKWP.Length);
                }
                this.param = (KeyParameter)((ParametersWithIV)param).Parameters;
                Array.Copy(newIv, 0, iv, 0, iv.Length);
            }
        }

        protected byte[] W(int n, byte[] block)
        {
            byte[] buf = new byte[engine.GetBlockSize()];

            //engine.Init(wrapCipherMode, param);

            for (int j = 0; j != 6; j++)
            {
                for (int i = 1; i <= n; i++)
                {
                    Array.Copy(block, 0, buf, 0, delta);
                    Array.Copy(block, delta * i, buf, delta, delta);
                    engine.ProcessBlock(buf, 0, buf, 0);

                    uint t = (uint)(n * j + i);
                    for (int k = 1; t != 0; k++)
                    {
                        byte v = (byte)t;

                        buf[delta - k] ^= v;

                        t >>= 8;
                    }

                    Array.Copy(buf, 0, block, 0, delta);
                    Array.Copy(buf, delta, block, delta * i, delta);
                }
            }

            return block;
        }

        protected void invW(int n, byte[] block, byte[] a)
        {
            byte[] buf = new byte[engine.GetBlockSize()];

            //engine.Init(!wrapCipherMode, param);

            n = n - 1;

            for (int j = 5; j >= 0; j--)
            {
                for (int i = n; i >= 1; i--)
                {
                    Array.Copy(a, 0, buf, 0, delta);
                    Array.Copy(block, delta * (i - 1), buf, delta, delta);

                    uint t = (uint)(n * j + i);
                    for (int k = 1; t != 0; k++)
                    {
                        byte v = (byte)t;

                        buf[delta - k] ^= v;

                        t >>= 8;
                    }

                    engine.ProcessBlock(buf, 0, buf, 0);
                    Array.Copy(buf, 0, a, 0, delta);
                    Array.Copy(buf, delta, block, delta * (i - 1), delta);
                }
            }
        }

        abstract public string AlgorithmName { get; }

        abstract public byte[] Wrap(byte[] input, int off, int length);

        abstract public byte[] Unwrap(byte[] input, int off, int length);
    }
}
