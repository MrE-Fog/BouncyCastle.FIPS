using Org.BouncyCastle.Asn1.X509;
using System;
using System.IO;

namespace Org.BouncyCastle.Cert.Selector
{
    internal class MSOutlookKeyIdCalculator
    {
        // This is less than ideal, but it seems to be the best way of supporting this without exposing SHA-1
        // as the class is only used to workout the MSOutlook Key ID, you can think of the fact it's SHA-1 as
        // a coincidence...
        internal static byte[] CalculateKeyId(SubjectPublicKeyInfo info)
        {
            Sha1Digest dig = new Sha1Digest();
            byte[] hash = new byte[dig.GetDigestSize()];
            byte[] spkiEnc = new byte[0];
            try
            {
                spkiEnc = info.GetDerEncoded();
            }
            catch (IOException)
            {
                return new byte[0];
            }

            // try the outlook 2010 calculation
            dig.BlockUpdate(spkiEnc, 0, spkiEnc.Length);

            dig.DoFinal(hash, 0);

            return hash;
        }

        internal abstract class GeneralDigest
        {
            private const int BYTE_LENGTH = 64;

            private byte[] xBuf;
            private int xBufOff;

            private long byteCount;

            internal GeneralDigest()
            {
                xBuf = new byte[4];
            }

            internal GeneralDigest(GeneralDigest t)
            {
                xBuf = new byte[t.xBuf.Length];
                CopyIn(t);
            }

            protected void CopyIn(GeneralDigest t)
            {
                Array.Copy(t.xBuf, 0, xBuf, 0, t.xBuf.Length);

                xBufOff = t.xBufOff;
                byteCount = t.byteCount;
            }

            public void Update(byte input)
            {
                xBuf[xBufOff++] = input;

                if (xBufOff == xBuf.Length)
                {
                    ProcessWord(xBuf, 0);
                    xBufOff = 0;
                }

                byteCount++;
            }

            public void BlockUpdate(
                byte[] input,
                int inOff,
                int length)
            {
                length = System.Math.Max(0, length);

                //
                // fill the current word
                //
                int i = 0;
                if (xBufOff != 0)
                {
                    while (i < length)
                    {
                        xBuf[xBufOff++] = input[inOff + i++];
                        if (xBufOff == 4)
                        {
                            ProcessWord(xBuf, 0);
                            xBufOff = 0;
                            break;
                        }
                    }
                }

                //
                // process whole words.
                //
                int limit = ((length - i) & ~3) + i;
                for (; i < limit; i += 4)
                {
                    ProcessWord(input, inOff + i);
                }

                //
                // load in the remainder.
                //
                while (i < length)
                {
                    xBuf[xBufOff++] = input[inOff + i++];
                }

                byteCount += length;
            }

            public void Finish()
            {
                long bitLength = (byteCount << 3);

                //
                // add the pad bytes.
                //
                Update((byte)128);

                while (xBufOff != 0) Update((byte)0);
                ProcessLength(bitLength);
                ProcessBlock();
            }

            public virtual void Reset()
            {
                byteCount = 0;
                xBufOff = 0;
                Array.Clear(xBuf, 0, xBuf.Length);
            }

            public int GetByteLength()
            {
                return BYTE_LENGTH;
            }

            internal abstract void ProcessWord(byte[] input, int inOff);
            internal abstract void ProcessLength(long bitLength);
            internal abstract void ProcessBlock();
            public abstract string AlgorithmName { get; }
            public abstract int GetDigestSize();
            public abstract int DoFinal(byte[] output, int outOff);
        }

        internal class Sha1Digest: GeneralDigest
        {
            private const int DigestLength = 20;

            private uint H1, H2, H3, H4, H5;

            private uint[] X = new uint[80];
            private int xOff;

            public Sha1Digest()
            {
                Reset();
            }

            /**
             * Copy constructor.  This will copy the state of the provided
             * message digest.
             */
            public Sha1Digest(Sha1Digest t)
                : base(t)
            {
                CopyIn(t);
            }

            private void CopyIn(Sha1Digest t)
            {
                base.CopyIn(t);

                H1 = t.H1;
                H2 = t.H2;
                H3 = t.H3;
                H4 = t.H4;
                H5 = t.H5;

                Array.Copy(t.X, 0, X, 0, t.X.Length);
                xOff = t.xOff;
            }

            public override string AlgorithmName
            {
                get { return "SHA-1"; }
            }

            public override int GetDigestSize()
            {
                return DigestLength;
            }

            internal override void ProcessWord(
                byte[] input,
                int inOff)
            {
                X[xOff] = BE_To_UInt32(input, inOff);

                if (++xOff == 16)
                {
                    ProcessBlock();
                }
            }

            internal static uint BE_To_UInt32(byte[] bs, int off)
            {
                return (uint)bs[off] << 24
                    | (uint)bs[off + 1] << 16
                    | (uint)bs[off + 2] << 8
                    | (uint)bs[off + 3];
            }

            internal override void ProcessLength(long bitLength)
            {
                if (xOff > 14)
                {
                    ProcessBlock();
                }

                X[14] = (uint)((ulong)bitLength >> 32);
                X[15] = (uint)((ulong)bitLength);
            }

            public override int DoFinal(
                byte[] output,
                int outOff)
            {
                Finish();

                UInt32_To_BE(H1, output, outOff);
                UInt32_To_BE(H2, output, outOff + 4);
                UInt32_To_BE(H3, output, outOff + 8);
                UInt32_To_BE(H4, output, outOff + 12);
                UInt32_To_BE(H5, output, outOff + 16);

                Reset();

                return DigestLength;
            }

            internal static void UInt32_To_BE(uint n, byte[] bs, int off)
            {
                bs[off] = (byte)(n >> 24);
                bs[off + 1] = (byte)(n >> 16);
                bs[off + 2] = (byte)(n >> 8);
                bs[off + 3] = (byte)(n);
            }

            /**
             * reset the chaining variables
             */
            public override void Reset()
            {
                base.Reset();

                H1 = 0x67452301;
                H2 = 0xefcdab89;
                H3 = 0x98badcfe;
                H4 = 0x10325476;
                H5 = 0xc3d2e1f0;

                xOff = 0;
                Array.Clear(X, 0, X.Length);
            }

            //
            // Additive constants
            //
            private const uint Y1 = 0x5a827999;
            private const uint Y2 = 0x6ed9eba1;
            private const uint Y3 = 0x8f1bbcdc;
            private const uint Y4 = 0xca62c1d6;

            private static uint F(uint u, uint v, uint w)
            {
                return (u & v) | (~u & w);
            }

            private static uint H(uint u, uint v, uint w)
            {
                return u ^ v ^ w;
            }

            private static uint G(uint u, uint v, uint w)
            {
                return (u & v) | (u & w) | (v & w);
            }

            internal override void ProcessBlock()
            {
                //
                // expand 16 word block into 80 word block.
                //
                for (int i = 16; i < 80; i++)
                {
                    uint t = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
                    X[i] = t << 1 | t >> 31;
                }

                //
                // set up working variables.
                //
                uint A = H1;
                uint B = H2;
                uint C = H3;
                uint D = H4;
                uint E = H5;

                //
                // round 1
                //
                int idx = 0;

                for (int j = 0; j < 4; j++)
                {
                    // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
                    // B = rotateLeft(B, 30)
                    E += (A << 5 | (A >> 27)) + F(B, C, D) + X[idx++] + Y1;
                    B = B << 30 | (B >> 2);

                    D += (E << 5 | (E >> 27)) + F(A, B, C) + X[idx++] + Y1;
                    A = A << 30 | (A >> 2);

                    C += (D << 5 | (D >> 27)) + F(E, A, B) + X[idx++] + Y1;
                    E = E << 30 | (E >> 2);

                    B += (C << 5 | (C >> 27)) + F(D, E, A) + X[idx++] + Y1;
                    D = D << 30 | (D >> 2);

                    A += (B << 5 | (B >> 27)) + F(C, D, E) + X[idx++] + Y1;
                    C = C << 30 | (C >> 2);
                }

                //
                // round 2
                //
                for (int j = 0; j < 4; j++)
                {
                    // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
                    // B = rotateLeft(B, 30)
                    E += (A << 5 | (A >> 27)) + H(B, C, D) + X[idx++] + Y2;
                    B = B << 30 | (B >> 2);

                    D += (E << 5 | (E >> 27)) + H(A, B, C) + X[idx++] + Y2;
                    A = A << 30 | (A >> 2);

                    C += (D << 5 | (D >> 27)) + H(E, A, B) + X[idx++] + Y2;
                    E = E << 30 | (E >> 2);

                    B += (C << 5 | (C >> 27)) + H(D, E, A) + X[idx++] + Y2;
                    D = D << 30 | (D >> 2);

                    A += (B << 5 | (B >> 27)) + H(C, D, E) + X[idx++] + Y2;
                    C = C << 30 | (C >> 2);
                }

                //
                // round 3
                //
                for (int j = 0; j < 4; j++)
                {
                    // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
                    // B = rotateLeft(B, 30)
                    E += (A << 5 | (A >> 27)) + G(B, C, D) + X[idx++] + Y3;
                    B = B << 30 | (B >> 2);

                    D += (E << 5 | (E >> 27)) + G(A, B, C) + X[idx++] + Y3;
                    A = A << 30 | (A >> 2);

                    C += (D << 5 | (D >> 27)) + G(E, A, B) + X[idx++] + Y3;
                    E = E << 30 | (E >> 2);

                    B += (C << 5 | (C >> 27)) + G(D, E, A) + X[idx++] + Y3;
                    D = D << 30 | (D >> 2);

                    A += (B << 5 | (B >> 27)) + G(C, D, E) + X[idx++] + Y3;
                    C = C << 30 | (C >> 2);
                }

                //
                // round 4
                //
                for (int j = 0; j < 4; j++)
                {
                    // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
                    // B = rotateLeft(B, 30)
                    E += (A << 5 | (A >> 27)) + H(B, C, D) + X[idx++] + Y4;
                    B = B << 30 | (B >> 2);

                    D += (E << 5 | (E >> 27)) + H(A, B, C) + X[idx++] + Y4;
                    A = A << 30 | (A >> 2);

                    C += (D << 5 | (D >> 27)) + H(E, A, B) + X[idx++] + Y4;
                    E = E << 30 | (E >> 2);

                    B += (C << 5 | (C >> 27)) + H(D, E, A) + X[idx++] + Y4;
                    D = D << 30 | (D >> 2);

                    A += (B << 5 | (B >> 27)) + H(C, D, E) + X[idx++] + Y4;
                    C = C << 30 | (C >> 2);
                }

                H1 += A;
                H2 += B;
                H3 += C;
                H4 += D;
                H5 += E;

                //
                // reset start of the buffer.
                //
                xOff = 0;
                Array.Clear(X, 0, 16);
            }
        }
    }
}