using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using Org.BouncyCastle.Utilities.IO;
using System.IO;

namespace Org.BouncyCastle.OpenPgp
{
    public class PgpOnePassSignature
    {
        private OnePassSignaturePacket sigPack;
        private int signatureType;

        private byte lastb;
        private IStreamCalculator<IVerifier> sigOut;

        internal PgpOnePassSignature(
            BcpgInputStream pIn) : this((OnePassSignaturePacket)pIn.ReadPacket())
        {
        }


        internal PgpOnePassSignature(
            OnePassSignaturePacket sigPack)
        {
            this.sigPack = sigPack;
            this.signatureType = sigPack.SignatureType;
        }

        /**
         * Initialise the signature object for verification.
         *
         * @param verifierBuilderProvider   provider for a content verifier builder for the signature type of interest.
         * @param pubKey  the public key to use for verification
         * @throws PgpException if there's an issue with creating the verifier.
         */
        public void InitVerify(IVerifierFactoryProvider<PgpSignatureTypeIdentifier> verifierFactoryProvider)
        {
            IVerifierFactory<PgpSignatureTypeIdentifier> verifierFactory = verifierFactoryProvider.CreateVerifierFactory(new PgpSignatureTypeIdentifier(sigPack.KeyAlgorithm, sigPack.HashAlgorithm));

            lastb = 0;
            sigOut = verifierFactory.CreateCalculator();
        }

        public void Update(
            byte b)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                if (b == '\r')
                {
                    byteUpdate((byte)'\r');
                    byteUpdate((byte)'\n');
                }
                else if (b == '\n')
                {
                    if (lastb != '\r')
                    {
                        byteUpdate((byte)'\r');
                        byteUpdate((byte)'\n');
                    }
                }
                else
                {
                    byteUpdate(b);
                }

                lastb = b;
            }
            else
            {
                byteUpdate(b);
            }
        }

        public void Update(
            byte[] bytes)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                for (int i = 0; i != bytes.Length; i++)
                {
                    this.Update(bytes[i]);
                }
            }
            else
            {
                blockUpdate(bytes, 0, bytes.Length);
            }
        }

        public void Update(
            byte[] bytes,
            int off,
            int length)
        {
            if (signatureType == PgpSignature.CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    this.Update(bytes[i]);
                }
            }
            else
            {
                blockUpdate(bytes, off, length);
            }
        }

        private void byteUpdate(byte b)
        {
            sigOut.Stream.WriteByte(b);
        }

        private void blockUpdate(byte[] block, int off, int len)
        {
            sigOut.Stream.Write(block, off, len);
        }

        /**
         * Verify the calculated signature against the passed in PgpSignature.
         * 
         * @param pgpSig
         * @return boolean
         * @throws PgpException
         */
        public bool Verify(
            PgpSignature pgpSig)
        {
            try
            {
                byte[] trailer = pgpSig.GetSignatureTrailer();

                sigOut.Stream.Write(trailer, 0, trailer.Length);

                sigOut.Stream.Close();
            }
            catch (IOException e)
            {
                throw new PgpException("unable to add trailer: " + e.Message, e);
            }

            return sigOut.GetResult().IsVerified(pgpSig.GetSignature());
        }

        public long KeyId
        {
            get
            {
                return sigPack.KeyId;
            }
        }

        public int SignatureType
        {
            get
            {
                return sigPack.SignatureType;
            }
        }

        public HashAlgorithmTag HashAlgorithm
        {
            get
            {
                return sigPack.HashAlgorithm;
            }
        }

        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get
            {
                return sigPack.KeyAlgorithm;
            }
        }

        public byte[] GetEncoded()
        {
            MemoryOutputStream bOut = new MemoryOutputStream();

            this.Encode(bOut);

            return bOut.ToArray();
        }

        public void Encode(
            Stream outStream)
        {
            BcpgOutputStream output = BcpgOutputStream.Wrap(outStream);

            output.WritePacket(sigPack);
        }
    }
}