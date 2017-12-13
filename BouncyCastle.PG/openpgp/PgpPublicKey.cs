using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.OpenPgp;
using Org.BouncyCastle.Bcpg;
using System.Collections.Generic;

namespace Org.BouncyCastle.OpenPgp
{
    /// <remarks>General class to handle a PGP public key object.</remarks>
    public class PgpPublicKey
    {
        private static readonly int[] MasterKeyCertificationTypes = new int[]
        {
            PgpSignature.PositiveCertification,
            PgpSignature.CasualCertification,
            PgpSignature.NoCertification,
            PgpSignature.DefaultCertification
        };

        private long keyId;
        private byte[] fingerprint;
        private int keyStrength;

        internal PublicKeyPacket publicPk;
        internal TrustPacket trustPk;
        internal IList<PgpSignature> keySigs = new List<PgpSignature>();
        internal IList ids = Platform.CreateArrayList();
        internal IList idTrusts = Platform.CreateArrayList();
        internal IList<List<PgpSignature>> idSigs = new List<List<PgpSignature>>();
        internal IList<PgpSignature> subSigs;

        private void Init(IKeyFingerPrintCalculator fingerPrintCalculator)
        {
            IBcpgKey key = publicPk.Key;

            this.fingerprint = fingerPrintCalculator.CalculateFingerprint(publicPk);

            if (publicPk.Version <= 3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey)key;

                this.keyId = rK.Modulus.LongValue;
                this.keyStrength = rK.Modulus.BitLength;
            }
            else
            {
                this.keyId = ((long)(fingerprint[fingerprint.Length - 8] & 0xff) << 56)
                                | ((long)(fingerprint[fingerprint.Length - 7] & 0xff) << 48)
                                | ((long)(fingerprint[fingerprint.Length - 6] & 0xff) << 40)
                                | ((long)(fingerprint[fingerprint.Length - 5] & 0xff) << 32)
                                | ((long)(fingerprint[fingerprint.Length - 4] & 0xff) << 24)
                                | ((long)(fingerprint[fingerprint.Length - 3] & 0xff) << 16)
                                | ((long)(fingerprint[fingerprint.Length - 2] & 0xff) << 8)
                                | ((fingerprint[fingerprint.Length - 1] & 0xff));

                if (key is RsaPublicBcpgKey)
                {
                    this.keyStrength = ((RsaPublicBcpgKey)key).Modulus.BitLength;
                }
                else if (key is DsaPublicBcpgKey)
                {
                    this.keyStrength = ((DsaPublicBcpgKey)key).P.BitLength;
                }
                else if (key is ElGamalPublicBcpgKey)
                {
                    this.keyStrength = ((ElGamalPublicBcpgKey)key).P.BitLength;
                }
                else if (key is ECPublicBcpgKey)
                {
                    this.keyStrength = ECNamedCurveTable.GetByOid(((ECPublicBcpgKey)key).CurveOid).Curve.FieldSize;
                }
            }
        }

        /**
         * Create a PGP public key from a packet descriptor using the passed in fingerPrintCalculator to do calculate
         * the fingerprint and keyID.
         *
         * @param publicKeyPacket  packet describing the public key.
         * @param fingerPrintCalculator calculator providing the digest support ot create the key fingerprint.
         * @throws PGPException  if the packet is faulty, or the required calculations fail.
         */
        public PgpPublicKey(PublicKeyPacket publicPk, IKeyFingerPrintCalculator fingerPrintCalculator)
                : this(publicPk, Platform.CreateArrayList(), new List<List<PgpSignature>>(), fingerPrintCalculator)
        {
        }

        /// <summary>Constructor for a sub-key.</summary>
        internal PgpPublicKey(
            PublicKeyPacket publicPk,
            TrustPacket trustPk,
            IList<PgpSignature> sigs,
            IKeyFingerPrintCalculator fingerPrintCalculator)
        {
            this.publicPk = publicPk;
            this.trustPk = trustPk;
            this.subSigs = sigs;

            Init(fingerPrintCalculator);
        }

        internal PgpPublicKey(
            PgpPublicKey key,
            TrustPacket trust,
            IList<PgpSignature> subSigs)
        {
            this.publicPk = key.publicPk;
            this.trustPk = trust;
            this.subSigs = subSigs;

            this.fingerprint = key.fingerprint;
            this.keyId = key.keyId;
            this.keyStrength = key.keyStrength;
        }

        /// <summary>Copy constructor.</summary>
        /// <param name="pubKey">The public key to copy.</param>
        internal PgpPublicKey(
            PgpPublicKey pubKey)
        {
            this.publicPk = pubKey.publicPk;

            this.keySigs = new List<PgpSignature>(pubKey.keySigs);
            this.ids = Platform.CreateArrayList(pubKey.ids);
            this.idTrusts = Platform.CreateArrayList(pubKey.idTrusts);
            this.idSigs = new List<List<PgpSignature>>(pubKey.idSigs.Count);
            for (int i = 0; i != pubKey.idSigs.Count; i++)
            {
                this.idSigs.Add(new List<PgpSignature>(pubKey.idSigs[i]));
            }

            if (pubKey.subSigs != null)
            {
                this.subSigs = new List<PgpSignature>(pubKey.subSigs.Count);
                for (int i = 0; i != pubKey.subSigs.Count; i++)
                {
                    this.subSigs.Add(pubKey.subSigs[i]);
                }
            }

            this.fingerprint = pubKey.fingerprint;
            this.keyId = pubKey.keyId;
            this.keyStrength = pubKey.keyStrength;
        }

        internal PgpPublicKey(
            PublicKeyPacket publicPk,
            TrustPacket trustPk,
            IList<PgpSignature> keySigs,
            IList ids,
            IList idTrusts,
            IList<List<PgpSignature>> idSigs,
            IKeyFingerPrintCalculator fingerPrintCalculator)
        {
            this.publicPk = publicPk;
            this.trustPk = trustPk;
            this.keySigs = keySigs;
            this.ids = ids;
            this.idTrusts = idTrusts;
            this.idSigs = idSigs;

            Init(fingerPrintCalculator);
        }

        internal PgpPublicKey(
            PublicKeyPacket publicPk,
            IList ids,
            IList<List<PgpSignature>> idSigs,
            IKeyFingerPrintCalculator fingerPrintCalculator)
        {
            this.publicPk = publicPk;
            this.ids = ids;
            this.idSigs = idSigs;
            Init(fingerPrintCalculator);
        }

        /// <summary>The version of this key.</summary>
        public int Version
        {
            get { return publicPk.Version; }
        }

        /// <summary>The creation time of this key.</summary>
        public DateTime CreationTime
        {
            get { return publicPk.GetTime(); }
        }

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        public byte[] GetTrustData()
        {
            if (trustPk == null)
            {
                return null;
            }

            return Arrays.Clone(trustPk.GetLevelAndTrustAmount());
        }

        /// <summary>The number of valid seconds from creation time - zero means no expiry.</summary>
        public long GetValidSeconds()
        {
            if (publicPk.Version <= 3)
            {
                return (long)publicPk.ValidDays * (24 * 60 * 60);
            }

            if (IsMasterKey)
            {
                for (int i = 0; i != MasterKeyCertificationTypes.Length; i++)
                {
                    long seconds = GetExpirationTimeFromSig(true, MasterKeyCertificationTypes[i]);
                    if (seconds >= 0)
                    {
                        return seconds;
                    }
                }
            }
            else
            {
                long seconds = GetExpirationTimeFromSig(false, PgpSignature.SubkeyBinding);
                if (seconds >= 0)
                {
                    return seconds;
                }
            }

            return 0;
        }

        private long GetExpirationTimeFromSig(
            bool selfSigned,
            int signatureType)
        {
            foreach (PgpSignature sig in GetSignaturesOfType(signatureType))
            {
                if (!selfSigned || sig.KeyId == KeyId)
                {
                    PgpSignatureSubpacketVector hashed = sig.GetHashedSubPackets();

                    if (hashed != null)
                    {
                        return hashed.GetKeyExpirationTime();
                    }

                    return 0;
                }
            }

            return -1;
        }

        /// <summary>The keyId associated with the public key.</summary>
        public long KeyId
        {
            get { return keyId; }
        }

        /// <summary>The fingerprint of the key</summary>
        public byte[] GetFingerprint()
        {
            return (byte[])fingerprint.Clone();
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for encryption.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for encryption.
        /// </returns>
        public bool IsEncryptionKey
        {
            get
            {
                switch (publicPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.ECDH:
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

        /// <summary>True, if this is a master key.</summary>
        public bool IsMasterKey
        {
            get { return subSigs == null; }
        }

        /// <summary>The algorithm code associated with the public key.</summary>
        public PublicKeyAlgorithmTag Algorithm
        {
            get { return publicPk.Algorithm; }
        }

        /// <summary>The strength of the key in bits.</summary>
        public int BitStrength
        {
            get { return keyStrength; }
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable<string> GetUserIds()
        {
            IList<string> temp = new List<string>();

            foreach (object o in ids)
            {
                if (o is string)
                {
                    temp.Add((string)o);
                }
            }

            return new EnumerableProxy<string>(temp);
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        public IEnumerable<PgpUserAttributeSubpacketVector> GetUserAttributes()
        {
            IList<PgpUserAttributeSubpacketVector> temp = new List<PgpUserAttributeSubpacketVector>();

            foreach (object o in ids)
            {
                if (o is PgpUserAttributeSubpacketVector)
                {
                    temp.Add((PgpUserAttributeSubpacketVector)o);
                }
            }

            return new EnumerableProxy<PgpUserAttributeSubpacketVector>(temp);
        }

        /// <summary>Allows enumeration of any signatures associated with the passed in id.</summary>
        /// <param name="id">The ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> GetSignaturesForId(
            string id)
        {
            if (id == null)
                throw new ArgumentNullException("id");

            for (int i = 0; i != ids.Count; i++)
            {
                if (id.Equals(ids[i]))
                {
                    return new EnumerableProxy<PgpSignature>(idSigs[i]);
                }
            }

            return null;
        }

        /// <summary>Allows enumeration of signatures associated with the passed in user attributes.</summary>
        /// <param name="userAttributes">The vector of user attributes to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable GetSignaturesForUserAttribute(
            PgpUserAttributeSubpacketVector userAttributes)
        {
            for (int i = 0; i != ids.Count; i++)
            {
                if (userAttributes.Equals(ids[i]))
                {
                    return new EnumerableProxy<PgpSignature>((IList<PgpSignature>)idSigs[i]);
                }
            }

            return null;
        }

        /// <summary>Allows enumeration of signatures of the passed in type that are on this key.</summary>
        /// <param name="signatureType">The type of the signature to be returned.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable GetSignaturesOfType(
            int signatureType)
        {
            IList<PgpSignature> temp = new List<PgpSignature>();

            foreach (PgpSignature sig in GetSignatures())
            {
                if (sig.SignatureType == signatureType)
                {
                    temp.Add(sig);
                }
            }

            return new EnumerableProxy<PgpSignature>(temp);
        }

        /// <summary>Allows enumeration of all signatures/certifications associated with this key.</summary>
        /// <returns>An <c>IEnumerable</c> with all signatures/certifications.</returns>
        public IEnumerable<PgpSignature> GetSignatures()
        {
            IList<PgpSignature> sigs = subSigs;
            if (sigs == null)
            {
                sigs = new List<PgpSignature>(keySigs);

                foreach (ICollection extraSigs in idSigs)
                {
                    foreach (PgpSignature sig in extraSigs)
                    {
                        sigs.Add(sig);
                    }
                }
            }

            return new EnumerableProxy<PgpSignature>(sigs);
        }

        /**
         * Return all signatures/certifications directly associated with this key (ie, not to a user id).
         *
         * @return an iterator (possibly empty) with all signatures/certifications.
         */
        public IEnumerable<PgpSignature> GetKeySignatures()
        {
            IList<PgpSignature> sigs = subSigs;
            if (sigs == null)
            {
                sigs = new List<PgpSignature>(keySigs);
            }
            return new EnumerableProxy<PgpSignature>(sigs);
        }

        public PublicKeyPacket PublicKeyPacket
        {
            get { return publicPk; }
        }

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        public void Encode(
            Stream outStr)
        {
            BcpgOutputStream bcpgOut = BcpgOutputStream.Wrap(outStr);

            bcpgOut.WritePacket(publicPk);
            if (trustPk != null)
            {
                bcpgOut.WritePacket(trustPk);
            }

            if (subSigs == null)    // not a sub-key
            {
                foreach (PgpSignature keySig in keySigs)
                {
                    keySig.Encode(bcpgOut);
                }

                for (int i = 0; i != ids.Count; i++)
                {
                    if (ids[i] is string)
                    {
                        string id = (string)ids[i];

                        bcpgOut.WritePacket(new UserIdPacket(id));
                    }
                    else
                    {
                        PgpUserAttributeSubpacketVector v = (PgpUserAttributeSubpacketVector)ids[i];
                        bcpgOut.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (idTrusts[i] != null)
                    {
                        bcpgOut.WritePacket((ContainedPacket)idTrusts[i]);
                    }

                    foreach (PgpSignature sig in (IList)idSigs[i])
                    {
                        sig.Encode(bcpgOut);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in subSigs)
                {
                    subSig.Encode(bcpgOut);
                }
            }
        }

        /// <summary>Check whether this (sub)key has a revocation signature on it.</summary>
        /// <returns>True, if this (sub)key has been revoked.</returns>
        public bool IsRevoked()
        {
            int ns = 0;
            bool revoked = false;
            if (IsMasterKey)	// Master key
            {
                while (!revoked && (ns < keySigs.Count))
                {
                    if (((PgpSignature)keySigs[ns++]).SignatureType == PgpSignature.KeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            else	// Sub-key
            {
                while (!revoked && (ns < subSigs.Count))
                {
                    if (((PgpSignature)subSigs[ns++]).SignatureType == PgpSignature.SubkeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            return revoked;
        }

        /// <summary>Add a certification for an id to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="id">The ID the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            string id,
            PgpSignature certification)
        {
            return AddCert(key, id, certification);
        }

        /// <summary>Add a certification for the given UserAttributeSubpackets to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="userAttributes">The attributes the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            PgpUserAttributeSubpacketVector userAttributes,
            PgpSignature certification)
        {
            return AddCert(key, userAttributes, certification);
        }

        private static PgpPublicKey AddCert(
            PgpPublicKey key,
            object id,
            PgpSignature certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            List<PgpSignature> sigList = null;

            for (int i = 0; i != returnKey.ids.Count; i++)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    sigList = returnKey.idSigs[i];
                }
            }

            if (sigList != null)
            {
                sigList.Add(certification);
            }
            else
            {
                sigList = new List<PgpSignature>();
                sigList.Add(certification);
                returnKey.ids.Add(id);
                returnKey.idTrusts.Add(null);
                returnKey.idSigs.Add(sigList);
            }

            return returnKey;
        }

        /// <summary>
        /// Remove any certifications associated with a user attribute subpacket on a key.
        /// </summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The attributes to be removed.</param>
        /// <returns>
        /// The re-certified key, or null if the user attribute subpacket was not found on the key.
        /// </returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            PgpUserAttributeSubpacketVector userAttributes)
        {
            return RemoveCert(key, userAttributes);
        }

        /// <summary>Remove any certifications associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that is to be removed.</param>
        /// <returns>The re-certified key, or null if the ID was not found on the key.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            string id)
        {
            return RemoveCert(key, id);
        }

        private static PgpPublicKey RemoveCert(
            PgpPublicKey key,
            object id)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            bool found = false;

            for (int i = 0; i < returnKey.ids.Count; i++)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    found = true;
                    returnKey.ids.RemoveAt(i);
                    returnKey.idTrusts.RemoveAt(i);
                    returnKey.idSigs.RemoveAt(i);
                }
            }

            return found ? returnKey : null;
        }

        /// <summary>Remove a certification associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that the certfication is to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            string id,
            PgpSignature certification)
        {
            return RemoveCert(key, id, certification);
        }

        /// <summary>Remove a certification associated with a given user attributes on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The user attributes that the certfication is to be removed from.</param>
        /// <param name="certification">The certification to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            PgpUserAttributeSubpacketVector userAttributes,
            PgpSignature certification)
        {
            return RemoveCert(key, userAttributes, certification);
        }

        private static PgpPublicKey RemoveCert(
            PgpPublicKey key,
            object id,
            PgpSignature certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            bool found = false;

            for (int i = 0; i < returnKey.ids.Count; i++)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    IList certs = (IList)returnKey.idSigs[i];
                    found = certs.Contains(certification);

                    if (found)
                    {
                        certs.Remove(certification);
                    }
                }
            }

            return found ? returnKey : null;
        }

        /// <summary>Add a revocation or some other key certification to a key.</summary>
        /// <param name="key">The key the revocation is to be added to.</param>
        /// <param name="certification">The key signature to be added.</param>
        /// <returns>The new changed public key object.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            PgpSignature certification)
        {
            if (key.IsMasterKey)
            {
                if (certification.SignatureType == PgpSignature.SubkeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for master key revocation.");
                }
            }
            else
            {
                if (certification.SignatureType == PgpSignature.KeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for sub-key revocation.");
                }
            }

            PgpPublicKey returnKey = new PgpPublicKey(key);

            if (returnKey.subSigs != null)
            {
                returnKey.subSigs.Add(certification);
            }
            else
            {
                returnKey.keySigs.Add(certification);
            }

            return returnKey;
        }

        /// <summary>Remove a certification from the key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The modified key, null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            PgpSignature certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            IList<PgpSignature> sigs = returnKey.subSigs != null
                ? returnKey.subSigs
                : returnKey.keySigs;

            //			bool found = sigs.Remove(certification);
            int pos = sigs.IndexOf(certification);
            bool found = pos >= 0;

            if (found)
            {
                sigs.RemoveAt(pos);
            }
            else
            {
                foreach (String id in key.GetUserIds())
                {
                    foreach (object sig in key.GetSignaturesForId(id))
                    {
                        // TODO Is this the right type of equality test?
                        if (certification == sig)
                        {
                            found = true;
                            returnKey = PgpPublicKey.RemoveCertification(returnKey, id, certification);
                        }
                    }
                }

                if (!found)
                {
                    foreach (PgpUserAttributeSubpacketVector id in key.GetUserAttributes())
                    {
                        foreach (object sig in key.GetSignaturesForUserAttribute(id))
                        {
                            // TODO Is this the right type of equality test?
                            if (certification == sig)
                            {
                                found = true;
                                returnKey = PgpPublicKey.RemoveCertification(returnKey, id, certification);
                            }
                        }
                    }
                }
            }

            return returnKey;
        }
    }
}
