
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /**
     * the KeyTransRecipientInformation class for a recipient who has been sent a secret
     * key encrypted using their public key that needs to be used to
     * extract the message.
     */
    public class KeyTransRecipientInformation : RecipientInformation
    {
        private KeyTransRecipientInfo info;

        internal KeyTransRecipientInformation(
            KeyTransRecipientInfo info,
            AlgorithmIdentifier messageAlgorithm,
            ICmsSecureReadable secureReadable,
            IAuthAttributesProvider additionalData) : base(info.KeyEncryptionAlgorithm, messageAlgorithm, secureReadable, additionalData)

        {

            this.info = info;

            RecipientIdentifier r = info.RecipientIdentifier;
            if (r.IsTagged)
            {
                Asn1OctetString octs = Asn1OctetString.GetInstance(r.ID);

                rid = new KeyTransRecipientID(octs.GetOctets()) as IRecipientID<RecipientInformation>;
            }
            else
            {
                IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.GetInstance(r.ID);

                rid = new KeyTransRecipientID(iAnds.Name, iAnds.SerialNumber.Value) as IRecipientID<RecipientInformation>;
            }
        }

        protected override RecipientOperator GetRecipientOperator(IRecipient recipient)
        {
            return ((IKeyTransRecipient)recipient).GetRecipientOperator(keyEncAlg, messageAlgorithm, info.EncryptedKey.GetOctets());
        }
    }
}
