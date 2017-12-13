using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    public enum RecipientType
    {
        KeyTrans,
        Kek,
        KeyAgree,
        Password
    }

    public interface IRecipientID<TRecip> : ISelector<TRecip> where TRecip : RecipientInformation
    {
        /// <summary>
        ///  Return the type code for this recipient ID.
        /// </summary>
        RecipientType Type
        {
            get;
        }

        bool Match(TRecip obj);
    }
}