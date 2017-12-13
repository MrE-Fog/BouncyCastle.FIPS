
using System.Collections.Generic;

namespace Org.BouncyCastle.Utilities
{
    /// <summary>
    /// A generic interface describing a simple store of objects.
    /// </summary>
    /// <typeparam name="TStored">the object type stored.</typeparam>
    public interface IStore<TStored>
    {
        ICollection<TStored> GetMatches(ISelector<TStored> selector);
    }
}
