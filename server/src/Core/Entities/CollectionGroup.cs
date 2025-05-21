﻿namespace Bit.Core.Entities;

#nullable enable

public class CollectionGroup
{
    public Guid CollectionId { get; set; }
    public Guid GroupId { get; set; }
    public bool ReadOnly { get; set; }
    public bool HidePasswords { get; set; }
    public bool Manage { get; set; }
}
