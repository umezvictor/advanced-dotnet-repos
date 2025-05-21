﻿using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CA.And.DDD.Template.Infrastructure.Persistance.Configuration.Infrastructure
{
    internal class DomainEventConfiguration : IEntityTypeConfiguration<DomainEvent>
    {
        public void Configure(EntityTypeBuilder<DomainEvent> builder)
        {
            builder.HasKey(x => x.DomainEventId);
            builder.Property(x => x.OccuredAt).HasColumnType("timestamp with time zone").HasDefaultValueSql("CURRENT_TIMESTAMP AT TIME ZONE 'UTC'");
            builder.Property(x => x.Type).HasMaxLength(500);
            builder.Property(x => x.AssemblyName).HasMaxLength(500);
            builder.Property(x => x.Payload);
            builder.Property(x => x.ComplatedAt).HasColumnType("timestamp with time zone");
        }
    }
}
